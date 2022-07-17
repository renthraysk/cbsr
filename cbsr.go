package cbsr

import (
	"bufio"
	"compress/gzip"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/google/brotli/go/cbrotli"
	"github.com/renthraysk/encoding"
)

func writerTo(b []byte) func(w io.Writer) (int64, error) {
	return func(w io.Writer) (int64, error) {
		n, err := w.Write(b)
		return int64(n), err
	}
}

// fsFile provides a writeTo implementation on a file residing in an fs.FS
type fsFile struct {
	fsys fs.FS
	name string
}

func (z *fsFile) writeTo(w io.Writer) (int64, error) {
	f, err := z.fsys.Open(z.name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(w, f)
}

// resource represents as http resource.
type resource struct {
	contentType     string
	contentLength   int64
	writerTo        func(w io.Writer) (int64, error)
	contentEncoding encoding.Encoding
}

// set sets the following http headers in dst
// - Content-Type
// - Content-Length
// - Content-Encoding if the body is encoded
// - Cache-Control if not set, it's set to immutable.
func (s *resource) set(dst http.Header) {
	v := [...]string{
		s.contentType,
		strconv.FormatInt(s.contentLength, 10),
		s.contentEncoding.String(),
		"public, max-age=31536000, immutable",
	}
	dst["Content-Type"] = v[:1:1]
	dst["Content-Length"] = v[1:2:2]
	if s.contentEncoding != encoding.Identity {
		dst["Content-Encoding"] = v[2:3:3]
	}
	// Probably not a good idea to discard an existing
	// Cache-Control header for an immutable one
	if _, ok := dst["Cache-Control"]; !ok {
		dst["Cache-Control"] = v[3:4:4]
	}
}

func (s *resource) writeResponse(w http.ResponseWriter, body bool) error {
	s.set(w.Header())
	if body {
		_, err := s.writerTo(w)
		return err
	}
	return nil
}

// ServeHTTP http.Handler implementation
func (s *resource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status := http.StatusMethodNotAllowed
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		acceptEncoding := encoding.Parse(r.Header.Get("Accept-Encoding"))
		if acceptEncoding.Contains(s.contentEncoding) {
			s.writeResponse(w, r.Method != http.MethodHead)
			return
		}
		status = http.StatusNotAcceptable
	}
	http.Error(w, http.StatusText(status), status)
}

type resources []*resource

type contentLengthSorter resources

func (s contentLengthSorter) Len() int { return len(s) }
func (s contentLengthSorter) Less(i, j int) bool {
	if s[i].contentLength < s[j].contentLength {
		return true
	}
	// if lengths are equal, then compare encodings
	// this prioritizes identity encoding, followed by gzip, and then br
	return s[i].contentLength == s[j].contentLength &&
		s[i].contentEncoding < s[j].contentEncoding
}

func (s contentLengthSorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// ServeHTTP http.Handler implementation
func (rs resources) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	status := http.StatusMethodNotAllowed
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		acceptEncoding := encoding.Parse(r.Header.Get("Accept-Encoding"))
		for _, s := range rs {
			if acceptEncoding.Contains(s.contentEncoding) {

				vary := []string{"Accept-Encoding"}
				if v, ok := w.Header()["Vary"]; ok {
					vary = ensureValue(v, "Accept-Encoding")
				}
				w.Header()["Vary"] = vary

				s.writeResponse(w, r.Method != http.MethodHead)
				return
			}
		}
		status = http.StatusNotAcceptable
	}
	http.Error(w, http.StatusText(status), status)
}

func index(fsys fs.FS, c Classifier) (map[string]resources, error) {

	type fsResource struct {
		resource
		fsFile
	}

	n := 16
	m := make(map[string]resources, n)
	rs := make([]fsResource, n)

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if n <= 0 {
			n = 8
			rs = make([]fsResource, n)
		}
		n--

		r := &rs[n]
		r.fsys, r.name = fsys, path
		r.writerTo = r.fsFile.writeTo

		var ok bool

		ext := filepath.Ext(path)
		r.contentEncoding, ok = c.ContentEncodingFromExt(ext)
		if ok {
			path = strings.TrimSuffix(path, ext)
			ext = filepath.Ext(path)
		}
		r.contentType = c.ContentTypeFromExt(ext)
		r.contentLength = info.Size()
		m[path] = append(m[path], &r.resource)
		return nil
	})
	return m, err
}

type responseWriter struct {
	header      http.Header
	w           io.Writer
	status      int
	wroteHeader bool
}

func (rw *responseWriter) Header() http.Header {
	return rw.header
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.header.Write(rw.w)
	io.WriteString(rw.w, "\r\n")
	rw.wroteHeader = true
}

func (rw *responseWriter) Write(p []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.w.Write(p)
}

func (rw *responseWriter) reset(w io.Writer) {
	rw.header = make(http.Header, 5)
	rw.w = w
	rw.wroteHeader = false
}

// RegisterFS traverses the fs.FS and registers a cache busting pattern for each group of files.
// It returns a map keyed by the file name from the fs.FS and the path to which the mux will
// handle.
// Intended to be passed to templates so ```{{index .SubResources "/static/js/default.js"}}``` will
// be replaced with the cache busting path.
func RegisterFS(mux *http.ServeMux, fsys fs.FS, prefix string) (map[string]string, error) {

	classifier := defaultClassifier{}

	index, err := index(fsys, classifier)
	if err != nil {
		return nil, err
	}
	srIndex := make(map[string]string, len(index))

	root := sha512.New()
	leaf := sha512.New()
	bufw := bufio.NewWriterSize(leaf, 32*sha512.BlockSize)
	rw := &responseWriter{}

	for keyPath, rs := range index {
		if len(rs) == 0 {
			continue
		}
		// Ensure an identity option exists
		rs = rs.appendIdentity(10 << 20)

		if len(rs) > 1 {
			// Sort by ascending content-length
			sort.Sort(contentLengthSorter(rs))
		}

		root.Reset()
		for _, r := range rs {
			leaf.Reset()
			bufw.Reset(leaf)
			rw.reset(bufw)

			if err := r.writeResponse(rw, true); err != nil {
				return nil, fmt.Errorf("failed to hash %q: %v", keyPath, err)
			}
			bufw.Flush()
			root.Write(leaf.Sum(bufw.AvailableBuffer()))
		}
		x := root.Sum(bufw.AvailableBuffer())
		ver := base64.URLEncoding.EncodeToString(x[:15]) // 15? 120 bits?

		relPath := strings.TrimPrefix(keyPath, prefix)
		ext := filepath.Ext(relPath)
		vPath := strings.TrimSuffix(relPath, ext) + "-" + ver + ext

		if vPath[0] != '/' {
			vPath = "/" + vPath
		}

		srIndex[keyPath] = vPath

		switch len(rs) {
		case 0:
		case 1:
			mux.Handle(vPath, rs[0])
		default:
			mux.Handle(vPath, rs)
		}
	}
	return srIndex, nil
}

type bodyWriter struct {
	io.Writer
	header http.Header
}

func (bw *bodyWriter) WriteHeader(code int) {}
func (bw *bodyWriter) Header() http.Header  { return bw.header }

func (rs resources) appendIdentity(limit int64) resources {
	if len(rs) == 0 {
		return rs
	}
	// Check if already have identity encoding
	for _, r := range rs {
		if r.contentEncoding == encoding.Identity {
			return rs
		}
	}
	for _, r := range rs {
		id, err := decode(r, limit)
		if err == nil && id != r {
			return append(rs, id)
		}
	}
	return rs
}

func decode(rs *resource, limit int64) (*resource, error) {
	switch rs.contentEncoding {
	case encoding.Identity:
		return rs, nil
	case encoding.Brotli, encoding.Gzip:

		r, w := io.Pipe()
		go func() {
			bw := &bodyWriter{w, make(http.Header, 0)}
			err := rs.writeResponse(bw, true)
			w.CloseWithError(err)
		}()

		var d io.ReadCloser
		switch rs.contentEncoding {
		case encoding.Gzip:
			var err error
			d, err = gzip.NewReader(r)
			if err != nil {
				return nil, err
			}
		case encoding.Brotli:
			d = cbrotli.NewReader(r)
		}
		defer d.Close()

		size := rs.contentLength

		if size < 10<<20 {
			size *= 3 // Assume 66% compression rate for intial buffer sizing
		}
		if size > limit {
			size = limit
		}

		body, err := readAll(d, size, limit)
		if err != nil {
			return nil, fmt.Errorf("failed to readAll: %w", err)
		}
		return &resource{
			contentType:     rs.contentType,
			contentLength:   int64(len(body)),
			contentEncoding: encoding.Identity,
			writerTo:        writerTo(body),
		}, nil
	}
	return nil, errors.New("unable to decode")
}

func readAll(r io.Reader, size, limit int64) ([]byte, error) {
	p := make([]byte, size)
	n, err := r.Read(p)
	i := int64(n)
	for ; err == nil; i += int64(n) {
		if i >= int64(len(p)) {
			if int64(len(p)) >= limit {
				return nil, errors.New("size limit exceeded")
			}
			p = append(p, 0)
			p = p[:cap(p)]
		}
		n, err = r.Read(p[i:])
	}
	if err == io.EOF {
		return p[:i], nil
	}
	return nil, err
}

func errError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case err == nil:
		return
	case errors.Is(err, fs.ErrNotExist):
		status = http.StatusNotFound
	case errors.Is(err, fs.ErrPermission):
		status = http.StatusForbidden
	}
	http.Error(w, http.StatusText(status), status)
}

// ensureValue ensures value will be present in returned slice of values.
func ensureValue[T comparable](values []T, value T) []T {
	for _, v := range values {
		if v == value {
			return values
		}
	}
	return append(values, value)
}
