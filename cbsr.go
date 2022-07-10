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

type slice []byte

func (s slice) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(s)
	return int64(n), err
}

type fsFile struct {
	fsys fs.FS
	name string
}

func (z *fsFile) WriteTo(w io.Writer) (int64, error) {
	f, err := z.fsys.Open(z.name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return io.Copy(w, f)
}

type resource struct {
	contentType     string
	contentLength   int64
	contentEncoding encoding.Encoding
	vary            bool
	writerTo        io.WriterTo
}

func (s *resource) set(dst http.Header) {
	v := [...]string{
		s.contentType,
		strconv.FormatInt(s.contentLength, 10),
		s.contentEncoding.String(),
		"Accept-Encoding",
		"max-age=31536000, immutable",
	}
	dst["Content-Type"] = v[:1:1]
	dst["Content-Length"] = v[1:2:2]
	if s.contentEncoding != encoding.Identity {
		dst["Content-Encoding"] = v[2:3:3]
	}
	if s.vary {
		vary := v[3:4:4]
		if v, ok := dst["Vary"]; ok {
			vary = ensureValue(v, "Accept-Encoding")
		}
		dst["Vary"] = vary
	}
	// Probably not a good idea to discard an existing
	// Cache-Control header for an immutable one
	if _, ok := dst["Cache-Control"]; !ok {
		dst["Cache-Control"] = v[4:5:5]
	}
}

func (s *resource) writeResponse(w http.ResponseWriter, body bool) error {
	s.set(w.Header())
	if body {
		_, err := s.writerTo.WriteTo(w)
		return err
	}
	return nil
}

func (s *resource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		s.writeResponse(w, r.Method != http.MethodHead)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
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

func (rs resources) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		acceptEncoding := encoding.Parse(r.Header.Get("Accept-Encoding"))
		for _, s := range rs {
			if acceptEncoding.Contains(s.contentEncoding) {
				s.writeResponse(w, r.Method != http.MethodHead)
				return
			}
		}
		http.Error(w, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func index(fsys fs.FS, c Classifier) (map[string]resources, error) {

	type s struct {
		resource
		fsFile
	}

	m := make(map[string]resources)
	n := 16
	rs := make([]s, n)

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
			rs = make([]s, n)
		}
		n--

		r := &rs[n]
		r.fsys, r.name = fsys, path
		r.writerTo = &r.fsFile

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

func RegisterFS(mux *http.ServeMux, fsys fs.FS, prefix string) (map[string]string, error) {

	classifier := defaultClassifier{}

	index, err := index(fsys, classifier)
	if err != nil {
		return nil, err
	}
	srIndex := make(map[string]string, len(index))

	root := sha512.New384()
	leaf := sha512.New384()
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
			for _, r := range rs {
				r.vary = true
			}
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

	for _, sr := range rs {
		switch sr.contentEncoding {
		case encoding.Brotli, encoding.Gzip:

			r, w := io.Pipe()
			go func() {
				bw := &bodyWriter{w, make(http.Header, 0)}
				err := sr.writeResponse(bw, true)
				w.CloseWithError(err)
			}()

			var d io.ReadCloser
			switch sr.contentEncoding {
			case encoding.Gzip:
				var err error
				d, err = gzip.NewReader(r)
				if err != nil {
					return rs
				}
			case encoding.Brotli:
				d = cbrotli.NewReader(r)
			}
			defer d.Close()

			size := sr.contentLength
			if size > limit {
				return rs
			}
			if size < 1<<30 {
				size *= 3 // Assume 66% compression rate for intial buffer sizing
			}

			body, err := readAll(d, make([]byte, size), limit)
			if err != nil {
				return rs
			}
			return append(rs, &resource{
				contentType:     sr.contentType,
				contentLength:   int64(len(body)),
				contentEncoding: encoding.Identity,
				writerTo:        slice(body),
			})
		}
	}
	return nil
}

func readAll(r io.Reader, p []byte, limit int64) ([]byte, error) {
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

func ErrError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, fs.ErrNotExist):
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	case errors.Is(err, fs.ErrPermission):
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
