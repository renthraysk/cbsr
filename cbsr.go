package cbsr

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha512"
	"embed"
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

type headers struct {
	contentType     string
	contentLength   int64
	contentEncoding encoding.Encoding
	vary            bool
}

func (h *headers) ContentType() string                { return h.contentType }
func (h *headers) ContentEncoding() encoding.Encoding { return h.contentEncoding }
func (h *headers) ContentLength() int64               { return h.contentLength }
func (h *headers) SetVary()                           { h.vary = true }

func (h *headers) set(dst http.Header) http.Header {
	s := [...]string{
		h.contentType,
		strconv.FormatInt(h.contentLength, 10),
		h.contentEncoding.String(),
		"Accept-Encoding",
		"max-age=31536000, immutable",
	}
	dst["Content-Type"] = s[:1:1]
	dst["Content-Length"] = s[1:2:2]
	if h.contentEncoding != encoding.Identity {
		dst["Content-Encoding"] = s[2:3:3]
	}
	if h.vary {
		vary := s[3:4:4]
		if v, ok := dst["Vary"]; ok {
			vary = ensureValue(v, "Accept-Encoding")
		}
		dst["Vary"] = vary
	}
	if _, ok := dst["Cache-Control"]; !ok {
		dst["Cache-Control"] = s[4:5:5]
	}
	return dst
}

type resource interface {
	ContentType() string
	ContentEncoding() encoding.Encoding
	ContentLength() int64
	SetVary()
	set(http.Header) http.Header

	http.Handler

	io.WriterTo
	Open() (io.ReadCloser, error)
}

type fsResource struct {
	headers
	fsys fs.FS
	name string
}

func (s *fsResource) Open() (io.ReadCloser, error) {
	return s.fsys.Open(s.name)
}

func (s *fsResource) WriteTo(w io.Writer) (int64, error) {
	f, err := s.Open()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n, err := io.Copy(w, f)
	return int64(n), err
}

func (s *fsResource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		s.set(w.Header())
		if r.Method == http.MethodHead {
			return
		}
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	s.WriteTo(w)
}

type memResource struct {
	headers
	body []byte
}

func (s *memResource) Open() (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(s.body)), nil
}

func (s *memResource) WriteTo(w io.Writer) (int64, error) {
	n, err := w.Write(s.body)
	return int64(n), err
}

func (s *memResource) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		s.set(w.Header())
		if r.Method == http.MethodHead {
			return
		}
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	s.WriteTo(w)
}

type resources []resource

type contentLengthSorter resources

func (s contentLengthSorter) Len() int { return len(s) }
func (s contentLengthSorter) Less(i, j int) bool {
	if s[i].ContentLength() < s[j].ContentLength() {
		return true
	}
	// if lengths are equal, then compare encodings
	// this prioritizes identity encoding, followed by gzip, and then br
	return s[i].ContentLength() == s[j].ContentLength() &&
		s[i].ContentEncoding() < s[j].ContentEncoding()
}

func (s contentLengthSorter) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (rs resources) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodHead, http.MethodGet:
		acceptEncoding := encoding.Parse(r.Header.Get("Accept-Encoding"))
		for _, s := range rs {
			if acceptEncoding.Contains(s.ContentEncoding()) {
				s.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, http.StatusText(http.StatusNotAcceptable), http.StatusNotAcceptable)
	default:
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func index(fsys fs.FS, c Classifier) (map[string]resources, error) {
	m := make(map[string]resources)
	n := 16
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
		var ok bool

		r.fsys = fsys
		r.name = path
		ext := filepath.Ext(path)
		r.contentEncoding, ok = c.ContentEncodingFromExt(ext)
		if ok {
			path = strings.TrimSuffix(path, ext)
			ext = filepath.Ext(path)
		}
		r.contentType = c.ContentTypeFromExt(ext)
		r.contentLength = info.Size()
		m[path] = append(m[path], r)
		return nil
	})
	return m, err
}

func RegisterFS(mux *http.ServeMux, efs embed.FS, prefix string) (map[string]string, error) {

	classifier := defaultClassifier{}

	index, err := index(efs, classifier)
	if err != nil {
		return nil, err
	}
	srIndex := make(map[string]string, len(index))

	root := sha512.New384()
	leaf := sha512.New384()
	bufw := bufio.NewWriterSize(leaf, 32*sha512.BlockSize)
	for keyPath, rs := range index {
		if len(rs) == 0 {
			continue
		}
		// Ensure an identity option exists
		rs = rs.appendIdentity(10 << 20) // limit to under 10Mb

		if len(rs) > 1 {
			// Sort by ascending content-length
			sort.Sort(contentLengthSorter(rs))
			for _, r := range rs {
				r.SetVary()
			}
		}

		root.Reset()
		for _, r := range rs {
			leaf.Reset()
			bufw.Reset(leaf)
			h := r.set(make(http.Header, 5))
			h.Write(bufw)
			bufw.WriteString("\r\n")
			if _, err := r.WriteTo(bufw); err != nil {
				return nil, fmt.Errorf("failed to hash %q: %w", keyPath, err)
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

func (rs resources) appendIdentity(limit int64) resources {
	if len(rs) == 0 {
		return rs
	}
	// Check if already have identity encoding
	for _, r := range rs {
		if r.ContentEncoding() == encoding.Identity {
			return rs
		}
	}

	body, err := rs.decode(limit)
	if err != nil {
		return rs
	}
	return append(rs, &memResource{
		headers: headers{
			contentType:     rs[0].ContentType(),
			contentLength:   int64(len(body)),
			contentEncoding: encoding.Identity,
		},
		body: body,
	})
}

func (rs resources) decode(limit int64) ([]byte, error) {
	for _, r := range rs {
		if b, err := decodeAll(r, limit); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("unable to decode")
}

func decodeAll(r resource, limit int64) ([]byte, error) {
	f, err := r.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var d io.ReadCloser
	switch r.ContentEncoding() {
	case encoding.Gzip:
		d, err = gzip.NewReader(f)
		if err != nil {
			return nil, err
		}
	case encoding.Brotli:
		d = cbrotli.NewReader(f)
	default:
		return nil, fmt.Errorf("unable to decode %s", r.ContentEncoding().String())
	}
	defer d.Close()

	size := r.ContentLength()
	if size > limit {
		return nil, errors.New("compressed size already exceeds limit")
	}
	if size < 10<<20 {
		size *= 3 // Assume 66% compression rate for intial buffer sizing
	}
	return readAll(d, size, limit)
}

func readAll(r io.Reader, size, limit int64) ([]byte, error) {
	b := make([]byte, size)
	n, err := r.Read(b)
	i := int64(n)
	for ; err == nil; i += int64(n) {
		if i >= int64(len(b)) {
			if int64(len(b)) >= limit {
				return nil, errors.New("size limit exceeded")
			}
			b = append(b, 0)
			b = b[:cap(b)]
		}
		n, err = r.Read(b[i:])
	}
	if err == io.EOF {
		return b[:i], nil
	}
	return nil, err
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
