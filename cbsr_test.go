package cbsr

import (
	"embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

//go:embed testdata
var testdata embed.FS

var methods = []string{"GET", "HEAD"}
var paths = map[string]string{
	"testdata/static/js/2.js": "text/javascript; charset=UTF-8",
	"testdata/static/js/3.js": "text/javascript; charset=UTF-8",
}

// Accept-Encoding => Content-Encoding
var encodings = map[string]string{
	"*":           "br",
	"gzip":        "gzip",
	"identity":    "",
	"br;q=0,gzip": "gzip",
}

func newRequest(t *testing.T, method, path, acceptEncoding string) *http.Request {
	r, err := http.NewRequest(method, path, nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	r.Header.Set("Accept-Encoding", acceptEncoding)
	return r
}

func getMux(t *testing.T) (*http.ServeMux, map[string]string) {
	mux := http.NewServeMux()

	srIndex, err := RegisterFS(mux, testdata, "testdata/static")
	if err != nil {
		t.Fatalf("failed to index fs: %v", err)
	}
	return mux, srIndex
}

func TestMethodNotAllowed(t *testing.T) {
	mux, srIndex := getMux(t)
	for _, method := range []string{"POST", "PUT", "DELETE", "CONNECT", "OPTIONS"} {
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, newRequest(t, method, srIndex["testdata/static/js/2.js"], "*"))
		assertStatus(t, http.StatusMethodNotAllowed, r.Code)
	}
}

func TestNotAcceptable(t *testing.T) {
	mux, srIndex := getMux(t)
	for _, acceptEncoding := range []string{"*;q=0", "identity;q=0"} {
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, newRequest(t, "HEAD", srIndex["testdata/static/js/2.js"], acceptEncoding))
		assertStatus(t, http.StatusNotAcceptable, r.Code)
	}
}

func TestOK(t *testing.T) {
	mux, srIndex := getMux(t)
	for _, method := range methods {
		for path, contentType := range paths {
			for acceptEncoding, contentEncoding := range encodings {
				t.Run(fmt.Sprintf("%s %s %s", method, path, acceptEncoding), func(t *testing.T) {
					r := httptest.NewRecorder()

					mux.ServeHTTP(r, newRequest(t, method, srIndex[path], acceptEncoding))

					assertStatus(t, http.StatusOK, r.Code)
					if r.Code == http.StatusOK {
						assertEqualFold(t, "Content-Type", contentType, r.Header().Get("Content-Type"))
						assertEqualFold(t, "Content-Encoding", contentEncoding, r.Header().Get("Content-Encoding"))
						assertEqualFold(t, "Vary", "Accept-Encoding", r.Header().Get("Vary"))
						switch method {
						case http.MethodGet:
							contentLength, err := strconv.Atoi(r.Header().Get("Content-Length"))
							if err != nil {
								t.Errorf("failed to parse Content-Length: %v", err)
							}
							assert(t, "body length", r.Body.Len(), contentLength)
						case http.MethodHead:
							assert(t, "body length", r.Body.Len(), 0)
						}
					}
				})
			}
		}
	}
}

func assertStatus(t *testing.T, expected, got int) {
	t.Helper()
	if expected != got {
		t.Fatalf("Status expected %v %q, got %v %q", expected, http.StatusText(expected), got, http.StatusText(got))
	}
}

func assertEqualFold(t *testing.T, name, expected, got string) {
	t.Helper()
	if !strings.EqualFold(expected, got) {
		t.Fatalf("%s expected %v, got %v", name, expected, got)
	}
}

func assert[T comparable](t *testing.T, name string, expected, got T) {
	t.Helper()
	if expected != got {
		t.Fatalf("%s expected %v, got %v", name, expected, got)
	}
}
