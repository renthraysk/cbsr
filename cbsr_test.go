package cbsr

import (
	"embed"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

//go:embed testdata
var testdata embed.FS

type test struct {
	Path   string
	Method string
	AE     string

	Status int
	CE     string
	Vary   string
}

const AE = "Accept-Encoding"

var methods = []string{"GET", "HEAD"}
var paths = []string{"testdata/static/js/2.js", "testdata/static/js/3.js"}

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
		mux.ServeHTTP(r, newRequest(t, method, srIndex[paths[0]], "*"))
		assertStatus(t, http.StatusMethodNotAllowed, r.Code)
	}
}

func TestNotAcceptable(t *testing.T) {
	mux, srIndex := getMux(t)
	for _, acceptEncoding := range []string{"*;q=0", "identity;q=0"} {
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, newRequest(t, "HEAD", srIndex[paths[0]], acceptEncoding))
		assertStatus(t, http.StatusNotAcceptable, r.Code)
	}
}

func TestOK(t *testing.T) {
	mux, srIndex := getMux(t)
	for _, method := range methods {
		for _, path := range paths {
			for acceptEncoding, contentEncoding := range encodings {
				t.Run(fmt.Sprintf("%s %s %s", method, path, acceptEncoding), func(t *testing.T) {
					r := httptest.NewRecorder()
					mux.ServeHTTP(r, newRequest(t, method, srIndex[path], acceptEncoding))
					assertStatus(t, http.StatusOK, r.Code)
					if r.Code == http.StatusOK {
						assert(t, "Content-Encoding", contentEncoding, r.Header().Get("Content-Encoding"))
						assert(t, "Vary", "Accept-Encoding", r.Header().Get("Vary"))
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

func assert[T comparable](t *testing.T, name string, expected, got T) {
	t.Helper()
	if expected != got {
		t.Fatalf("%s expected %v, got %v", name, expected, got)
	}
}
