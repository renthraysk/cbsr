package cbsr

import "github.com/renthraysk/encoding"

type Classifier interface {
	ContentTypeFromExt(ext string) string
	ContentEncodingFromExt(ext string) (encoding.Encoding, bool)
}

type defaultClassifier struct{}

func (defaultClassifier) ContentTypeFromExt(ext string) string {
	switch ext {
	case ".avif":
		return "image/avif"
	case ".css":
		return "text/css; charset=utf-8"
	case ".gif":
		return "image/gif"
	case ".htm", ".html":
		return "text/html; charset=utf-8"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".svg":
		return "image/svg+xml; charset=utf-8"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".wasm":
		return "appliction/wasm"
	case ".webp":
		return "image/webp"
	case ".xml":
		return "application/xml; charset=utf-8"
	}
	return ""
}

func (defaultClassifier) ContentEncodingFromExt(ext string) (encoding.Encoding, bool) {
	switch ext {
	case ".br":
		return encoding.Brotli, true
	case ".gz":
		return encoding.Gzip, true
	}
	return encoding.Identity, false
}
