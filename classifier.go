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
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js", ".mjs":
		return "text/javascript; charset=utf-8"
	case ".htm", ".html":
		return "text/html; charset=utf-8"
	case ".json":
		return "application/json; charset=utf-8"
	case ".xml":
		return "application/xml; charset=utf-8"
	case ".svg":
		return "image/svg+xml; charset=utf-8"
	case ".gif":
		return "image/gif"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".pdf":
		return "application/pdf"
	case ".wasm":
		return "appliction/wasm"
	case ".webp":
		return "image/webp"
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
