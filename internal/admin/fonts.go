package admin

import (
	"bytes"
	"embed"
	"net/http"
	"strings"
	"time"
)

// consoleFontPrefix is the public URL prefix of the self-hosted console fonts.
const consoleFontPrefix = "/_static/fonts/"

// fontFiles is the self-hosted console font bundle (m7kni design system v2).
// The page never fetches a font from another origin: the three files below are
// the only font bytes it references. Font accepts fixed filenames only, so a
// request path can never select another embedded file.
//
//go:embed fonts/*.woff2
var fontFiles embed.FS

// Font returns one self-hosted console font by its public filename.
func Font(name string) ([]byte, bool) {
	switch name {
	case "hanken-grotesk-latin.woff2", "hanken-grotesk-latin-ext.woff2", "JetBrainsMono-Variable.woff2":
		data, err := fontFiles.ReadFile("fonts/" + name)
		return data, err == nil
	default:
		return nil, false
	}
}

// handleFont serves one embedded font. Font bytes carry no tenant data, and the
// admin server has no other static assets.
func (s *Server) handleFont(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, consoleFontPrefix)
	font, ok := Font(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(font))
}
