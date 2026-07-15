package admin

import (
	"embed"
	"html/template"
	"io"
)

//go:embed page.html.tmpl
var files embed.FS

// tmpl is parsed once at init; a malformed template panics here (and is
// caught by any test that imports this package), never at request time.
var tmpl = template.Must(template.New("page.html.tmpl").Funcs(funcs).ParseFS(files, "page.html.tmpl"))

var funcs = template.FuncMap{
	// healthClass maps a health verdict to its badge CSS class.
	"healthClass": func(state string) string {
		switch state {
		case healthHealthy:
			return "ok"
		case healthDegraded:
			return "err"
		default: // healthStarting and any unknown state
			return "pending"
		}
	},
}

// render writes the HTML status page for s to w.
func render(w io.Writer, s Status) error {
	return tmpl.Execute(w, s)
}
