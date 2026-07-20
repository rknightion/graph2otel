package admin

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"strings"
)

//go:embed page.html.tmpl
var files embed.FS

// tmpl is parsed once at init; a malformed template panics here (and is
// caught by any test that imports this package), never at request time.
var tmpl = template.Must(template.New("page.html.tmpl").Funcs(funcs).ParseFS(files, "page.html.tmpl"))

// sparkMaxPoints caps how many recent-run samples the duration sparkline and
// outcome strip render, keeping the inline SVG/DOM small for a long-lived
// process (the StatusTracker retains up to historyLen=60 samples).
const sparkMaxPoints = 40

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
	// skipBadgeClass maps a skip category to its badge CSS class, so a
	// license/permission gap reads differently from a deliberate opt-out.
	"skipBadgeClass": func(category string) string {
		switch category {
		case skipCatLicense:
			return "warn"
		case skipCatExperimental:
			return "info"
		default: // skipCatDisabled and any unknown/"" category
			return "muted"
		}
	},
	// sparkline renders a recent-duration trend as an inline SVG polyline.
	// Returns "" for fewer than two points (nothing meaningful to draw).
	"sparkline": sparkline,
	// outcomeStrip renders recent run outcomes as a row of ok/fail ticks.
	"outcomeStrip": outcomeStrip,
}

// tail returns the last n elements of s (all of s when it is shorter).
func tail[T any](s []T, n int) []T {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

// sparkline builds an inline SVG polyline (viewBox 0..100 x 0..24) from the
// most recent durations. A flat line is drawn when every sample is equal.
func sparkline(series []int64) template.HTML {
	pts := tail(series, sparkMaxPoints)
	if len(pts) < 2 {
		return ""
	}
	minV, maxV := pts[0], pts[0]
	for _, v := range pts {
		if v < minV {
			minV = v
		}
		if v > maxV {
			maxV = v
		}
	}
	span := float64(maxV - minV)
	const w, h = 100.0, 24.0
	var b strings.Builder
	for i, v := range pts {
		x := float64(i) / float64(len(pts)-1) * w
		// y inverted so larger durations sit higher; flat mid-line when span==0.
		y := h / 2
		if span > 0 {
			y = h - (float64(v-minV)/span)*h
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return template.HTML(fmt.Sprintf( //nolint:gosec // G203: all inputs are numeric, no user data
		`<svg class="spark" viewBox="0 0 100 24" preserveAspectRatio="none" aria-hidden="true"><polyline points="%s"/></svg>`,
		b.String()))
}

// outcomeStrip renders the recent run outcomes (true=success) as a compact row
// of colored ticks, oldest-left. Returns "" when there is no history.
func outcomeStrip(series []bool) template.HTML {
	pts := tail(series, sparkMaxPoints)
	if len(pts) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<span class="outcome">`)
	for _, ok := range pts {
		if ok {
			b.WriteString(`<i></i>`)
		} else {
			b.WriteString(`<i class="f"></i>`)
		}
	}
	b.WriteString(`</span>`)
	return template.HTML(b.String()) //nolint:gosec // G203: fixed markup, no user data
}

// render writes the HTML status page for p to w.
func render(w io.Writer, p pageModel) error {
	return tmpl.Execute(w, p)
}
