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
	// stateGlyph is the shape or icon that carries an availability state
	// without color (design system v2: color is never the only signal).
	"stateGlyph": func(state string) template.HTML { return iconUse(stateGlyphName(state), "gl") },
	// skipGlyph is stateGlyph for a skip category.
	"skipGlyph": func(category string) template.HTML { return iconUse(skipGlyphName(category), "gl") },
	// shapeFor maps a health/readiness badge class to its status shape:
	// filled circle healthy, diamond degraded, hollow ring starting.
	"shapeFor": func(class string) template.HTML { return iconUse(shapeName(class), "gl") },
	// headroomClass is the throttle headroom color ramp (state class).
	"headroomClass": headroomClass,
	// sparkline renders a recent-duration trend as an inline SVG polyline.
	// Returns "" for fewer than two points (nothing meaningful to draw).
	"sparkline": sparkline,
	// sparklineF is sparkline for a float series (throttle headroom, #227).
	// html/template cannot call a generic function, so each element type needs
	// its own named entry point.
	"sparklineF": sparklineF,
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

// sparkNumber is the element type a sparkline can be drawn from: run
// durations in milliseconds (int64) and headroom percentages (float64).
type sparkNumber interface {
	~int64 | ~float64
}

// sparkline builds an inline SVG polyline from a recent-duration series.
func sparkline(series []int64) template.HTML { return sparklineOf(series) }

// sparklineF builds an inline SVG polyline from a recent float series.
func sparklineF(series []float64) template.HTML { return sparklineOf(series) }

// Sparkline geometry is the family small-chart standard: 100 x 22, no axis.
const sparkW, sparkH = 100.0, 22.0

// sparklineOf builds an inline SVG polyline (viewBox 0..100 x 0..22) from the
// most recent samples. A flat line is drawn when every sample is equal.
func sparklineOf[T sparkNumber](series []T) template.HTML {
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
	span := float64(maxV) - float64(minV)
	const w, h = sparkW, sparkH
	var b strings.Builder
	for i, v := range pts {
		x := float64(i) / float64(len(pts)-1) * w
		// y inverted so larger durations sit higher; flat mid-line when span==0.
		y := h / 2
		if span > 0 {
			y = h - ((float64(v)-float64(minV))/span)*h
		}
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return template.HTML(fmt.Sprintf( //nolint:gosec // G203: all inputs are numeric, no user data
		`<svg class="spark" viewBox="0 0 100 22" preserveAspectRatio="none" aria-hidden="true"><polyline points="%s"/></svg>`,
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
	failed := 0
	for _, ok := range pts {
		if !ok {
			failed++
		}
	}
	// The strip is never the only carrier: a plain-text count follows it.
	fmt.Fprintf(&b, `<span class="ocount">%d of %d failed</span>`, failed, len(pts))
	return template.HTML(b.String()) //nolint:gosec // G203: fixed markup, numeric values only
}

// stateGlyphName maps an availability state to its glyph id in the page's
// icon sprite. Unknown future states read as the hollow ring (starting).
func stateGlyphName(state string) string {
	switch state {
	case "healthy", "healthy_empty":
		return "s-circle"
	case "limited", "degraded":
		return "i-warning"
	case "blocked":
		return "i-prohibit"
	case "failed", "startup_failed":
		return "i-warning-circle"
	case "covered":
		return "i-arrows-split"
	default: // disabled, starting and any unknown state
		return "s-ring"
	}
}

// skipGlyphName maps a skip category to its glyph id; a plain opt-out has none.
func skipGlyphName(category string) string {
	switch category {
	case skipCatLicense:
		return "i-warning"
	case skipCatExperimental:
		return "i-info"
	default:
		return ""
	}
}

// shapeName maps a badge class (healthClass output) to a status shape.
func shapeName(class string) string {
	switch class {
	case "ok":
		return "s-circle"
	case "err":
		return "s-diamond"
	default:
		return "s-ring"
	}
}

// headroomClass colors a throttle headroom percentage: ok above 60, warn from
// 20 to 60, err below 20. 20 percent left is the 80 percent saturation line the
// g2o throttle alerts already use.
func headroomClass(pct float64) string {
	switch {
	case pct > 60:
		return "ok"
	case pct >= 20:
		return "warn"
	default:
		return "err"
	}
}

// iconUse references a symbol in the page's inline icon sprite. An empty id
// renders nothing.
func iconUse(id, class string) template.HTML {
	if id == "" {
		return ""
	}
	return template.HTML(fmt.Sprintf( //nolint:gosec // G203: id and class are fixed internal literals
		`<svg class="%s" aria-hidden="true"><use href="#%s"/></svg>`, class, id))
}

// render writes the HTML status page for p to w.
func render(w io.Writer, p pageModel) error {
	return tmpl.Execute(w, p)
}
