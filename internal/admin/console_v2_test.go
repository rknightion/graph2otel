package admin

import (
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/rknightion/graph2otel/internal/availability"
	"github.com/rknightion/graph2otel/internal/config"
)

// The embedded console follows the m7kni design system v2 family contract
// (design/console-v2/implementation-spec.md). These tests pin that contract:
// the shared token block byte for byte, light-default theming, no request that
// leaves the host, and the AA contrast pairs the spec records.

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readRepoFile(t *testing.T, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(raw)
}

// familyTokenBlock is the first css fence of the family spec: section 1, the
// block shared verbatim by tailscale2otel, opnsense2otel, graph2otel and
// codexlb2otel.
func familyTokenBlock(t *testing.T) string {
	t.Helper()
	spec := readRepoFile(t, "design/console-v2/implementation-spec.md")
	const open = "```css\n"
	start := strings.Index(spec, open)
	if start < 0 {
		t.Fatal("family token block opening fence not found")
	}
	start += len(open)
	end := strings.Index(spec[start:], "\n```")
	if end < 0 {
		t.Fatal("family token block closing fence not found")
	}
	return spec[start : start+end]
}

// tokenBlockEqual reports whether the page's <style> opens with token verbatim.
func tokenBlockEqual(page, token string) bool {
	const open = "<style>\n"
	start := strings.Index(page, open)
	if start < 0 {
		return false
	}
	start += len(open)
	return len(page) >= start+len(token) && page[start:start+len(token)] == token
}

func TestConsoleV2_FamilyTokenBlockMatchesTheSpec(t *testing.T) {
	token := familyTokenBlock(t)
	if !strings.Contains(token, "--t2o-accent:#1d6a8a") || !strings.Contains(token, "Compatibility aliases") {
		t.Fatalf("spec fence is not the family token block: %.80q", token)
	}
	if page := readRepoFile(t, "internal/admin/page.html.tmpl"); !tokenBlockEqual(page, token) {
		t.Error("internal/admin/page.html.tmpl family token block differs from design/console-v2/implementation-spec.md section 1")
	}
}

// The negative case for the identity guard: a plausible local palette edit,
// a dropped line and a leading edit must all be rejected.
func TestConsoleV2_TokenBlockGuardRejectsMutation(t *testing.T) {
	token := familyTokenBlock(t)
	for name, mutated := range map[string]string{
		"recoloured accent": strings.Replace(token, "--t2o-accent:#1d6a8a", "--t2o-accent:#000000", 1),
		"dropped alias":     strings.Replace(token, "  --pending:var(--t2o-fg-muted);\n", "", 1),
		"truncated block":   token[:len(token)-3],
	} {
		if mutated == token {
			t.Fatalf("%s: mutation did not change the block", name)
		}
		if tokenBlockEqual("<style>\n"+mutated+"\n", token) {
			t.Errorf("%s: guard accepted a mutated token block", name)
		}
	}
	if tokenBlockEqual("<style>\n/* a local comment */\n"+token, token) {
		t.Error("guard accepted content before the token block")
	}
}

func TestConsoleV2_ThemeContractLightDefaultOSPreferenceExplicitWins(t *testing.T) {
	page := readRepoFile(t, "internal/admin/page.html.tmpl")
	for _, want := range []string{
		// Persisted choice is applied before first paint and keeps this repo's key.
		"localStorage.getItem('graph2otel-theme')",
		"localStorage.setItem('graph2otel-theme'",
		// No stored choice: follow the OS, otherwise LIGHT.
		"window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light'",
		":root:not([data-theme]){",
		":root[data-theme=\"light\"]{",
		":root[data-theme=\"dark\"]{",
		":root[data-theme=\"light\"]{color-scheme:light}",
		":root[data-theme=\"dark\"]{color-scheme:dark}",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("theme contract missing %q", want)
		}
	}
	if strings.Contains(page, "(prefers-color-scheme: light)") {
		t.Error("page still falls back to dark when the OS expresses no preference")
	}
	// The default :root block is the light palette, so light is the default.
	token := familyTokenBlock(t)
	light, dark := tokenSets(t)
	def := parseTokens(token[:strings.Index(token, "/* No stored preference")])
	for k, v := range light {
		if def[k] != v {
			t.Errorf("default :root %s = %q, want the light value %q", k, def[k], v)
		}
	}
	if light["t2o-bg"] == dark["t2o-bg"] {
		t.Error("light and dark palettes are identical")
	}
}

func TestConsoleV2_FontsAreEmbeddedAndServedOnlyFromTheFixedAllowlist(t *testing.T) {
	s := New(config.AdminConfig{Enabled: true, Addr: "127.0.0.1:0"}, nil, nil, nil, nil, nil, nil)
	for _, name := range []string{"hanken-grotesk-latin.woff2", "hanken-grotesk-latin-ext.woff2", "JetBrainsMono-Variable.woff2"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, consoleFontPrefix+name, nil))
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s = %d, want 200", name, w.Code)
		}
		if got := w.Header().Get("Content-Type"); got != "font/woff2" {
			t.Errorf("%s Content-Type = %q, want font/woff2", name, got)
		}
		if !strings.HasPrefix(w.Body.String(), "wOF2") {
			t.Errorf("%s is not a woff2 file", name)
		}
	}
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, consoleFontPrefix + "unknown.woff2", http.StatusNotFound},
		{http.MethodGet, consoleFontPrefix + "page.html.tmpl", http.StatusNotFound},
		{http.MethodGet, consoleFontPrefix, http.StatusNotFound},
		{http.MethodPost, consoleFontPrefix + "hanken-grotesk-latin.woff2", http.StatusMethodNotAllowed},
	} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
		if w.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, w.Code, tc.want)
		}
	}
	if font, ok := Font("../../page.html.tmpl"); ok || font != nil {
		t.Fatal("Font accepted a non-published filename")
	}
}

var (
	reExternalURL = regexp.MustCompile(`(?i)(?:https?:)?//[a-z0-9][a-z0-9.-]*\.[a-z]{2,}`)
	reURLFunc     = regexp.MustCompile(`url\(\s*["']?([^"')\s]+)`)
	reAttrRef     = regexp.MustCompile(`(?i)\b(?:src|href|action|poster|srcset|data)\s*=\s*"([^"]*)"`)
	reFetchTarget = regexp.MustCompile(`fetch\(\s*'([^']*)'`)
)

// TestConsoleV2_NoExternalNetworkRequests renders the page from a populated
// status and proves nothing in it can reach another origin: no absolute URL
// (the SVG namespace string is the only allowed one and is never fetched), no
// @import, every url()/href/src is local or a data: image, and the only
// network calls in the script are same-origin fetches.
func TestConsoleV2_NoExternalNetworkRequests(t *testing.T) {
	rendered := renderString(t, richStatus())
	for name, body := range map[string]string{
		"rendered page": rendered,
		"page template": readRepoFile(t, "internal/admin/page.html.tmpl"),
	} {
		scrubbed := strings.NewReplacer("http://www.w3.org/2000/svg", "", "http://www.w3.org/1999/xlink", "").Replace(body)
		if m := reExternalURL.FindString(scrubbed); m != "" {
			t.Errorf("%s: external URL %q", name, m)
		}
		if strings.Contains(strings.ToLower(body), "@import") {
			t.Errorf("%s: contains @import", name)
		}
		for _, m := range reURLFunc.FindAllStringSubmatch(body, -1) {
			if !strings.HasPrefix(m[1], "/_static/fonts/") && !strings.HasPrefix(m[1], "data:") {
				t.Errorf("%s: url(%s) is not a local font or data: image", name, m[1])
			}
		}
		for _, m := range reAttrRef.FindAllStringSubmatch(body, -1) {
			ref := m[1]
			if strings.HasPrefix(ref, "{{") || strings.HasPrefix(ref, "#") || strings.HasPrefix(ref, "/") || strings.HasPrefix(ref, "data:") {
				continue
			}
			t.Errorf("%s: attribute reference %q is not same-origin", name, ref)
		}
		for _, m := range reFetchTarget.FindAllStringSubmatch(body, -1) {
			if !strings.HasPrefix(m[1], "/api/") {
				t.Errorf("%s: fetch(%q) is not a same-origin API call", name, m[1])
			}
		}
		for _, banned := range []string{"XMLHttpRequest", "WebSocket", "EventSource", "sendBeacon", "<iframe", "<img ", "<script src", "importScripts"} {
			if strings.Contains(body, banned) {
				t.Errorf("%s: uses %s", name, banned)
			}
		}
	}
}

// A planted external reference must be caught by the guard above.
func TestConsoleV2_ExternalURLGuardCatchesPlantedRequests(t *testing.T) {
	for _, planted := range []string{
		`<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">`,
		`@font-face{src:url("//cdn.example.net/a.woff2")}`,
		`<script src="https://cdn.example.net/x.js"></script>`,
	} {
		if reExternalURL.FindString(planted) == "" {
			t.Errorf("guard missed %q", planted)
		}
	}
}

func hexRGB(t *testing.T, hex string) [3]float64 {
	t.Helper()
	if len(hex) != 7 || hex[0] != '#' {
		t.Fatalf("bad color %q", hex)
	}
	var out [3]float64
	for i := range out {
		v, err := strconv.ParseUint(hex[1+2*i:3+2*i], 16, 8)
		if err != nil {
			t.Fatalf("bad color %q: %v", hex, err)
		}
		out[i] = float64(v) / 255
	}
	return out
}

func luminance(c [3]float64) float64 {
	f := func(v float64) float64 {
		if v <= 0.03928 {
			return v / 12.92
		}
		return math.Pow((v+0.055)/1.055, 2.4)
	}
	return 0.2126*f(c[0]) + 0.7152*f(c[1]) + 0.0722*f(c[2])
}

func contrast(a, b [3]float64) float64 {
	la, lb := luminance(a), luminance(b)
	if la < lb {
		la, lb = lb, la
	}
	return (la + 0.05) / (lb + 0.05)
}

var reToken = regexp.MustCompile(`--(t2o-[a-z0-9-]+):\s*(#[0-9a-fA-F]{6})`)

func parseTokens(block string) map[string]string {
	out := map[string]string{}
	for _, m := range reToken.FindAllStringSubmatch(block, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// tokenSets reads the light and dark palettes from the data-theme blocks of the
// token block, and checks the OS-preference block carries the same dark values,
// so all three routes to a theme agree.
func tokenSets(t *testing.T) (light, dark map[string]string) {
	t.Helper()
	token := familyTokenBlock(t)
	block := func(sel string) string {
		i := strings.Index(token, sel)
		if i < 0 {
			t.Fatalf("token block has no %s", sel)
		}
		j := strings.Index(token[i:], "}")
		return token[i : i+j]
	}
	light = parseTokens(block(`:root[data-theme="light"]{`))
	dark = parseTokens(block(`:root[data-theme="dark"]{`))
	osDark := parseTokens(block(`:root:not([data-theme]){`))
	for k, v := range dark {
		if osDark[k] != v {
			t.Errorf("prefers-color-scheme dark %s = %q, explicit dark = %q", k, osDark[k], v)
		}
	}
	if len(light) != 19 || len(dark) != 19 {
		t.Fatalf("parsed too few tokens: light=%d dark=%d", len(light), len(dark))
	}
	return light, dark
}

// blend returns fg over bg at alpha, for the 10 percent chart area fill.
func blend(fg, bg [3]float64, alpha float64) [3]float64 {
	var out [3]float64
	for i := range out {
		out[i] = fg[i]*alpha + bg[i]*(1-alpha)
	}
	return out
}

// TestConsoleV2_AAContrastPairsHold computes WCAG 2.1 contrast for every pair
// the family spec (section 10) and the graph2otel spec (section 7) record, from
// the colors the page ships, in both themes. Text pairs must reach 4.5; the
// recorded non-text pair reaches 3. The computed value must also match the
// number the spec prints, so a palette drift is caught as well as a failure.
func TestConsoleV2_AAContrastPairsHold(t *testing.T) {
	light, dark := tokenSets(t)
	type pair struct {
		fg, bg       string
		wantL, wantD float64 // as printed in the spec
		min          float64 // 4.5 for text, 3 for meaningful graphics
	}
	pairs := []pair{
		{"t2o-fg", "t2o-bg", 14.72, 14.43, 4.5},
		{"t2o-fg", "t2o-surface", 15.60, 13.49, 4.5},
		{"t2o-fg", "t2o-raised", 16.41, 12.25, 4.5},
		{"t2o-fg", "t2o-hover", 14.00, 12.79, 4.5},
		{"t2o-fg-soft", "t2o-surface", 9.87, 9.16, 4.5},
		{"t2o-fg-muted", "t2o-surface", 5.67, 6.42, 4.5},
		{"t2o-fg-muted", "t2o-raised", 5.97, 5.82, 4.5},
		{"t2o-fg-muted", "t2o-bg", 5.35, 6.86, 4.5},
		{"t2o-accent", "t2o-bg", 5.41, 7.38, 4.5},
		{"t2o-accent", "t2o-surface", 5.73, 6.89, 4.5}, // series-1 and the row marker too
		{"t2o-accent", "t2o-raised", 6.03, 6.26, 4.5},
		{"t2o-on-accent", "t2o-accent", 6.03, 7.38, 4.5},
		{"t2o-accent-hover", "t2o-surface", 7.43, 8.15, 4.5},
		{"t2o-ok", "t2o-surface", 4.79, 6.38, 4.5},
		{"t2o-warn", "t2o-surface", 4.99, 7.00, 4.5}, // series-3 too
		{"t2o-fail", "t2o-surface", 6.03, 5.66, 4.5}, // row marker too
		{"t2o-ok", "t2o-bg", 4.52, 6.82, 4.5},
		{"t2o-warn", "t2o-bg", 4.71, 7.49, 4.5},
		{"t2o-fail", "t2o-bg", 5.69, 6.06, 4.5},
		{"t2o-fg", "t2o-accent-soft", 13.94, 10.91, 4.5},
		{"t2o-fg-soft", "t2o-accent-soft", 8.82, 7.40, 4.5},
		// graph2otel section 7: state words in hovered (raised) rows.
		{"t2o-ok", "t2o-raised", 5.04, 5.79, 4.5},
		{"t2o-warn", "t2o-raised", 5.25, 6.35, 4.5},
		{"t2o-fail", "t2o-raised", 6.35, 5.14, 4.5},
		{"t2o-fg-soft", "t2o-raised", 10.38, 8.32, 4.5},
		// Recorded exception: a bar trough is structure, its value also printed as text.
		{"t2o-accent", "t2o-track", 3.83, 4.37, 3},
	}
	for _, p := range pairs {
		for theme, set := range map[string]map[string]string{"light": light, "dark": dark} {
			fg, bg := set[p.fg], set[p.bg]
			if fg == "" || bg == "" {
				t.Fatalf("%s: token missing for %s on %s", theme, p.fg, p.bg)
			}
			got := contrast(hexRGB(t, fg), hexRGB(t, bg))
			want := p.wantL
			if theme == "dark" {
				want = p.wantD
			}
			// The spec prints ratios from the unrounded oklch sources, so the hex the
			// page ships differs by up to about 0.06. A palette change moves it further.
			if math.Abs(got-want) > 0.1 {
				t.Errorf("%s %s on %s = %.2f, spec records %.2f", theme, p.fg, p.bg, got, want)
			}
			if got < p.min {
				t.Errorf("%s %s on %s = %.2f, below the %.1f floor", theme, p.fg, p.bg, got, p.min)
			}
		}
	}
	// Series 1 on its own area fill (10 percent of series-1 over the surface) is
	// a graphic: the spec requires 3:1.
	for theme, set := range map[string]map[string]string{"light": light, "dark": dark} {
		surface := hexRGB(t, set["t2o-surface"])
		fill := blend(hexRGB(t, set["t2o-accent"]), surface, 0.10)
		got := contrast(hexRGB(t, set["t2o-accent"]), fill)
		if got < 3 {
			t.Errorf("%s series-1 on its area fill = %.2f, want at least 3", theme, got)
		}
	}
}

func TestConsoleV2_SmallChartStandard(t *testing.T) {
	page := readRepoFile(t, "internal/admin/page.html.tmpl")
	for _, want := range []string{
		// Tokens (spec section 3.1) and frozen geometry (section 3.2).
		"--t2o-chart-grid:var(--t2o-line)", "--t2o-chart-axis:var(--t2o-fg-muted)",
		"--t2o-series-1:var(--t2o-accent)", "--t2o-series-2:var(--t2o-fg)", "--t2o-series-3:var(--t2o-warn)",
		"--t2o-chart-area:0.10", "--t2o-chart-h:110px", "--t2o-spark-w:100px", "--t2o-spark-h:22px",
		"var PAD_L=44, PAD_R=8, PAD_T=8, PAD_B=14;",
		// Three gridlines, value labels in the gutter at x=4, 9px mono.
		"[0,0.5,1].forEach", "x:4,y:y+3", "font-size:9px",
		// Stroke patterns carry the series when color cannot.
		".s2{stroke:var(--t2o-series-2);stroke-width:1.5;stroke-dasharray:4 3}",
		".s3{stroke:var(--t2o-series-3);stroke-width:1.6;stroke-dasharray:1 3}",
		// Three series at most; area only for exactly one series.
		".slice(0,3)", "if(series.length===1){",
		// Inline legend and the two non-chart states.
		"function chartLegend", "'collecting, '+maxLen+' of 2 samples'", "'s-ring',offMsg",
		// Crosshair and sampled-point dot.
		"'class':'cross'", "r:2.5",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("small-chart standard: page missing %q", want)
		}
	}
	// The unconditional first-series area of the old chart must be gone.
	if strings.Contains(page, "if(si===0){") {
		t.Error("area fill is still drawn for the first series of a multi-series chart")
	}
	// Every chart has a legend slot above it.
	for _, id := range []string{"Goroutines", "Heap", "GC", "Emit", "Card", "Failing", "Duration"} {
		if !strings.Contains(page, `id="lg`+id+`"`) {
			t.Errorf("chart %s has no legend element", id)
		}
	}
}

func TestSparkline_FamilyGeometry(t *testing.T) {
	got := string(sparkline([]int64{3, 9, 1, 7}))
	if !strings.Contains(got, `viewBox="0 0 100 22"`) {
		t.Errorf("sparkline = %q, want a 100x22 viewBox", got)
	}
	// y stays inside 0..22: the minimum sits on the baseline, the maximum on the top edge.
	if !strings.Contains(got, ",22.0") || !strings.Contains(got, ",0.0") {
		t.Errorf("sparkline = %q, want points spanning y 0..22", got)
	}
	if !strings.Contains(readRepoFile(t, "internal/admin/page.html.tmpl"), "svg.spark polyline{vector-effect:non-scaling-stroke}") {
		t.Error("sparkline stroke is not non-scaling")
	}
}

func TestOutcomeStrip_PlainTextCountAccompaniesTheStrip(t *testing.T) {
	got := string(outcomeStrip([]bool{true, false, true, true, false}))
	if !strings.Contains(got, "2 of 5 failed") {
		t.Errorf("outcomeStrip = %q, want a plain-text failure count", got)
	}
}

func TestHeadroomClassRamp(t *testing.T) {
	for pct, want := range map[float64]string{100: "ok", 60.1: "ok", 60: "warn", 20: "warn", 19.9: "err", 0: "err"} {
		if got := headroomClass(pct); got != want {
			t.Errorf("headroomClass(%v) = %q, want %q", pct, got, want)
		}
	}
}

// Every availability state, and every health class, maps to a shape or icon.
func TestStateGlyphsCoverEveryAvailabilityState(t *testing.T) {
	want := map[availability.State]string{
		availability.StateHealthy:       "s-circle",
		availability.StateHealthyEmpty:  "s-circle",
		availability.StateLimited:       "i-warning",
		availability.StateDegraded:      "i-warning",
		availability.StateBlocked:       "i-prohibit",
		availability.StateFailed:        "i-warning-circle",
		availability.StateStartupFailed: "i-warning-circle",
		availability.StateCovered:       "i-arrows-split",
		availability.StateDisabled:      "s-ring",
		availability.StateStarting:      "s-ring",
	}
	page := readRepoFile(t, "internal/admin/page.html.tmpl")
	for state, glyph := range want {
		if got := stateGlyphName(string(state)); got != glyph {
			t.Errorf("stateGlyphName(%q) = %q, want %q", state, got, glyph)
		}
		if !strings.Contains(page, fmt.Sprintf("<symbol id=%q", glyph)) {
			t.Errorf("icon sprite has no symbol %q", glyph)
		}
	}
	if stateGlyphName("a_future_state") != "s-ring" {
		t.Error("an unknown state must read as the hollow ring")
	}
	for class, shape := range map[string]string{"ok": "s-circle", "err": "s-diamond", "pending": "s-ring"} {
		if got := shapeName(class); got != shape {
			t.Errorf("shapeName(%q) = %q, want %q", class, got, shape)
		}
	}
}

// A failing row carries the 2px inset marker plus a word in its State cell; it
// is no longer a tinted row.
func TestConsoleV2_FailingRowUsesMarkerNotTint(t *testing.T) {
	body := renderString(t, richStatus())
	if !strings.Contains(body, `<tr class="t2o-row--alert">`) {
		t.Error("failing collector row has no row marker")
	}
	if strings.Contains(body, "rgba(") {
		t.Error("page still carries a saturated rgba() fill")
	}
	if strings.Contains(body, "tr.bad") || strings.Contains(body, `class="bad"`) {
		t.Error("tinted bad-row treatment is still present")
	}
}

func TestConsoleV2_ChromeKeepsIDsAndGainsTabRoles(t *testing.T) {
	body := renderString(t, richStatus())
	for _, want := range []string{
		`role="tablist"`, `role="tab"`, `role="tabpanel"`, "aria-selected",
		`id="healthBadge"`, `id="readinessBadge"`, `id="healthReasons"`, `id="staleBanner"`,
		`id="generatedAt"`, `id="updatedAgo"`, `id="pauseBtn"`, `id="refreshNow"`,
		`id="ruHealth"`, `id="ruReadiness"`, `id="ruTenants"`, `id="ruEnabled"`, `id="ruFailing"`, `id="ruPending"`,
		`href="/_static/fonts/hanken-grotesk-latin.woff2"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
}
