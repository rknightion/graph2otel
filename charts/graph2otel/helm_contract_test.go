package graph2otel_test

import (
	"os/exec"
	"regexp"
	"testing"
)

var (
	livenessProbe = regexp.MustCompile(
		`(?m)^ {10}livenessProbe:\n {12}httpGet:\n {14}path: /healthz\n {14}port: admin$`,
	)
	readinessProbe = regexp.MustCompile(
		`(?m)^ {10}readinessProbe:\n {12}httpGet:\n {14}path: /readyz\n {14}port: admin$`,
	)
	adminPort = regexp.MustCompile(
		`(?m)^ {10}ports:\n {12}- name: admin\n {14}containerPort: [0-9]+$`,
	)
)

func TestDeploymentRendersDistinctLivenessAndReadinessEndpoints(t *testing.T) {
	rendered := renderChart(t)

	assertMatchCount(t, rendered, "liveness /healthz probe", livenessProbe, 1)
	assertMatchCount(t, rendered, "readiness /readyz probe", readinessProbe, 1)
	assertMatchCount(t, rendered, "admin port", adminPort, 1)
}

func TestDeploymentOmitsAdminSurfaceWhenDisabled(t *testing.T) {
	rendered := renderChart(t, "--set", "config.admin.enabled=false")

	assertMatchCount(t, rendered, "liveness probe", livenessProbe, 0)
	assertMatchCount(t, rendered, "readiness probe", readinessProbe, 0)
	assertMatchCount(t, rendered, "admin port", adminPort, 0)
}

func renderChart(t *testing.T, args ...string) []byte {
	t.Helper()

	helm, err := exec.LookPath("helm")
	if err != nil {
		t.Skip("helm is not installed; rendered chart contract is exercised by the Helm CI job")
	}

	helmArgs := append([]string{"template", "test", "."}, args...)
	rendered, err := exec.Command(helm, helmArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("helm template %v: %v\n%s", args, err, rendered)
	}
	return rendered
}

func assertMatchCount(
	t *testing.T,
	rendered []byte,
	name string,
	pattern *regexp.Regexp,
	want int,
) {
	t.Helper()

	if got := len(pattern.FindAll(rendered, -1)); got != want {
		t.Errorf("%s count = %d, want %d", name, got, want)
	}
}
