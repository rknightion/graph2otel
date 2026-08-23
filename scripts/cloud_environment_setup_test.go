package scripts_test

import (
	"os"
	"strings"
	"testing"
)

func TestCloudEnvironmentSetupContract(t *testing.T) {
	contents, err := os.ReadFile("cloud-environment-setup.sh")
	if err != nil {
		t.Fatal(err)
	}

	script := string(contents)
	required := []string{
		"LOCAL AGENTS: DO NOT RUN THIS SCRIPT",
		"backlog.md@1.50.1",
		`GO_VERSION="1.27.0"`,
		"github.com/golangci/golangci-lint/v2/cmd/golangci-lint v2.13.1",
		"golang.org/x/vuln/cmd/govulncheck v1.3.0",
		"github.com/norwoodj/helm-docs/cmd/helm-docs v1.14.2",
		".bashrc",
	}
	for _, want := range required {
		if !strings.Contains(script, want) {
			t.Errorf("setup script does not contain %q", want)
		}
	}
}
