package configcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckReportsValidatedCounts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	path := filepath.Join(root, "config", "cove", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("allow = [\"example.com\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := output
	out := new(bytes.Buffer)
	output = out
	t.Cleanup(func() { output = old })
	if err := Run([]string{"check"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "config valid — 0 protected, 1 allowed") {
		t.Fatalf("output = %q", out.String())
	}
}
