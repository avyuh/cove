package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLauncherMainUsageExitCodes(t *testing.T) {
	if code := launcherMain([]string{"--bad-flag"}); code != 64 {
		t.Fatalf("bad flag code = %d, want 64", code)
	}
	if code := launcherMain([]string{}); code != 64 {
		t.Fatalf("missing -- code = %d, want 64", code)
	}
}

func TestLauncherMainMalformedConfigReturns78(t *testing.T) {
	cfgHome := t.TempDir()
	dir := filepath.Join(cfgHome, "cove")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[[inject]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	if code := launcherMain([]string{"--", "/bin/true"}); code != 78 {
		t.Fatalf("malformed config code = %d, want 78", code)
	}
}

func TestLauncherMainNegativeConfigReturns78(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "allow inject conflict",
			body: `
allow = ["api.example.com"]
[[inject]]
host = "api.example.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "env:TOKEN"
`,
		},
		{name: "bare wildcard", body: `allow = ["*"]`},
		{name: "broad cred mount", body: `[options]` + "\n" + `cred_mount = ["/"]`},
		{name: "broad runtime mount", body: `[options]` + "\n" + `runtime_mount = ["/"]`},
		{name: "broad env passthrough", body: `[options]` + "\n" + `env_passthrough = ["*"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgHome := t.TempDir()
			dir := filepath.Join(cfgHome, "cove")
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(tt.body), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("XDG_CONFIG_HOME", cfgHome)
			if code := launcherMain([]string{"--", "/bin/true"}); code != 78 {
				t.Fatalf("config %q code = %d, want 78", tt.name, code)
			}
		})
	}
}
