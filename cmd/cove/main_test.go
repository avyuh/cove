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
