package launcher

import (
	"os"
	"path/filepath"
	"testing"

	"cove/internal/config"
)

func TestInitStatusFailureMapsAgentNotFoundTo127(t *testing.T) {
	code, err := initStatusFailure("ERR agent-not-found nonesuch-binary")
	if code != 127 {
		t.Fatalf("code = %d, want 127", code)
	}
	exitErr, ok := err.(ExitError)
	if !ok {
		t.Fatalf("err = %T, want ExitError", err)
	}
	if exitErr.Code != 127 {
		t.Fatalf("ExitError.Code = %d, want 127", exitErr.Code)
	}
}

func TestInitStatusFailureMapsSetupFailureTo75(t *testing.T) {
	code, err := initStatusFailure("ERR mount pivot_root: nope")
	if code != 75 {
		t.Fatalf("code = %d, want 75", code)
	}
	exitErr, ok := err.(ExitError)
	if !ok {
		t.Fatalf("err = %T, want ExitError", err)
	}
	if exitErr.Code != 75 {
		t.Fatalf("ExitError.Code = %d, want 75", exitErr.Code)
	}
}

func TestRunBadProjectReturns66BeforeProxy(t *testing.T) {
	cfg := &config.Config{}
	cfg.Options.ProxyPort = 8080
	code, err := Run(cfg, Opts{Project: filepath.Join(t.TempDir(), "missing"), AgentArgv: []string{"/bin/true"}})
	if code != 66 {
		t.Fatalf("code = %d, want 66", code)
	}
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestParseCredMounts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".config", "gh"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, "relative", "creds"), 0700); err != nil {
		t.Fatal(err)
	}
	mounts, err := parseCredMounts([]string{"~/.config/gh", "relative/creds:rw"})
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 2 {
		t.Fatalf("mounts len = %d, want 2", len(mounts))
	}
	if mounts[0].Source != filepath.Join(home, ".config", "gh") || mounts[0].Rel != filepath.Join(".config", "gh") || mounts[0].RW {
		t.Fatalf("bad first mount: %+v", mounts[0])
	}
	if mounts[1].Source != filepath.Join(home, "relative", "creds") || mounts[1].Rel != filepath.Join("relative", "creds") || !mounts[1].RW {
		t.Fatalf("bad second mount: %+v", mounts[1])
	}
	if _, err := parseCredMounts([]string{filepath.Dir(home)}); err == nil {
		t.Fatalf("expected outside-HOME cred_mount rejection")
	}
}

func TestEnvMatch(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"AWS_*", "AWS_REGION", true},
		{"AWS_*", "AZURE_TOKEN", false},
		{"TOKEN", "TOKEN", true},
		{"TOKEN", "TOKEN_EXTRA", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"/"+tt.name, func(t *testing.T) {
			if got := envMatch(tt.pattern, tt.name); got != tt.want {
				t.Fatalf("envMatch(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
			}
		})
	}
}
