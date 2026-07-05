package launcher

import (
	"io"
	"os"
	"path/filepath"
	"strings"
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
	oldStderr := os.Stderr
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = stderrW
	mounts, err := parseCredMounts([]string{"~/.config/gh", "relative/creds:rw"})
	_ = stderrW.Close()
	os.Stderr = oldStderr
	if err != nil {
		t.Fatal(err)
	}
	warningBytes, err := io.ReadAll(stderrR)
	if err != nil {
		t.Fatal(err)
	}
	warning := string(warningBytes)
	if len(mounts) != 2 {
		t.Fatalf("mounts len = %d, want 2", len(mounts))
	}
	if mounts[0].Source != filepath.Join(home, ".config", "gh") || mounts[0].Rel != filepath.Join(".config", "gh") || mounts[0].RW {
		t.Fatalf("bad first mount: %+v", mounts[0])
	}
	if mounts[1].Source != filepath.Join(home, "relative", "creds") || mounts[1].Rel != filepath.Join("relative", "creds") || !mounts[1].RW {
		t.Fatalf("bad second mount: %+v", mounts[1])
	}
	if !strings.Contains(warning, "~/.config/gh") || !strings.Contains(warning, "read-only") {
		t.Fatalf("read-only warning missing cred_mount and mode: %q", warning)
	}
	if !strings.Contains(warning, "relative/creds:rw") || !strings.Contains(warning, "read-write") {
		t.Fatalf("read-write warning missing cred_mount and mode: %q", warning)
	}
	if _, err := parseCredMounts([]string{filepath.Dir(home)}); err == nil {
		t.Fatalf("expected outside-HOME cred_mount rejection")
	}
}

func TestBuildDirectivesCopiesEnvPassthroughAndInjectTargets(t *testing.T) {
	cfgHome := t.TempDir()
	cfgDir := filepath.Join(cfgHome, "cove")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "ca.pem"), []byte("test-ca\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "secret")
	t.Setenv("AZURE_TOKEN", "nope")
	t.Setenv("EXACT_TOKEN", "exact")
	cfg, err := config.LoadBytes([]byte(`
[options]
env_passthrough = ["AWS_*", "EXACT_TOKEN"]

[[inject]]
host = "api.example.com:9443"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "env:TOKEN"
dummy_env = "EXAMPLE_API_KEY"
base_url_env = "EXAMPLE_BASE_URL"
base_url_value = "https://api.example.com"
`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := buildDirectives(cfg, Opts{AgentArgv: []string{"/bin/true"}}, t.TempDir(), "/tmp/proxy.sock")
	if err != nil {
		t.Fatal(err)
	}
	if d.EnvPassthrough["AWS_REGION"] != "us-east-1" || d.EnvPassthrough["AWS_SECRET_ACCESS_KEY"] != "secret" || d.EnvPassthrough["EXACT_TOKEN"] != "exact" {
		t.Fatalf("env passthrough missing values: %+v", d.EnvPassthrough)
	}
	if _, ok := d.EnvPassthrough["AZURE_TOKEN"]; ok {
		t.Fatalf("non-matching env var was copied: %+v", d.EnvPassthrough)
	}
	if len(d.Inject) != 1 {
		t.Fatalf("inject directives = %d, want 1", len(d.Inject))
	}
	if d.Inject[0].Host != "api.example.com" || d.Inject[0].Port != 9443 {
		t.Fatalf("inject target = %s:%d, want api.example.com:9443", d.Inject[0].Host, d.Inject[0].Port)
	}
}

func TestSweepRootPathsRemovesInactiveImmediately(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "cove-root.stale")
	active := filepath.Join(dir, "cove-root.active")
	if err := os.Mkdir(stale, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(active, 0755); err != nil {
		t.Fatal(err)
	}
	if err := sweepRootPaths([]string{stale, active}, false, func(path string) bool {
		return path == filepath.Clean(active)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale root still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(active); err != nil {
		t.Fatalf("active root was removed: %v", err)
	}
}

func TestSweepRootPathsForceRemovesActive(t *testing.T) {
	active := filepath.Join(t.TempDir(), "cove-root.active")
	if err := os.Mkdir(active, 0755); err != nil {
		t.Fatal(err)
	}
	if err := sweepRootPaths([]string{active}, true, func(string) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(active); !os.IsNotExist(err) {
		t.Fatalf("forced active root still exists or stat failed: %v", err)
	}
}

func TestMountinfoHasMountpointUnescapesPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mountinfo")
	root := "/tmp/cove-root.with space"
	line := "36 25 0:32 / /tmp/cove-root.with\\040space rw,nosuid - tmpfs tmpfs rw\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	if !mountinfoHasMountpoint(path, root) {
		t.Fatalf("mountinfoHasMountpoint did not find escaped mountpoint")
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
