package launcher

import (
	"cove/internal/clierr"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cove/internal/config"
	"cove/internal/secret"
)

func TestDryRunCredentialPostureDoesNotResolveSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-token")
	const secretValue = "real-secret-value-must-not-be-reported"
	if err := os.WriteFile(path, []byte(secretValue+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ref := "file:" + path
	cfg := &config.Config{
		Inject: []config.InjectStanza{{
			Host: "api.example.com", Secret: ref,
			Issuer: "human:security-ceremony", MaxTTL: "30m", BootstrapRef: "human:yubikey-slot-9a",
		}},
		SigV4: []config.SigV4Stanza{{
			Host: "my-bucket.s3.us-east-1.amazonaws.com", AccessKeyID: ref, SecretAccessKey: ref, SessionToken: ref,
		}},
		MTLS: []config.MTLSStanza{{
			Host: "partner.example.com", ClientCert: ref, ClientKey: ref,
		}},
	}

	proj := t.TempDir()
	report := captureStdout(t, func() {
		code, err := Run(cfg, Opts{DryRun: true, Project: proj, AgentArgv: []string{"agent"}})
		if err != nil || code != 0 {
			t.Fatalf("Run() = (%d, %v), want (0, nil)", code, err)
		}
	})
	// The humanized dry-run (architecture §11.1) shows a credential summary, not
	// individual refs or values. It must never print the resolved secret value,
	// and per the design it does not print the secret ref path either.
	for _, want := range []string{"Would start", "Credentials:", "protected", "Network:", "Audit:"} {
		if !strings.Contains(report, want) {
			t.Errorf("report missing %q:\n%s", want, report)
		}
	}
	if strings.Contains(report, secretValue) {
		t.Fatalf("report leaked resolved secret value: %q", report)
	}
	if strings.Contains(report, ref) {
		t.Errorf("report printed a secret ref (should show only a summary):\n%s", report)
	}
}

func TestSecretCacheObservesAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credential")
	if err := os.WriteFile(path, []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cache := secret.NewCache(nil)
	ref := "file:" + path
	if got, err := cache.Resolve(ref); err != nil || got != "first" {
		t.Fatalf("initial Resolve() = %q, %v", got, err)
	}
	tmp := filepath.Join(dir, "credential.new")
	if err := os.WriteFile(tmp, []byte("second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	if got, err := cache.Resolve(ref); err != nil || got != "second" {
		t.Fatalf("Resolve() after atomic replacement = %q, %v", got, err)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() { os.Stdout = old })
	fn()
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestInitStatusFailureMapsAgentNotFoundTo127(t *testing.T) {
	code, err := initStatusFailure("ERR agent-not-found nonesuch-binary")
	if code != 127 {
		t.Fatalf("code = %d, want 127", code)
	}
	ce := new(clierr.Error)
	ok := errors.As(err, &ce)
	if !ok {
		t.Fatalf("err = %T, want *clierr.Error", err)
	}
	if ce.Code != 127 {
		t.Fatalf("clierr.Error.Code = %d, want 127", ce.Code)
	}
}

func TestInitStatusFailureMapsSetupFailureTo75(t *testing.T) {
	code, err := initStatusFailure("ERR mount pivot_root: nope")
	if code != 75 {
		t.Fatalf("code = %d, want 75", code)
	}
	ce := new(clierr.Error)
	ok := errors.As(err, &ce)
	if !ok {
		t.Fatalf("err = %T, want *clierr.Error", err)
	}
	if ce.Code != 75 {
		t.Fatalf("clierr.Error.Code = %d, want 75", ce.Code)
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

func TestPreflightUsernsProbeSuccessProceedsWithoutProfile(t *testing.T) {
	oldProbe := probeUsernsSelf
	t.Cleanup(func() {
		probeUsernsSelf = oldProbe
	})
	called := false
	probeUsernsSelf = func() error {
		called = true
		return nil
	}

	if err := preflightUserns(); err != nil {
		t.Fatalf("preflightUserns() error = %v, want nil", err)
	}
	if !called {
		t.Fatal("probe did not run")
	}
}

func TestPreflightUsernsProbeFailureReturns77Guidance(t *testing.T) {
	oldProbe := probeUsernsSelf
	t.Cleanup(func() {
		probeUsernsSelf = oldProbe
	})
	probeUsernsSelf = func() error {
		return os.ErrPermission
	}

	err := preflightUserns()
	ce := new(clierr.Error)
	ok := errors.As(err, &ce)
	if !ok {
		t.Fatalf("err = %T, want *clierr.Error", err)
	}
	if ce.Code != 77 {
		t.Fatalf("clierr.Error.Code = %d, want 77", ce.Code)
	}
	if !strings.Contains(ce.What+" "+ce.Fix, "cove setup") {
		t.Fatalf("guidance missing from error: %q", ce.What+" "+ce.Fix)
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
	mounts, err := parseCredMounts([]string{"~/.config/gh", "relative/creds:rw"}, true)
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
	if _, err := parseCredMounts([]string{filepath.Dir(home)}, true); err == nil {
		t.Fatalf("expected outside-HOME cred_mount rejection")
	}
}

func TestResolveRuntimeMountsPicksNVMVersionRoot(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".nvm", "versions", "node", "v22.0.0")
	bin := filepath.Join(root, "bin")
	lib := filepath.Join(root, "lib", "node_modules", "@anthropic-ai", "claude-code")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(lib, 0755); err != nil {
		t.Fatal(err)
	}
	node := filepath.Join(bin, "node")
	if err := os.WriteFile(node, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(lib, "cli.js")
	if err := os.WriteFile(cli, []byte("#!/usr/bin/env node\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../lib/node_modules/@anthropic-ai/claude-code/cli.js", filepath.Join(bin, "claude")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin)
	mounts, err := resolveRuntimeMounts("claude", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0] != root {
		t.Fatalf("runtime mounts = %#v, want [%q]", mounts, root)
	}
}

func TestResolveRuntimeMountsPicksRootForNativePackageSymlink(t *testing.T) {
	home := t.TempDir()
	root := filepath.Join(home, ".nvm", "versions", "node", "v22.0.0")
	bin := filepath.Join(root, "bin")
	pkgBin := filepath.Join(root, "lib", "node_modules", "@anthropic-ai", "claude-code", "bin")
	if err := os.MkdirAll(bin, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(pkgBin, 0755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(pkgBin, "claude.exe")
	if err := os.WriteFile(target, []byte{0x7f, 'E', 'L', 'F'}, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../lib/node_modules/@anthropic-ai/claude-code/bin/claude.exe", filepath.Join(bin, "claude")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin)
	mounts, err := resolveRuntimeMounts("claude", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(mounts) != 1 || mounts[0] != root {
		t.Fatalf("runtime mounts = %#v, want [%q]", mounts, root)
	}
}

func TestResolveRuntimeMountsRejectsHomeOrAboveWidening(t *testing.T) {
	home := t.TempDir()
	shims := filepath.Join(home, "shims")
	bin := filepath.Join(home, "bin")
	lib := filepath.Join(home, "lib")
	agentDir := filepath.Join(home, "agent")
	for _, dir := range []string{shims, bin, lib, agentDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "node"), []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cli := filepath.Join(agentDir, "cli.js")
	if err := os.WriteFile(cli, []byte("#!/usr/bin/env node\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../agent/cli.js", filepath.Join(shims, "claude")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", shims+string(os.PathListSeparator)+bin)
	mounts, err := resolveRuntimeMounts("claude", nil)
	if err == nil {
		t.Fatalf("expected HOME-or-above guard rejection, got mounts %#v", mounts)
	}
	if !strings.Contains(err.Error(), "options.runtime_mount") || !strings.Contains(err.Error(), "system-install") {
		t.Fatalf("guard error lacks guidance: %v", err)
	}
	for _, mount := range mounts {
		if mount == home || filepath.Dir(home) == mount {
			t.Fatalf("guard returned broad mount: %#v", mounts)
		}
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

func TestBuildDirectivesAddsSigV4Dummies(t *testing.T) {
	for name, regions := range map[string][]string{
		"agreed":    {"us-east-1", "us-east-1"},
		"disagreed": {"us-east-1", "us-west-2"},
	} {
		t.Run(name, func(t *testing.T) {
			cfgHome := t.TempDir()
			cfgDir := filepath.Join(cfgHome, "cove")
			if err := os.MkdirAll(cfgDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cfgDir, "ca.pem"), []byte("test-ca\n"), 0600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("XDG_CONFIG_HOME", cfgHome)
			cfg := &config.Config{SigV4: []config.SigV4Stanza{{Region: regions[0]}, {Region: regions[1]}}}
			d, err := buildDirectives(cfg, Opts{AgentArgv: []string{"/bin/true"}}, t.TempDir(), "/tmp/proxy.sock")
			if err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]string{
				"AWS_ACCESS_KEY_ID":         "COVE0000000000000000",
				"AWS_SECRET_ACCESS_KEY":     "cove-dummy-aws-ask-the-human-to-run-cove-add-s3",
				"AWS_SESSION_TOKEN":         "cove-dummy-aws-ask-the-human-to-run-cove-add-s3",
				"AWS_EC2_METADATA_DISABLED": "true",
			} {
				if got := d.DummyEnv[key]; got != want {
					t.Fatalf("%s = %q, want %q", key, got, want)
				}
			}
			if regions[0] == regions[1] {
				if d.DummyEnv["AWS_REGION"] != regions[0] || d.DummyEnv["AWS_DEFAULT_REGION"] != regions[0] {
					t.Fatalf("region dummies = %+v, want %q", d.DummyEnv, regions[0])
				}
			} else if _, ok := d.DummyEnv["AWS_REGION"]; ok {
				t.Fatalf("AWS_REGION should be omitted for conflicting regions: %+v", d.DummyEnv)
			} else if _, ok := d.DummyEnv["AWS_DEFAULT_REGION"]; ok {
				t.Fatalf("AWS_DEFAULT_REGION should be omitted for conflicting regions: %+v", d.DummyEnv)
			}
		})
	}
}

func TestBuildPlanDummyHintsNeverUseHostSecret(t *testing.T) {
	t.Setenv("REAL_HOST_SECRET", "real-host-secret-must-not-cross")
	cfg, err := config.LoadBytes([]byte(`
[[inject]]
host = "api.example.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "env:REAL_HOST_SECRET"
dummy_env = "EXAMPLE_API_KEY"
`))
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildPlan(cfg, Opts{Project: t.TempDir(), AgentArgv: []string{"/bin/true"}, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Directives.DummyEnv["EXAMPLE_API_KEY"]; got != "cove-dummy-ask-the-human-to-run-cove-add" {
		t.Fatalf("dummy = %q", got)
	}
	for _, value := range p.Directives.DummyEnv {
		if value == "real-host-secret-must-not-cross" {
			t.Fatal("real host secret reached box dummy environment")
		}
	}
}

func TestBuildDirectivesDeduplicatesSharedDummyEnv(t *testing.T) {
	cfgHome := t.TempDir()
	cfgDir := filepath.Join(cfgHome, "cove")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "ca.pem"), []byte("test-ca\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	cfg, err := config.LoadBytes([]byte(`
[[inject]]
host="api.example.com"
header_name="Authorization"
header_template="Bearer {secret}"
secret="env:API_TOKEN"
dummy_env="GH_TOKEN"
dummy_value="cove-dummy-gh-token"

[[inject]]
host="github.example.com"
header_name="Authorization"
header_template="Bearer {secret}"
secret="env:GIT_TOKEN"
dummy_env="GH_TOKEN"
dummy_value="cove-dummy-gh-token"
`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := buildDirectives(cfg, Opts{AgentArgv: []string{"/bin/true"}}, t.TempDir(), "/tmp/proxy.sock")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.DummyEnv) != 1 || d.DummyEnv["GH_TOKEN"] != "cove-dummy-gh-token" {
		t.Fatalf("dummy env = %+v, want one shared GH_TOKEN", d.DummyEnv)
	}
}

func TestBuildDirectivesCarriesGitHubBasicTransform(t *testing.T) {
	cfgHome := t.TempDir()
	cfgDir := filepath.Join(cfgHome, "cove")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "ca.pem"), []byte("test-ca\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	cfg, err := config.LoadBytes([]byte(`
[[inject]]
host="github.com"
transform="github-basic"
header_name="Authorization"
basic_username="x-access-token"
secret="env:GH_TOKEN"
dummy_env="GH_TOKEN"
dummy_value="dummy-only-value"
github_repositories=["owner/repo"]
allowed_methods=["GET"]
`))
	if err != nil {
		t.Fatal(err)
	}
	d, err := buildDirectives(cfg, Opts{AgentArgv: []string{"/bin/true"}}, t.TempDir(), "/tmp/proxy.sock")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Inject) != 1 || d.Inject[0].Transform != "github-basic" || d.Inject[0].DummyValue != "dummy-only-value" {
		t.Fatalf("inject directives = %+v", d.Inject)
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
