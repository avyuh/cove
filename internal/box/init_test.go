package box

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestAgentNotFoundClassifiesENOENT(t *testing.T) {
	if !agentNotFound(exec.ErrNotFound) {
		t.Fatalf("exec.ErrNotFound was not classified")
	}
	if !agentNotFound(os.ErrNotExist) {
		t.Fatalf("os.ErrNotExist was not classified")
	}
	if agentNotFound(errors.New("other")) {
		t.Fatalf("unrelated error was classified")
	}
}

func TestResolveAgentPathUsesBoxEnvPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "/definitely/not/the/box/path")
	got, err := resolveAgentPath("agent", []string{"PATH=" + dir})
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("resolved path = %q, want %q", got, path)
	}
}

func TestBuildEnvInjectBaseURLDummyAndPassthrough(t *testing.T) {
	env := envMap(buildEnv(Directives{
		ProxyEnabled: true,
		ProxyPort:    18080,
		Inject: []InjectDirective{
			{
				DummyEnv:     "KIMI_API_KEY",
				DummyValue:   "dummy-kimi",
				BaseURLEnv:   "KIMI_BASE_URL",
				BaseURLValue: "http://127.0.0.1:49152",
			},
			{
				DummyEnv:     "OPENAI_API_KEY",
				BaseURLEnv:   "OPENAI_BASE_URL",
				BaseURLValue: "https://api.openai.com/v1",
			},
			{
				BaseURLEnv:   "PENDING_BASE_URL",
				BaseURLValue: dynamicBaseURLLoopback,
			},
		},
		EnvPassthrough: map[string]string{
			"AWS_REGION": "us-east-1",
		},
	}))
	if env["KIMI_API_KEY"] != "dummy-kimi" {
		t.Fatalf("KIMI_API_KEY = %q, want dummy-kimi", env["KIMI_API_KEY"])
	}
	if env["KIMI_BASE_URL"] != "http://127.0.0.1:49152" {
		t.Fatalf("KIMI_BASE_URL = %q, want dynamic loopback URL", env["KIMI_BASE_URL"])
	}
	if env["OPENAI_API_KEY"] != "cove-dummy-do-not-use" {
		t.Fatalf("OPENAI_API_KEY = %q, want default dummy", env["OPENAI_API_KEY"])
	}
	if env["OPENAI_BASE_URL"] != "https://api.openai.com/v1" {
		t.Fatalf("OPENAI_BASE_URL = %q, want real HTTPS base URL", env["OPENAI_BASE_URL"])
	}
	if _, ok := env["PENDING_BASE_URL"]; ok {
		t.Fatalf("unallocated :0 base URL reached env: %q", env["PENDING_BASE_URL"])
	}
	if env["AWS_REGION"] != "us-east-1" {
		t.Fatalf("AWS_REGION = %q, want passthrough value", env["AWS_REGION"])
	}
	if env["HTTPS_PROXY"] != "http://127.0.0.1:18080" {
		t.Fatalf("HTTPS_PROXY = %q, want proxy port", env["HTTPS_PROXY"])
	}
}

func TestBuildEnvAppliesGenericDummyEnvWithoutHostAWSSecret(t *testing.T) {
	t.Setenv("AWS_SECRET_ACCESS_KEY", "real-host-secret-must-not-cross")
	env := envMap(buildEnv(Directives{DummyEnv: map[string]string{
		"AWS_ACCESS_KEY_ID":         "COVE0000000000000000",
		"AWS_SECRET_ACCESS_KEY":     "cove-dummy-secret-access-key-do-not-use",
		"AWS_SESSION_TOKEN":         "cove-dummy-session-token-do-not-use",
		"AWS_EC2_METADATA_DISABLED": "true",
	}}))
	for key, want := range map[string]string{
		"AWS_ACCESS_KEY_ID":         "COVE0000000000000000",
		"AWS_SECRET_ACCESS_KEY":     "cove-dummy-secret-access-key-do-not-use",
		"AWS_SESSION_TOKEN":         "cove-dummy-session-token-do-not-use",
		"AWS_EC2_METADATA_DISABLED": "true",
	} {
		if got := env[key]; got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestBuildEnvPrependsRuntimeMountBinToPath(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	env := envMap(buildEnv(Directives{RuntimeMount: []string{root}}))
	wantPrefix := filepath.Join(root, "bin") + string(os.PathListSeparator)
	if !strings.HasPrefix(env["PATH"], wantPrefix) {
		t.Fatalf("PATH = %q, want prefix %q", env["PATH"], wantPrefix)
	}
}

func TestBuildEnvGitHubDummyCredentialConfig(t *testing.T) {
	t.Setenv("GIT_CONFIG_COUNT", "99")
	t.Setenv("GIT_CONFIG_KEY_0", "credential.helper=host")
	t.Setenv("GIT_CONFIG_VALUE_0", "host-secret")
	env := buildEnv(Directives{Inject: []InjectDirective{{
		Transform: "github-basic", DummyValue: "dummy-only-value",
	}}})
	got := envMap(env)
	for key, want := range map[string]string{
		"GIT_CONFIG_COUNT":    "2",
		"GIT_CONFIG_KEY_0":    "credential.https://github.com.helper",
		"GIT_CONFIG_KEY_1":    "credential.https://github.com.useHttpPath",
		"GIT_CONFIG_VALUE_1":  "true",
		"GIT_TERMINAL_PROMPT": "0",
	} {
		if got[key] != want {
			t.Fatalf("%s = %q, want %q", key, got[key], want)
		}
	}
	helper := got["GIT_CONFIG_VALUE_0"]
	if !strings.Contains(helper, "[ \"$op\" = get ]") || !strings.Contains(helper, "protocol") || !strings.Contains(helper, "github.com") {
		t.Fatalf("helper lacks get-only github HTTPS guard: %q", helper)
	}
	if !strings.Contains(helper, "dummy-only-value") || strings.Contains(helper, "host-secret") {
		t.Fatalf("helper dummy/host secret content = %q", helper)
	}
	for _, item := range env {
		if strings.HasPrefix(item, "GIT_CONFIG_KEY_2=") || strings.HasPrefix(item, "GIT_CONFIG_VALUE_2=") {
			t.Fatalf("unexpected command-scope index in %q", item)
		}
	}
}

func TestAppendGitHubDummyCredentialConfigAccountsForExistingEntries(t *testing.T) {
	env := appendGitHubDummyCredentialConfig([]string{
		"GIT_CONFIG_KEY_0=existing.one", "GIT_CONFIG_VALUE_0=value",
		"GIT_CONFIG_KEY_1=existing.two", "GIT_CONFIG_VALUE_1=value",
	}, []InjectDirective{{Transform: "github-basic"}})
	got := envMap(env)
	if got["GIT_CONFIG_COUNT"] != "4" || got["GIT_CONFIG_KEY_2"] != "credential.https://github.com.helper" || got["GIT_CONFIG_KEY_3"] != "credential.https://github.com.useHttpPath" {
		t.Fatalf("command-scope sequence = %+v", got)
	}
}

func TestAgentTrampolineUsesProcSelfExe(t *testing.T) {
	if agentTrampolinePath != "/proc/self/exe" {
		t.Fatalf("agentTrampolinePath = %q, want /proc/self/exe", agentTrampolinePath)
	}
}

func TestWaitForPIDExitAndSignalCodes(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 42")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if code := waitForPID(cmd.Process.Pid); code != 42 {
		t.Fatalf("exit code = %d, want 42", code)
	}

	cmd = exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if code := waitForPID(cmd.Process.Pid); code != 128+int(syscall.SIGTERM) {
		t.Fatalf("signal code = %d, want %d", code, 128+int(syscall.SIGTERM))
	}
}

func envMap(env []string) map[string]string {
	out := map[string]string{}
	for _, kv := range env {
		name, val, ok := strings.Cut(kv, "=")
		if ok {
			out[name] = val
		}
	}
	return out
}
