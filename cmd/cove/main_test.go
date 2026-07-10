package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"cove/internal/clierr"
)

func TestParseInvocationMatrix(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		kind, cmd string
		agent     []string
		project   string
		wantErr   int
	}{
		{name: "log is command", args: []string{"cove", "log"}, kind: invocationCommand, cmd: "log"},
		{name: "double dash log is agent", args: []string{"cove", "--", "log"}, kind: invocationLauncher, agent: []string{"log"}},
		{name: "launcher flag then log is agent", args: []string{"cove", "-C", "x", "log"}, kind: invocationLauncher, project: "x", agent: []string{"log"}},
		{name: "agent help is preserved", args: []string{"cove", "claude", "--help"}, kind: invocationLauncher, agent: []string{"claude", "--help"}},
		{name: "agent literal separator is preserved", args: []string{"cove", "claude", "--", "--literal"}, kind: invocationLauncher, agent: []string{"claude", "--", "--literal"}},
		{name: "agent empty argument is preserved", args: []string{"cove", "claude", "-p", ""}, kind: invocationLauncher, agent: []string{"claude", "-p", ""}},
		{name: "dash agent uses escape", args: []string{"cove", "--", "-agent"}, kind: invocationLauncher, agent: []string{"-agent"}},
		{name: "empty argv", args: nil, wantErr: 64},
		{name: "unknown launcher flag", args: []string{"cove", "--bad-flag"}, wantErr: 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv, err := parseInvocation(tt.args)
			if tt.wantErr != 0 {
				if err == nil || cliExitCode(err) != tt.wantErr {
					t.Fatalf("parse error = %v (code %d), want code %d", err, cliExitCode(err), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if inv.Kind != tt.kind || inv.Name != tt.cmd {
				t.Fatalf("invocation = %#v, want kind %q command %q", inv, tt.kind, tt.cmd)
			}
			if !reflect.DeepEqual(inv.AgentArgv, tt.agent) {
				t.Fatalf("AgentArgv = %#v, want %#v", inv.AgentArgv, tt.agent)
			}
			if tt.project != "" && inv.Project != tt.project {
				t.Fatalf("Project = %q, want %q", inv.Project, tt.project)
			}
		})
	}
}

func TestReservedNamesNeverUsePATHAliases(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	inv, err := parseInvocation([]string{"cove", "log"})
	if err != nil {
		t.Fatal(err)
	}
	if inv.Kind != invocationCommand || inv.Name != "log" {
		t.Fatalf("log invocation = %#v, want exact public command", inv)
	}
}

func cliExitCode(err error) int {
	if e, ok := err.(*clierr.Error); ok {
		return e.ExitCode()
	}
	return 1
}

func TestLauncherMainUsageExitCodes(t *testing.T) {
	if code := run([]string{"cove", "--bad-flag"}); code != 64 {
		t.Fatalf("bad flag code = %d, want 64", code)
	}
	if code := run([]string{"cove"}); code != 64 {
		t.Fatalf("missing agent code = %d, want 64", code)
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
	if code := run([]string{"cove", "--", "/bin/true"}); code != 78 {
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
			if code := run([]string{"cove", "--", "/bin/true"}); code != 78 {
				t.Fatalf("config %q code = %d, want 78", tt.name, code)
			}
		})
	}
}
