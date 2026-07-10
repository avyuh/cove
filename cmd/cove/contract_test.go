package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"cove/internal/config"
	"cove/internal/proxy"
	"cove/internal/secret"
)

func buildContractBinary(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "cove-contract")
	cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-o", bin, ".")
	cmd.Dir = "."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build contract binary: %v\n%s", err, out)
	}
	return bin
}

func TestContractExitCodeFidelity(t *testing.T) {
	bin := buildContractBinary(t)
	for _, tt := range []struct {
		name, script string
		want         int
	}{
		{"zero", "exit 0", 0},
		{"seven", "exit 7", 7},
		{"one-twenty-six", "exit 126", 126},
		{"sigterm", "kill -TERM $$", 128 + 15},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(bin, "__agent", "/", "-", "-1", "/bin/sh", "-c", tt.script)
			err := cmd.Run()
			got := 0
			if err != nil {
				exitErr, ok := err.(*exec.ExitError)
				if !ok {
					t.Fatal(err)
				}
				got = exitErr.ExitCode()
				if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
					got = 128 + int(status.Signal())
				}
			}
			if got != tt.want {
				t.Fatalf("cove code = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestContractTTYHasRawAgentPathAndNoReceiptOnStdout(t *testing.T) {
	bin := buildContractBinary(t)
	// script supplies a real PTY. Two dimensions model an initial window and a
	// resize; the agent must see both its stdin and stdout as terminals.
	for _, size := range []string{"24 80", "33 101"} {
		cmdText := "stty rows " + strings.Fields(size)[0] + " cols " + strings.Fields(size)[1] + " raw -echo; " +
			bin + " __agent / - -1 /bin/sh -c 'x=$(dd bs=1 count=1 2>/dev/null); test \"$x\" = x; test -t 0; test -t 1; stty size'"
		cmd := exec.Command("script", "-q", "-e", "-c", cmdText, "/dev/null")
		cmd.Stdin = strings.NewReader("x")
		var stdout bytes.Buffer
		cmd.Stdout = &stdout
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("script TTY (%s): %v\nstdout=%q\nstderr=%q", size, err, stdout.String(), stderr.String())
		}
		if !strings.Contains(stdout.String(), size) {
			t.Fatalf("agent did not receive window %q: %q", size, stdout.String())
		}
		if strings.Contains(stdout.String(), "cove:") {
			t.Fatalf("receipt text reached stdout: %q", stdout.String())
		}
	}
}

func TestContractZeroConfigClaudeAndInertSecuritySnapshot(t *testing.T) {
	home := t.TempDir()
	fixture := filepath.Join("testdata", "zero_config_claude", ".claude", ".credentials.json")
	credential, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude", ".credentials.json"), credential, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	var claudeSecret string
	for _, stanza := range cfg.Inject {
		if stanza.Host == "api.anthropic.com" {
			claudeSecret = stanza.Secret
		}
	}
	if claudeSecret == "" {
		t.Fatal("default config lost Claude's zero-config protected stanza")
	}
	if got, err := secret.NewCache(nil).Resolve(claudeSecret); err != nil || got != "synthetic-cove-contract-token-not-real" {
		t.Fatalf("synthetic Claude credential = %q, %v", got, err)
	}

	snapshot, err := os.ReadFile(filepath.Join("testdata", "inert_security_snapshot.txt"))
	if err != nil {
		t.Fatal(err)
	}
	m := proxy.NewMatcher(cfg)
	for _, line := range strings.Split(string(snapshot), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		hostPort, want := fields[0], fields[1]
		host, portText, _ := strings.Cut(hostPort, ":")
		port := 443
		if portText != "443" {
			t.Fatalf("bad snapshot port %q", portText)
		}
		policy, _ := m.Match(host, port)
		wantPolicy := map[string]proxy.Policy{
			"allow":  proxy.PolicyAllow,
			"inject": proxy.PolicyInject,
			"deny":   proxy.PolicyDeny,
		}[want]
		if policy != wantPolicy {
			t.Fatalf("%s policy = %d, want %q", hostPort, policy, want)
		}
	}
}
