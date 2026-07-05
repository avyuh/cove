package box

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
