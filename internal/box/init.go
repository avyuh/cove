package box

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
)

type Directives struct {
	Project        string
	ProxySock      string
	ProxyEnabled   bool
	TmpSize        string
	ProxyPort      int
	AgentArgv      []string
	Term           string
	TTY            bool
	CAPEM          []byte
	CABundlePEM    []byte
	Inject         []InjectDirective
	CredMount      []CredMount
	EnvPassthrough map[string]string
}

type InjectDirective struct {
	DummyEnv     string
	DummyValue   string
	BaseURLEnv   string
	BaseURLValue string
}

type CredMount struct {
	Source string
	Rel    string
	RW     bool
}

func InitMain() int {
	if os.Getenv("COVE_PROBE_USERNS") == "1" {
		return 0
	}
	statusFD, _ := strconv.Atoi(os.Getenv("COVE_STATUS_FD"))
	d, err := readDirectives()
	if err != nil {
		writeStatus(statusFD, "ERR directives "+err.Error())
		return 75
	}
	if err := syscall.Setresgid(0, 0, 0); err != nil {
		writeStatus(statusFD, "ERR setresgid "+err.Error())
		return 75
	}
	if err := syscall.Setresuid(0, 0, 0); err != nil {
		writeStatus(statusFD, "ERR setresuid "+err.Error())
		return 75
	}
	root, err := buildRoot(d)
	if err != nil {
		writeStatus(statusFD, "ERR mount "+err.Error())
		return 75
	}
	if err := bringLoopbackUp(); err != nil {
		writeStatus(statusFD, "ERR lo "+err.Error())
		return 75
	}
	if err := dropCaps(); err != nil {
		writeStatus(statusFD, "ERR capdrop "+err.Error())
		return 75
	}
	if d.ProxyEnabled {
		if err := startShim(d.ProxyPort); err != nil {
			writeStatus(statusFD, "ERR shim "+err.Error())
			return 75
		}
	}
	code, err := runAgent(d, statusFD, root)
	if err != nil {
		writeStatus(statusFD, "ERR exec "+err.Error())
		return 75
	}
	return code
}

func readDirectives() (Directives, error) {
	fd, err := strconv.Atoi(os.Getenv("COVE_DIR_FD"))
	if err != nil {
		return Directives{}, err
	}
	f := os.NewFile(uintptr(fd), "cove-directives")
	if f == nil {
		return Directives{}, fmt.Errorf("directives fd missing")
	}
	defer f.Close()
	var d Directives
	if err := json.NewDecoder(f).Decode(&d); err != nil {
		return Directives{}, err
	}
	if len(d.AgentArgv) == 0 {
		return Directives{}, fmt.Errorf("missing agent argv")
	}
	if d.TmpSize == "" {
		d.TmpSize = "256m"
	}
	if d.ProxyPort == 0 {
		d.ProxyPort = 8080
	}
	return d, nil
}

func writeStatus(fd int, s string) {
	if fd <= 0 {
		return
	}
	_, _ = syscall.Write(fd, []byte(s+"\n"))
}

func runAgent(d Directives, statusFD int, root string) (int, error) {
	env := buildEnv(d)
	if d.TTY {
		return runAgentPTY(d, env, statusFD, root)
	}
	cmd := exec.Command(d.AgentArgv[0], d.AgentArgv[1:]...)
	cmd.Env = env
	cmd.Stdin = os.NewFile(0, "stdin")
	cmd.Stdout = os.NewFile(1, "stdout")
	cmd.Stderr = os.NewFile(2, "stderr")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	writeStatus(statusFD, "OK "+root)
	forwardSignals(cmd.Process.Pid)
	return waitForPID(cmd.Process.Pid), nil
}

func forwardSignals(pid int) {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGCONT)
	go func() {
		for sig := range ch {
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(-pid, s)
			}
		}
	}()
}

func waitForPID(child int) int {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return 1
		}
		if pid != child {
			continue
		}
		if status.Exited() {
			return status.ExitStatus()
		}
		if status.Signaled() {
			return 128 + int(status.Signal())
		}
	}
}

func copyAndClose(dst, src *os.File) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
}
