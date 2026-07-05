package box

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
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
		if agentNotFound(err) {
			writeStatus(statusFD, "ERR agent-not-found "+strconv.Quote(d.AgentArgv[0]))
			return 127
		}
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
	agent, err := resolveAgentPath(d.AgentArgv[0], env)
	if err != nil {
		return 0, err
	}
	proc, err := startAgentChild(agent, d.AgentArgv[1:], env, statusFD, root, "", nil, nil)
	if err != nil {
		return 0, err
	}
	forwardSignals(proc.Pid)
	code := waitForPID(proc.Pid)
	_ = proc.Release()
	return code, nil
}

func agentNotFound(err error) bool {
	return errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist)
}

func resolveAgentPath(name string, env []string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return name, nil
	}
	path := envValue(env, "PATH")
	if path == "" {
		path = os.Getenv("PATH")
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		candidate := filepath.Join(dir, name)
		st, err := os.Stat(candidate)
		if err != nil || st.IsDir() || st.Mode().Perm()&0111 == 0 {
			continue
		}
		return candidate, nil
	}
	return "", exec.ErrNotFound
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, kv := range env {
		if strings.HasPrefix(kv, prefix) {
			return strings.TrimPrefix(kv, prefix)
		}
	}
	return ""
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

func startAgentChild(agent string, args []string, env []string, statusFD int, root string, slavePath string, ctl *os.File, master *os.File) (*os.Process, error) {
	if slavePath == "" {
		slavePath = "-"
	}
	masterFD := -1
	if master != nil {
		masterFD = agentPTYMasterFD
	}
	argv := append([]string{"cove-agent", "__agent", root, slavePath, strconv.Itoa(masterFD), agent}, args...)
	status := os.NewFile(uintptr(statusFD), "cove-status")
	files := []*os.File{
		os.Stdin,
		os.Stdout,
		os.Stderr,
		nil,
		status,
	}
	if slavePath != "-" {
		files[0], files[1], files[2] = nil, nil, nil
		files = append(files, ctl, master)
	}
	sys := &syscall.SysProcAttr{}
	if slavePath != "-" {
		sys.Setsid = true
	} else {
		sys.Setpgid = true
	}
	proc, err := os.StartProcess(agentTrampolinePath, argv, &os.ProcAttr{
		Env:   scrubAgentEnv(env),
		Files: files,
		Sys:   sys,
	})
	if err == nil {
		_ = os.Remove(agentTrampolinePath)
	}
	return proc, err
}
