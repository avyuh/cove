package launcher

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"cove/internal/box"
	"cove/internal/config"
	"cove/internal/setup"
	"cove/internal/version"
)

type Opts struct {
	Project   string
	NoAudit   bool
	Verbose   bool
	DryRun    bool
	AgentArgv []string
	Version   string
}

type ExitError struct {
	Code int
	Msg  string
}

const usernsDeniedMessage = "cove: user namespaces denied; run `cove setup` (needs sudo, once)"

var (
	probeUsernsSelf = setup.ProbeUsernsSelf
)

var sigV4DummyEnv = map[string]string{
	"AWS_ACCESS_KEY_ID":         "COVE0000000000000000",
	"AWS_SECRET_ACCESS_KEY":     "cove-dummy-secret-access-key-do-not-use",
	"AWS_SESSION_TOKEN":         "cove-dummy-session-token-do-not-use",
	"AWS_EC2_METADATA_DISABLED": "true",
}

func (e ExitError) Error() string {
	return e.Msg
}

func Run(cfg *config.Config, opts Opts) (int, error) {
	if opts.DryRun {
		fmt.Printf("project=%s proxy_port=%d agent=%q\n", opts.Project, cfg.Options.ProxyPort, opts.AgentArgv)
		for _, line := range setup.CredentialPostureLines(cfg) {
			fmt.Println(line)
		}
		return 0, nil
	}
	project, err := resolveProject(opts.Project)
	if err != nil {
		return 66, ExitError{Code: 66, Msg: err.Error()}
	}
	if err := preflightUserns(); err != nil {
		return 77, err
	}
	if err := sweepRoots(false); err != nil && opts.Verbose {
		fmt.Fprintf(os.Stderr, "cove: cleanup warning: %v\n", err)
	}
	control, sessionSock, err := ensureProxySession(opts.AgentArgv[0])
	if err != nil {
		return 69, ExitError{Code: 69, Msg: "cove proxy unavailable: " + err.Error()}
	}
	defer control.Close()
	d, err := buildDirectives(cfg, opts, project, sessionSock)
	if err != nil {
		return 78, err
	}
	d.ProxyEnabled = true
	code, err := spawnInit(d, opts.Verbose)
	return code, err
}

func resolveProject(project string) (string, error) {
	if project == "" {
		project = "."
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("project path %s not found", abs)
	}
	if !st.IsDir() {
		return "", fmt.Errorf("project path %s is not a directory", abs)
	}
	return abs, nil
}

func buildDirectives(cfg *config.Config, opts Opts, project, proxySock string) (box.Directives, error) {
	ca, err := os.ReadFile(filepath.Join(config.ConfigDir(), "ca.pem"))
	if err != nil {
		return box.Directives{}, fmt.Errorf("read cove CA: %w", err)
	}
	bundle, err := os.ReadFile("/etc/ssl/certs/ca-certificates.crt")
	if err != nil {
		bundle = nil
	}
	bundle = append(append([]byte{}, bundle...), '\n')
	bundle = append(bundle, ca...)
	inject := make([]box.InjectDirective, 0, len(cfg.Inject))
	dummyEnv := make(map[string]string)
	for _, st := range cfg.Inject {
		host := st.Host
		port := st.Port
		if r, err := config.ParseRule(st.Host); err == nil {
			host = r.Host
			port = r.Port
		}
		inject = append(inject, box.InjectDirective{
			Host:         host,
			Port:         port,
			Transform:    st.Transform,
			DummyEnv:     st.DummyEnv,
			DummyValue:   st.DummyValue,
			BaseURLEnv:   st.BaseURLEnv,
			BaseURLValue: st.BaseURLValue,
		})
		if st.DummyEnv != "" {
			dummyEnv[st.DummyEnv] = st.DummyValue
		}
	}
	if len(cfg.SigV4) > 0 {
		for key, value := range sigV4DummyEnv {
			dummyEnv[key] = value
		}
		region := cfg.SigV4[0].Region
		for _, st := range cfg.SigV4[1:] {
			if st.Region != region {
				region = ""
				break
			}
		}
		if region != "" {
			dummyEnv["AWS_REGION"] = region
			dummyEnv["AWS_DEFAULT_REGION"] = region
		}
	}
	env := map[string]string{}
	for _, pattern := range cfg.Options.EnvPassthrough {
		for _, kv := range os.Environ() {
			name, val, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			if envMatch(pattern, name) {
				env[name] = val
			}
		}
	}
	creds, err := parseCredMounts(cfg.Options.CredMount)
	if err != nil {
		return box.Directives{}, err
	}
	runtimeMounts, err := resolveRuntimeMounts(opts.AgentArgv[0], cfg.Options.RuntimeMount)
	if err != nil {
		return box.Directives{}, err
	}
	for _, m := range runtimeMounts {
		fmt.Fprintf(os.Stderr, "cove: runtime %s is mounted INTO the box read-only at the same path\n", m)
	}
	return box.Directives{
		Project:        project,
		ProxySock:      proxySock,
		ProxyEnabled:   false,
		TmpSize:        cfg.Options.TmpSize,
		ProxyPort:      cfg.Options.ProxyPort,
		AgentArgv:      opts.AgentArgv,
		Term:           os.Getenv("TERM"),
		TTY:            isTTY(0) && isTTY(1),
		CAPEM:          ca,
		CABundlePEM:    bundle,
		Inject:         inject,
		DummyEnv:       dummyEnv,
		CredMount:      creds,
		RuntimeMount:   runtimeMounts,
		EnvPassthrough: env,
	}, nil
}

func spawnInit(d box.Directives, verbose bool) (int, error) {
	dirR, dirW, err := os.Pipe()
	if err != nil {
		return 75, err
	}
	statusR, statusW, err := os.Pipe()
	if err != nil {
		return 75, err
	}
	var ctlR, ctlW *os.File
	if d.TTY {
		ctlR, ctlW, err = os.Pipe()
		if err != nil {
			return 75, err
		}
		defer ctlW.Close()
	}
	defer dirW.Close()
	defer statusR.Close()

	self, err := os.Executable()
	if err != nil || self == "" {
		self = "/proc/self/exe"
	}
	cmd := exec.Command(self, "__init")
	cmd.Args[0] = "cove-init"
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.ExtraFiles = []*os.File{dirR, statusW}
	cmd.Env = []string{
		"COVE_DIR_FD=3",
		"COVE_STATUS_FD=4",
		"COVE_TERM=" + os.Getenv("TERM"),
	}
	if d.TTY {
		cmd.ExtraFiles = append(cmd.ExtraFiles, ctlR)
		cmd.Env = append(cmd.Env, "COVE_CTL_FD=5")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID | syscall.CLONE_NEWNET |
			syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		UidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getuid(),
			Size:        1,
		}},
		GidMappings: []syscall.SysProcIDMap{{
			ContainerID: 0,
			HostID:      os.Getgid(),
			Size:        1,
		}},
		GidMappingsEnableSetgroups: false,
	}

	raw, rawRestore, err := maybeRaw(d.TTY)
	if err != nil {
		return 75, err
	}
	if raw {
		stopSignalRestore := installRawSignalRestore(rawRestore)
		defer stopSignalRestore()
		defer rawRestore()
	}
	if err := cmd.Start(); err != nil {
		if errors.Is(err, syscall.EPERM) {
			return 77, usernsDeniedError()
		}
		return 75, err
	}
	_ = dirR.Close()
	_ = statusW.Close()
	if ctlR != nil {
		_ = ctlR.Close()
	}
	if err := json.NewEncoder(dirW).Encode(d); err != nil {
		return 75, err
	}
	_ = dirW.Close()
	if d.TTY {
		sendWinsize(ctlW)
		watchWinsize(ctlW)
	}

	line, err := bufio.NewReader(statusR).ReadString('\n')
	if err != nil {
		_ = cmd.Wait()
		return 75, ExitError{Code: 75, Msg: "cove: box setup failed before status"}
	}
	line = strings.TrimSpace(line)
	if verbose {
		fmt.Fprintf(os.Stderr, "cove: init status %s\n", line)
	}
	if !strings.HasPrefix(line, "OK") {
		_ = cmd.Wait()
		return initStatusFailure(line)
	}
	root := ""
	if fields := strings.Fields(line); len(fields) > 1 {
		root = fields[1]
	}
	err = cmd.Wait()
	cleanupRoot(root)
	if err == nil {
		return 0, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
			if status.Exited() {
				return status.ExitStatus(), nil
			}
			if status.Signaled() {
				return 128 + int(status.Signal()), nil
			}
		}
	}
	return 1, err
}

func preflightUserns() error {
	if err := probeUsernsSelf(); err != nil {
		return usernsDeniedError()
	}
	return nil
}

func usernsDeniedError() ExitError {
	return ExitError{Code: 77, Msg: usernsDeniedMessage}
}

func initStatusFailure(line string) (int, error) {
	if strings.HasPrefix(line, "ERR agent-not-found ") {
		agent := strings.TrimSpace(strings.TrimPrefix(line, "ERR agent-not-found "))
		if unquoted, err := strconv.Unquote(agent); err == nil {
			agent = unquoted
		}
		if agent == "" {
			agent = "agent"
		}
		return 127, ExitError{Code: 127, Msg: "cove: agent '" + strings.ReplaceAll(agent, "'", "'\\''") + "' not found in box PATH"}
	}
	return 75, ExitError{Code: 75, Msg: "cove: box setup failed: " + line}
}

func ensureProxySession(agentPath string) (net.Conn, string, error) {
	sock := filepath.Join(config.StateDir(), "proxyd.sock")
	if err := pingProxy(sock); err != nil {
		_ = os.Remove(sock)
		if err := spawnProxy(); err != nil {
			return nil, "", err
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			if err := pingProxy(sock); err == nil {
				break
			}
			if time.Now().After(deadline) {
				return nil, "", fmt.Errorf("PING timed out")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	c, err := net.DialTimeout("unix", sock, 250*time.Millisecond)
	if err != nil {
		return nil, "", err
	}
	sessionID, err := newSessionID()
	if err != nil {
		_ = c.Close()
		return nil, "", err
	}
	agent := filepath.Base(agentPath)
	if agent == "" || agent == "." || agent == string(filepath.Separator) {
		agent = "agent"
	}
	if _, err := fmt.Fprintf(c, "REGISTER %s %s\n", sessionID, sanitizeAgent(agent)); err != nil {
		_ = c.Close()
		return nil, "", err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		_ = c.Close()
		return nil, "", err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "OK ") {
		_ = c.Close()
		return nil, "", errors.New(line)
	}
	return c, strings.TrimSpace(strings.TrimPrefix(line, "OK ")), nil
}

func pingProxy(sock string) error {
	c, err := net.DialTimeout("unix", sock, 250*time.Millisecond)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := io.WriteString(c, "PING\n"); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	line = strings.TrimSpace(line)
	want := "PONG " + version.Version
	if line != want {
		return fmt.Errorf("bad proxy health response %q", line)
	}
	return nil
}

func spawnProxy() error {
	if err := os.MkdirAll(config.StateDir(), 0700); err != nil {
		return err
	}
	logPath := filepath.Join(config.StateDir(), "proxyd.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer logFile.Close()
	null, err := os.OpenFile("/dev/null", os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer null.Close()
	self, err := os.Executable()
	if err != nil || self == "" {
		self = "/proc/self/exe"
	}
	cmd := exec.Command(self, "proxyd")
	cmd.Stdin = null
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}

func newSessionID() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func sanitizeAgent(agent string) string {
	agent = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return '_'
		}
		return r
	}, agent)
	if agent == "" {
		return "agent"
	}
	return agent
}

func parseCredMounts(entries []string) ([]box.CredMount, error) {
	home, _ := os.UserHomeDir()
	var out []box.CredMount
	for _, e := range entries {
		rw := false
		path := e
		if strings.HasSuffix(e, ":rw") {
			rw = true
			path = strings.TrimSuffix(e, ":rw")
		}
		if strings.HasPrefix(path, "~/") {
			path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(home, path)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(home, abs)
		if err != nil || strings.HasPrefix(rel, "..") || rel == "." {
			return nil, fmt.Errorf("cred_mount %q must be under HOME", e)
		}
		if _, err := os.Stat(abs); err != nil {
			fmt.Fprintf(os.Stderr, "cove: warning: cred_mount %s does not exist; skipping\n", abs)
			continue
		}
		mode := "read-only"
		if rw {
			mode = "read-write - UNSAFE under concurrent sessions"
		}
		fmt.Fprintf(os.Stderr, "cove: credential %q is mounted INTO the box %s (exfil-contained, not theft-proof)\n", e, mode)
		out = append(out, box.CredMount{Source: abs, Rel: rel, RW: rw})
	}
	return out, nil
}

func envMatch(pattern, name string) bool {
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(name, strings.TrimSuffix(pattern, "*"))
	}
	return pattern == name
}

func sweepRoots(force bool) error {
	matches, err := filepath.Glob("/tmp/cove-root.*")
	if err != nil {
		return err
	}
	return sweepRootPaths(matches, force, rootActive)
}

func sweepRootPaths(paths []string, force bool, active func(string) bool) error {
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		if !st.IsDir() {
			continue
		}
		if !force && active(filepath.Clean(p)) {
			continue
		}
		_ = syscall.Unmount(p, syscall.MNT_DETACH)
		_ = os.RemoveAll(p)
	}
	return nil
}

func rootActive(root string) bool {
	if mountinfoHasMountpoint("/proc/self/mountinfo", root) {
		return true
	}
	return rootHasLiveOwner(root)
}

func rootHasLiveOwner(root string) bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, ent := range entries {
		if !ent.IsDir() || !allDecimalDigits(ent.Name()) {
			continue
		}
		proc := filepath.Join("/proc", ent.Name())
		if procLinkUnderRoot(filepath.Join(proc, "root"), root) ||
			procLinkUnderRoot(filepath.Join(proc, "cwd"), root) ||
			mountinfoHasMountpoint(filepath.Join(proc, "mountinfo"), root) {
			return true
		}
	}
	return false
}

func procLinkUnderRoot(path, root string) bool {
	target, err := os.Readlink(path)
	if err != nil {
		return false
	}
	target = strings.TrimSuffix(target, " (deleted)")
	target = filepath.Clean(target)
	return target == root || strings.HasPrefix(target, root+string(filepath.Separator))
}

func mountinfoHasMountpoint(path, root string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		mountpoint := filepath.Clean(unescapeMountinfo(fields[4]))
		if mountpoint == root || strings.HasPrefix(mountpoint, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func unescapeMountinfo(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v := (s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0')
			b.WriteByte(v)
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(b byte) bool {
	return b >= '0' && b <= '7'
}

func allDecimalDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func cleanupRoot(root string) {
	if root == "" || !strings.HasPrefix(root, "/tmp/cove-root.") {
		return
	}
	_ = syscall.Unmount(root, syscall.MNT_DETACH)
	_ = os.RemoveAll(root)
}

func isTTY(fd int) bool {
	var ws winsize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	return errno == 0
}

type winsize struct {
	Rows uint16
	Cols uint16
	X    uint16
	Y    uint16
}

func sendWinsize(w *os.File) {
	var ws winsize
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(1), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if errno != 0 || ws.Rows == 0 || ws.Cols == 0 {
		return
	}
	var buf [8]byte
	binary.LittleEndian.PutUint16(buf[0:2], ws.Rows)
	binary.LittleEndian.PutUint16(buf[2:4], ws.Cols)
	binary.LittleEndian.PutUint16(buf[4:6], ws.X)
	binary.LittleEndian.PutUint16(buf[6:8], ws.Y)
	_, _ = w.Write(buf[:])
}

func watchWinsize(w *os.File) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGWINCH)
	go func() {
		for range ch {
			sendWinsize(w)
		}
	}()
}

func installRawSignalRestore(restore func()) func() {
	ch := make(chan os.Signal, 2)
	done := make(chan struct{})
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case sig := <-ch:
			restore()
			signal.Stop(ch)
			signal.Reset(sig)
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(os.Getpid(), s)
				os.Exit(128 + int(s))
			}
			os.Exit(1)
		case <-done:
			signal.Stop(ch)
		}
	}()
	return func() {
		close(done)
	}
}
