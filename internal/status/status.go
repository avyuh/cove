// Package status implements the deliberately read-only readiness report.
package status

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"cove/internal/clierr"
	"cove/internal/config"
	"cove/internal/proxy"
	"cove/internal/secret"
	"cove/internal/version"
)

type Level int

const (
	Ready Level = iota
	Warning
	Failed
)

type Check struct {
	Name, Detail, Fix string
	Level             Level
	Code              int
	Extra             string
}
type Report struct{ Checks []Check }
type Options struct {
	Verbose    bool
	ConfigPath string
	Userns     func() error
}

func Run(args []string) error {
	fs := flag.NewFlagSet("cove status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	verbose := fs.Bool("verbose", false, "show diagnostic detail")
	if err := fs.Parse(args); err != nil {
		return clierr.Wrap(clierr.EXUsage, "invalid status option", nil, "cove status", err)
	}
	r := RunChecks(Options{Verbose: *verbose})
	Render(os.Stdout, r, *verbose)
	return reportError(r)
}

func RunChecks(opts Options) Report {
	path := opts.ConfigPath
	if path == "" {
		path = filepath.Join(config.ConfigDir(), "config.toml")
	}
	r := Report{}
	cfg, err := config.Load(path)
	if err != nil {
		r.Checks = append(r.Checks, Check{"config", "invalid — cove config edit", "cove config edit", Failed, clierr.EXConfig, err.Error()})
	} else {
		r.Checks = append(r.Checks, Check{"config", "valid", "", Ready, 0, path})
	}
	userns := opts.Userns
	if userns == nil {
		userns = probeUserns
	}
	if err := userns(); err != nil {
		r.Checks = append(r.Checks, Check{"box", "user namespaces unavailable — cove setup", "cove setup", Failed, clierr.EXNoPerm, err.Error()})
	} else {
		r.Checks = append(r.Checks, Check{"box", "user namespaces ready", "", Ready, 0, ""})
	}
	cert, key := filepath.Join(filepath.Dir(path), "ca.pem"), filepath.Join(filepath.Dir(path), "ca-key.pem")
	if ca, err := proxy.LoadCA(cert, key); err != nil || keyUnsafe(key) {
		detail := "CA/key unavailable — cove setup"
		extra := ""
		if err != nil {
			extra = err.Error()
		}
		r.Checks = append(r.Checks, Check{"CA", detail, "cove setup", Failed, clierr.EXConfig, extra})
	} else {
		extra := ""
		if opts.Verbose {
			extra = fingerprint(cert)
		}
		_ = ca
		r.Checks = append(r.Checks, Check{"CA", "local certificate ready", "", Ready, 0, extra})
	}
	if err := ping(filepath.Join(config.StateDir(), "proxyd.sock")); err != nil {
		r.Checks = append(r.Checks, Check{"doorman", "proxy unavailable — cove status --verbose", "cove status --verbose", Failed, clierr.EXUnavailable, err.Error()})
	} else {
		r.Checks = append(r.Checks, Check{"doorman", "proxy ready", "", Ready, 0, "control=2"})
	}
	if agent, err := findAgent(); err != nil {
		r.Checks = append(r.Checks, Check{"agent", "no supported agent on PATH — install claude, codex, or gemini", "install claude", Failed, 127, err.Error()})
	} else {
		r.Checks = append(r.Checks, Check{"agent", "ready", "", Ready, 0, agent})
	}
	if cfg != nil {
		r.Checks = append(r.Checks, credentialChecks(cfg)...)
	}
	return r
}

func credentialChecks(cfg *config.Config) []Check {
	var out []Check
	for _, s := range cfg.Inject {
		out = append(out, credentialCheck(s.Name, s.Host, s.Secret))
	}
	for _, s := range cfg.SigV4 {
		out = append(out, credentialCheck(s.Name, s.Host, s.SecretAccessKey))
	}
	for _, s := range cfg.MTLS {
		c := credentialCheck(s.Name, s.Host, s.ClientKey)
		if secret.Check(s.ClientCert) != secret.Available {
			c.Level, c.Detail = Warning, "needs a key — cove setup"
		}
		out = append(out, c)
	}
	return out
}
func credentialCheck(name, host, ref string) Check {
	if name == "" {
		name = host
	}
	if secret.Check(ref) == secret.Available {
		return Check{name, "ready to inject", "", Ready, 0, "credential configured"}
	}
	return Check{name, "needs a key — cove add " + name, "cove add " + name, Warning, 0, "credential unavailable"}
}
func Render(w io.Writer, r Report, verbose bool) {
	for _, c := range r.Checks {
		mark := "✓"
		if c.Level == Warning {
			mark = "○"
		}
		if c.Level == Failed {
			mark = "x"
		}
		fmt.Fprintf(w, "%s %-10s %s\n", mark, c.Name, c.Detail)
		if verbose && c.Extra != "" {
			fmt.Fprintf(w, "  %s\n", c.Extra)
		}
	}
	if reportError(r) == nil {
		fmt.Fprintln(w, "\nready. try: cove claude")
	}
}
func reportError(r Report) error {
	var worst Check
	for _, c := range r.Checks {
		if c.Level == Failed && (worst.Code == 0 || priority(c.Code) < priority(worst.Code)) {
			worst = c
		}
	}
	if worst.Code == 0 {
		return nil
	}
	return clierr.Wrap(worst.Code, "status check failed: "+worst.Name, nil, worst.Fix, nil)
}
func priority(code int) int {
	switch code {
	case clierr.EXConfig:
		return 1
	case clierr.EXNoPerm:
		return 2
	case clierr.EXUnavailable:
		return 3
	default:
		return 4
	}
}
func keyUnsafe(path string) bool {
	st, err := os.Stat(path)
	return err != nil || st.Mode().Perm()&0077 != 0
}
func fingerprint(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return "CA SHA-256 " + strings.ToUpper(hex.EncodeToString(sum[:]))
}
func ping(path string) error {
	c, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err = io.WriteString(c, "PING\n"); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != "PONG" || f[1] != version.Version || f[2] != "control=2" {
		return fmt.Errorf("bad proxy health response %q", strings.TrimSpace(line))
	}
	return nil
}
func findAgent() (string, error) {
	for _, n := range []string{"claude", "codex", "gemini"} {
		if p, err := exec.LookPath(n); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no supported agent found")
}
func probeUserns() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return exec.Command(exe, "__probe_userns").Run()
}
