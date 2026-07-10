// Package connection implements the small, human-facing policy commands.
package connection

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"cove/internal/clierr"
	"cove/internal/config"
	"cove/internal/prompt"
	"cove/internal/proxy"
)

var (
	loadPolicy                = config.Load
	addManagedAllow           = config.AddManagedAllow
	queuePending              = proxy.QueuePendingAllow
	confirmAllow              = prompt.Confirm
	reloadPolicy              = reloadProxy
	allowNow                  = time.Now
	allowOutput     io.Writer = os.Stdout
	commandOutput   io.Writer = os.Stdout
	commandInput    io.Reader = os.Stdin
	readPassword              = prompt.ReadPassword
	readSecretStdin           = prompt.ReadSecretStdin
	confirmMutation           = prompt.Confirm
)

// Add implements the first authoring wave for catalog services and generic
// token injection. Literal secrets are deliberately not flags.
func Add(args []string) error {
	if len(args) == 0 {
		return clierr.Wrap(clierr.EXUsage, "add requires a service", nil, "cove help add", nil)
	}
	for _, a := range args {
		if a == "--secret" || a == "--token" || a == "--key" || a == "--pat" {
			return clierr.Wrap(clierr.EXUsage, "secrets cannot be passed as command-line arguments", nil, "use --secret-stdin --yes", nil)
		}
	}
	if args[0] == "token" {
		return addToken(args[1:])
	}
	s, ok := services[args[0]]
	if !ok {
		return clierr.Wrap(clierr.EXUsage, "unknown service "+args[0], nil, "cove help add", nil)
	}
	fs := flag.NewFlagSet("cove add "+s.Name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	stdin, yes := fs.Bool("secret-stdin", false, "read secret from stdin"), fs.Bool("yes", false, "skip confirmation")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return clierr.Wrap(clierr.EXUsage, "invalid add option", nil, "cove help add", err)
	}
	return addService(s, *stdin, *yes)
}

func addService(s Service, stdin, yes bool) error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	p, err := compileService(s, cfg)
	if err != nil {
		return clierr.Wrap(clierr.EXUsage, "cannot add "+s.Name, nil, "cove list", err)
	}
	if err := confirmMutation(previewPlan(p), yes); err != nil {
		return clierr.Wrap(clierr.EXUsage, "add was not confirmed", nil, "rerun with --yes", err)
	}
	var secret []byte
	if stdin {
		secret, err = readSecretStdin(commandInput)
	} else {
		secret, err = readPassword(s.Name + " secret: ")
	}
	if err != nil {
		return clierr.Wrap(clierr.EXUsage, "could not read secret", nil, "use --secret-stdin --yes", err)
	}
	if err := commitPlan(context.Background(), p, secret); err != nil {
		return err
	}
	fprint(commandOutput, "saved: "+s.Name+"\n"+p.Try+"\n")
	return nil
}

var tokenName = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var headerName = regexp.MustCompile(`^[!#$%&'*+.^_` + "`" + `|~0-9A-Za-z-]+$`)

func addToken(args []string) error {
	fs := flag.NewFlagSet("cove add token", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	host, env, header := fs.String("host", "", "host"), fs.String("env", "", "dummy env"), fs.String("header", "Authorization: Bearer {secret}", "header template")
	stdin, yes := fs.Bool("secret-stdin", false, "read secret from stdin"), fs.Bool("yes", false, "skip confirmation")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return clierr.Wrap(clierr.EXUsage, "token requires NAME and --host", nil, "cove help add", err)
	}
	name := fs.Arg(0)
	if !tokenName.MatchString(name) {
		return clierr.Wrap(clierr.EXUsage, "invalid token name", nil, "cove help add", nil)
	}
	if _, err := config.ParseExactRule(*host); err != nil {
		return clierr.Wrap(clierr.EXUsage, "invalid token host", nil, "cove help add", err)
	}
	parts := strings.SplitN(*header, ":", 2)
	if len(parts) != 2 || !headerName.MatchString(parts[0]) || strings.ContainsAny(*header, "\r\n") || strings.Count(*header, "{secret}") != 1 {
		return clierr.Wrap(clierr.EXUsage, "invalid token header", nil, "cove help add", nil)
	}
	if *env != "" && !envName.MatchString(*env) {
		return clierr.Wrap(clierr.EXUsage, "invalid token environment name", nil, "cove help add", nil)
	}
	s := Service{Name: "token-" + name, SecretFile: "token-" + name, Stanza: config.InjectStanza{Name: "token-" + name, Host: *host, HeaderName: parts[0], HeaderTemplate: strings.TrimSpace(parts[1]), DummyEnv: *env, DummyValue: "cove-dummy-ask-the-human-to-run-cove-add"}, Try: "try: cove list"}
	return addService(s, *stdin, *yes)
}

func fprint(w io.Writer, s string) { _, _ = io.WriteString(w, s) }

// List reports effective policy names without resolving any credential value.
// Its tab-separated form is intentionally stable for non-terminal callers.
func List(args []string) error {
	if len(args) != 0 {
		return clierr.Wrap(clierr.EXUsage, "list accepts no arguments", nil, "cove help list", nil)
	}
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	for _, st := range cfg.Inject {
		name := st.Name
		if name == "" {
			name = "manual:inject:" + st.Host
		}
		state := "needs a key"
		if strings.HasPrefix(st.Secret, "file:") {
			if _, err := os.Stat(strings.TrimPrefix(st.Secret, "file:")); err == nil {
				state = "ready"
			}
		}
		fmt.Fprintf(commandOutput, "%s\tprotected\t%s\t%s\n", name, st.Host, state)
	}
	for _, a := range cfg.AllowRules {
		fmt.Fprintf(commandOutput, "manual:allow:%s\tallowed\t%s\tn/a\n", config.FormatExactRule(a), config.FormatExactRule(a))
	}
	return nil
}

// Allow implements `cove allow HOST [--once] [--yes]`. It deliberately
// accepts only one concrete destination: wildcard policies remain an explicit
// hand-authored configuration choice.
func Allow(args []string) error {
	fs := flag.NewFlagSet("cove allow", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	once := fs.Bool("once", false, "allow only the next session")
	yes := fs.Bool("yes", false, "skip TTY confirmation")
	if err := fs.Parse(args); err != nil {
		return clierr.Wrap(clierr.EXUsage, "invalid allow option", nil, "cove help allow", err)
	}
	if fs.NArg() != 1 {
		return clierr.Wrap(clierr.EXUsage, "allow accepts exactly one host", nil, "cove help allow", nil)
	}
	rule, err := config.ParseExactRule(fs.Arg(0))
	if err != nil {
		return clierr.Wrap(clierr.EXUsage, "invalid host for allow", nil, "cove help allow", err)
	}
	canonical := config.FormatExactRule(rule)
	cfg, err := loadPolicy("")
	if err != nil {
		return err
	}
	if owner := protectedOwner(cfg, rule); owner != "" {
		return clierr.Wrap(clierr.EXUsage, "cannot allow "+canonical+" because it is already protected by "+owner, nil, "cove list; then cove config edit", nil)
	}

	scope := "current and future sessions"
	if *once {
		scope = "the next session only"
	}
	preview := fmt.Sprintf("Allow %s as opaque TLS.\nAny credential already inside the box may be sent here.\nScope: %s.", canonical, scope)
	if err := confirmAllow(preview, *yes); err != nil {
		if !*yes && strings.Contains(err.Error(), "requires a TTY") {
			return clierr.Wrap(clierr.EXUsage, "confirmation requires a TTY", nil, "rerun with --yes", err)
		}
		return clierr.Wrap(clierr.EXUsage, "allow was not confirmed", nil, "rerun cove allow with --yes", err)
	}

	if *once {
		if err := queuePending(config.StateDir(), rule, allowNow()); err != nil {
			return clierr.Wrap(clierr.EXUnavailable, "could not queue the one-shot allow", nil, "cove status", err)
		}
		fmt.Fprintf(allowOutput, "Allowed %s for the next session only. The next successfully started session will claim it.\n", canonical)
		return nil
	}

	if hasAllow(cfg, rule) {
		fmt.Fprintf(allowOutput, "%s is already allowed for current and future sessions.\n", canonical)
		return nil
	}
	if _, err := addManagedAllow(context.Background(), rule); err != nil {
		return err
	}
	if err := reloadPolicy(); err != nil {
		return clierr.Wrap(clierr.EXUnavailable, "allow was saved, but is not active in the running proxy", nil, "restart cove or run cove status", err)
	}
	fmt.Fprintf(allowOutput, "Allowed %s for current and future sessions.\n", canonical)
	return nil
}

func sameRule(a, b config.AllowRule) bool {
	return a.Host == b.Host && a.Port == b.Port && a.Wildcard == b.Wildcard
}

func hasAllow(cfg *config.Config, rule config.AllowRule) bool {
	for _, current := range cfg.AllowRules {
		if sameRule(current, rule) {
			return true
		}
	}
	return false
}

func protectedOwner(cfg *config.Config, rule config.AllowRule) string {
	for _, st := range cfg.Inject {
		if r, err := config.ParseRule(st.Host); err == nil && sameRule(r, rule) {
			return "inject policy"
		}
	}
	for _, st := range cfg.SigV4 {
		if r, err := config.ParseRule(st.Host); err == nil && sameRule(r, rule) {
			return "sigv4 policy"
		}
	}
	for _, st := range cfg.MTLS {
		if r, err := config.ParseRule(st.Host); err == nil && sameRule(r, rule) {
			return "mtls policy"
		}
	}
	return ""
}

// reloadProxy asks the already-running per-user daemon to atomically load the
// config it just committed. A missing or old daemon is deliberately surfaced
// to callers; saved policy must never be reported as active when it is not.
func reloadProxy() error {
	path := filepath.Join(config.StateDir(), "proxyd.sock")
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := io.WriteString(c, "RELOAD/2\n"); err != nil {
		return err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(line) != "OK/2 reload" {
		return errors.New("proxy did not acknowledge reload")
	}
	return nil
}
