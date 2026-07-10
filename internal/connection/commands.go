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
	"sort"
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
	if args[0] == "github" {
		return addGitHub(args[1:])
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

func addGitHub(args []string) error {
	fs := flag.NewFlagSet("cove add github", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var repos csvValues
	fs.Var(&repos, "repo", "OWNER/REPO or OWNER/*")
	oauth, stdin, yes := fs.Bool("oauth", false, "use gh OAuth"), fs.Bool("secret-stdin", false, "read PAT from stdin"), fs.Bool("yes", false, "skip confirmation")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*oauth && len(repos) != 0) || (*oauth && *stdin) {
		return clierr.Wrap(clierr.EXUsage, "invalid github option", nil, "cove help add", err)
	}
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	if *oauth {
		return addGitHubOAuth(cfg, *yes)
	}
	if len(repos) == 0 {
		repo, err := originRepository(".git/config")
		if err != nil {
			return clierr.Wrap(clierr.EXUsage, "github requires --repo OWNER/REPO", nil, "cove add github --repo OWNER/REPO", err)
		}
		repos = append(repos, repo)
	}
	for _, repo := range repos {
		if err := validGitHubRepo(repo); err != nil {
			return clierr.Wrap(clierr.EXUsage, "invalid github repository", nil, "cove add github --repo OWNER/REPO", err)
		}
	}
	sort.Strings(repos)
	api, git := githubPAT(repos)
	if err := githubConflict(cfg, api, git); err != nil {
		return clierr.Wrap(clierr.EXUsage, "cannot add github", nil, "cove list", err)
	}
	preview := "protected: github PAT\nhosts: github.com, api.github.com\ncredential: stored host-side; absent from the box\nundo: cove add github --oauth\n"
	if err := confirmMutation(preview, *yes); err != nil {
		return clierr.Wrap(clierr.EXUsage, "add was not confirmed", nil, "rerun with --yes", err)
	}
	var secret []byte
	if *stdin {
		secret, err = readSecretStdin(commandInput)
	} else {
		secret, err = readPassword("GitHub PAT: ")
	}
	if err != nil {
		return clierr.Wrap(clierr.EXUsage, "could not read secret", nil, "use --secret-stdin --yes", err)
	}
	// Rename the credential first.  The sole config commit below performs every
	// policy change together, so no state can expose allow plus one inject.
	if err := config.WriteSecretAtomic(filepath.Join(config.ConfigDir(), "secrets", "github-pat"), secret); err != nil {
		return err
	}
	if err := commitManaged(context.Background(), func(m *config.ManagedConfig) error {
		removeGitHubManaged(m)
		blockPresentBase(cfg, m, "allow", "github.com")
		blockPresentBase(cfg, m, "allow", "api.github.com")
		blockPresentBase(cfg, m, "inject", "github.com")
		blockPresentBase(cfg, m, "inject", "api.github.com")
		m.Inject = append(m.Inject, api, git)
		return nil
	}); err != nil {
		return err
	}
	fprint(commandOutput, "saved: github\nundo: cove add github --oauth\n")
	return nil
}

type csvValues []string

func (v *csvValues) String() string { return strings.Join(*v, ",") }
func (v *csvValues) Set(s string) error {
	for _, p := range strings.Split(s, ",") {
		if p == "" {
			return errors.New("empty repository")
		}
		*v = append(*v, p)
	}
	return nil
}

func validGitHubRepo(repo string) error {
	p := strings.Split(repo, "/")
	if len(p) != 2 || p[0] == "" || p[1] == "" || repo == "*/*" || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(p[0]) || (p[1] != "*" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`).MatchString(p[1])) {
		return errors.New("must be owner/repo or owner/*")
	}
	return nil
}

// originRepository reads git's config syntax directly; it intentionally never
// invokes git or a shell. Only a unique origin URL is accepted.
func originRepository(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	inOrigin := false
	var urls []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			inOrigin = line == `[remote "origin"]`
			continue
		}
		if inOrigin && strings.HasPrefix(line, "url") {
			p := strings.SplitN(line, "=", 2)
			if len(p) == 2 {
				urls = append(urls, strings.TrimSpace(p[1]))
			}
		}
	}
	if len(urls) != 1 {
		return "", errors.New("origin is ambiguous")
	}
	u := strings.TrimSuffix(strings.TrimSpace(urls[0]), ".git")
	var repo string
	if i := strings.Index(u, ":"); i >= 0 && !strings.Contains(u[:i], "/") {
		repo = u[i+1:]
	} else if i := strings.Index(u, "://"); i >= 0 {
		parts := strings.Split(strings.TrimPrefix(u[i+3:], "/"), "/")
		if len(parts) >= 3 {
			repo = strings.Join(parts[1:], "/")
		}
	} else {
		return "", errors.New("unsupported origin URL")
	}
	if err := validGitHubRepo(repo); err != nil {
		return "", err
	}
	return repo, nil
}

func githubConflict(cfg *config.Config, stanzas ...config.InjectStanza) error {
	for _, want := range stanzas {
		for _, current := range cfg.Inject {
			if current.Host == want.Host && current.Name != "" && current.Name != want.Name {
				return fmt.Errorf("%s is already owned by %s", want.Host, current.Name)
			}
		}
	}
	return nil
}
func hasBase(cfg *config.Config, kind, host string) bool {
	if kind == "allow" {
		for _, managed := range cfg.Managed.Allow {
			if managed.Host == host {
				return false
			}
		}
		for _, a := range cfg.AllowRules {
			if config.FormatExactRule(a) == host {
				return true
			}
		}
		return false
	}
	for _, st := range cfg.Inject {
		if st.Host == host && st.Name == "" {
			return true
		}
	}
	return false
}
func blockPresentBase(cfg *config.Config, m *config.ManagedConfig, kind, host string) {
	if !hasBase(cfg, kind, host) {
		return
	}
	for _, b := range m.Block {
		if b.Kind == kind && b.Host == host {
			return
		}
	}
	m.Block = append(m.Block, config.PolicyRef{Kind: kind, Host: host})
}
func removeGitHubManaged(m *config.ManagedConfig) {
	m.Inject = removeInjectNames(m.Inject, "github", "github-api")
	m.Allow = removeAllowNames(m.Allow, "github", "github-api")
}
func removeInjectNames(in []config.InjectStanza, names ...string) []config.InjectStanza {
	out := in[:0]
	for _, x := range in {
		found := false
		for _, n := range names {
			found = found || x.Name == n
		}
		if !found {
			out = append(out, x)
		}
	}
	return out
}
func removeAllowNames(in []config.NamedAllow, names ...string) []config.NamedAllow {
	out := in[:0]
	for _, x := range in {
		found := false
		for _, n := range names {
			found = found || x.Name == n
		}
		if !found {
			out = append(out, x)
		}
	}
	return out
}

func addGitHubOAuth(cfg *config.Config, yes bool) error {
	preview := "GitHub OAuth credential becomes readable in the box. It remains exfiltration-bounded by GitHub policies.\nhosts: github.com, api.github.com\nundo: cove remove github\n"
	if err := confirmMutation(preview, yes); err != nil {
		return clierr.Wrap(clierr.EXUsage, "add was not confirmed", nil, "rerun with --yes", err)
	}
	if err := commitManaged(context.Background(), func(m *config.ManagedConfig) error {
		removeGitHubManaged(m)
		blockPresentBase(cfg, m, "allow", "github.com")
		blockPresentBase(cfg, m, "allow", "api.github.com")
		blockPresentBase(cfg, m, "inject", "github.com")
		blockPresentBase(cfg, m, "inject", "api.github.com")
		m.Allow = append(m.Allow, config.NamedAllow{Name: "github", Host: "github.com"}, config.NamedAllow{Name: "github-api", Host: "api.github.com"})
		return nil
	}); err != nil {
		return err
	}
	fprint(commandOutput, "saved: github OAuth; PAT stored, disabled\nundo: cove remove github\n")
	return nil
}

// Remove removes only named generated policy. It retains secrets and adds
// blocks for any base policy that would otherwise become effective again.
func Remove(args []string) error {
	fs := flag.NewFlagSet("cove remove", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	yes := fs.Bool("yes", false, "skip confirmation")
	// NAME is the first positional; flags follow it (Go's flag parser stops at the
	// first non-flag, so parse the flags from args after NAME).
	if len(args) < 1 {
		return clierr.Wrap(clierr.EXUsage, "remove requires NAME", nil, "cove list", nil)
	}
	name := args[0]
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return clierr.Wrap(clierr.EXUsage, "remove requires NAME", nil, "cove list", err)
	}
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	found := false
	for _, x := range cfg.Managed.Inject {
		if x.Name == name {
			found = true
		}
	}
	for _, x := range cfg.Managed.Allow {
		if x.Name == name {
			found = true
		}
	}
	if !found {
		return clierr.Wrap(clierr.EXUsage, "unknown or manual connection "+name, nil, "cove list", nil)
	}
	if err := confirmMutation("remove: "+name+"\nconnection will be blocked; stored secrets are retained, disabled\n", *yes); err != nil {
		return clierr.Wrap(clierr.EXUsage, "remove was not confirmed", nil, "rerun with --yes", err)
	}
	if err := commitManaged(context.Background(), func(m *config.ManagedConfig) error {
		for _, x := range m.Inject {
			if x.Name == name {
				blockPresentBase(cfg, m, "allow", x.Host)
				blockPresentBase(cfg, m, "inject", x.Host)
			}
		}
		for _, x := range m.Allow {
			if x.Name == name {
				blockPresentBase(cfg, m, "allow", x.Host)
			}
		}
		m.Inject = removeInjectNames(m.Inject, name)
		m.Allow = removeAllowNames(m.Allow, name)
		return nil
	}); err != nil {
		return err
	}
	fprint(commandOutput, "removed: "+name+"; stored, disabled\n")
	return nil
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
	// NAME is the first positional; flags follow it. Go's flag parser stops at the
	// first non-flag, so parse the flags from args after NAME.
	if len(args) < 1 {
		return clierr.Wrap(clierr.EXUsage, "token requires NAME and --host", nil, "cove help add", nil)
	}
	name := args[0]
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 0 {
		return clierr.Wrap(clierr.EXUsage, "token requires NAME and --host", nil, "cove help add", err)
	}
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
