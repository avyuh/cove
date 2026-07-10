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
)

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
