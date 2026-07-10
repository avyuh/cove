// Package explain turns persisted denial records into a single safe next step.
package explain

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cove/internal/clierr"
	"cove/internal/config"
	"cove/internal/proxy"
)

type candidate struct {
	rec   proxy.AuditRecord
	order int
}

func Run(args []string) error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	return run(args, config.StateDir(), cfg, os.Stdout)
}
func run(args []string, state string, cfg *config.Config, out io.Writer) error {
	fs := flag.NewFlagSet("cove explain", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return clierr.Wrap(clierr.EXUsage, "invalid explain option", nil, "cove help explain", err)
	}
	if fs.NArg() != 1 || fs.Arg(0) != "last" {
		return clierr.Wrap(clierr.EXUsage, "explain accepts only: last", nil, "cove help explain", nil)
	}
	c, ok := newest(state)
	if !ok {
		fmt.Fprintln(out, "nothing stored to explain\ntry: cove log --last")
		return nil
	}
	path := c.rec.Path
	if path == "" {
		path = "/"
	} else if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	fmt.Fprintf(out, "blocked: %s %s%s (session %s)\n", method(c.rec.Method), c.rec.Host, path, c.rec.Session)
	fmt.Fprintln(out, "because: "+because(c.rec))
	fmt.Fprintln(out, "fix: "+fix(c.rec, cfg))
	return nil
}
func newest(state string) (candidate, bool) {
	var best candidate
	found := false
	order := 0
	for _, suffix := range []string{".5", ".4", ".3", ".2", ".1", ""} {
		f, err := os.Open(filepath.Join(state, "audit.log") + suffix)
		if err != nil {
			continue
		}
		dec := json.NewDecoder(f)
		for {
			var r proxy.AuditRecord
			if dec.Decode(&r) != nil {
				break
			}
			order++
			if r.Policy != "deny" {
				continue
			}
			if !found || r.TS.After(best.rec.TS) || (r.TS.Equal(best.rec.TS) && order > best.order) {
				best = candidate{r, order}
				found = true
			}
		}
		_ = f.Close()
	}
	return best, found
}
func method(s string) string {
	if s == "" {
		return "CONNECT"
	}
	return s
}
func because(r proxy.AuditRecord) string {
	switch r.Reason {
	case "host_policy":
		return "this host is not allowed"
	case "missing_secret":
		return "the protected connection needs its secret"
	case "upstream_transport":
		return "the upstream transport failed"
	case "policy_method":
		return "the protected connection does not grant this method"
	case "policy_resource":
		return "the protected connection does not grant this resource"
	case "policy_operation":
		return "the protected connection does not grant this operation"
	default:
		if r.Reason != "" {
			return r.Reason
		}
		return "the policy blocked this request"
	}
}
func fix(r proxy.AuditRecord, cfg *config.Config) string {
	switch r.Reason {
	case "host_policy":
		if !protected(r.Host, cfg) {
			return "cove allow " + r.Host
		}
		return "cove config edit"
	case "missing_secret":
		if r.Service != "" {
			return "cove add " + r.Service
		}
		return "cove config edit"
	case "upstream_transport":
		return "cove status --verbose"
	case "policy_method", "policy_resource", "policy_operation":
		if s := service(r); s != "" {
			if s == "github" && r.Resource != "" {
				return "cove add github --repo " + strings.TrimPrefix(r.Resource, "/")
			}
			return "cove add " + s
		}
		return "cove config edit"
	default:
		return "cove config edit"
	}
}
func service(r proxy.AuditRecord) string {
	if r.Service != "" {
		return r.Service
	}
	switch r.Host {
	case "api.github.com", "github.com":
		return "github"
	case "api.openai.com":
		return "openai"
	case "api.moonshot.cn":
		return "kimi"
	case "generativelanguage.googleapis.com":
		return "gemini"
	case "huggingface.co":
		return "huggingface"
	}
	if strings.Contains(r.Host, ".s3.") || strings.HasPrefix(r.Host, "s3.") {
		return "s3"
	}
	return ""
}
func protected(host string, cfg *config.Config) bool {
	if cfg == nil {
		return false
	}
	for _, list := range [][]string{hostsInject(cfg.Inject), hostsSig(cfg.SigV4), hostsMTLS(cfg.MTLS)} {
		for _, h := range list {
			if h == host || strings.HasPrefix(h, "*.") && strings.HasSuffix(host, strings.TrimPrefix(h, "*")) {
				return true
			}
		}
	}
	return false
}
func hostsInject(v []config.InjectStanza) []string {
	o := make([]string, len(v))
	for i, x := range v {
		o[i] = x.Host
	}
	return o
}
func hostsSig(v []config.SigV4Stanza) []string {
	o := make([]string, len(v))
	for i, x := range v {
		o[i] = x.Host
	}
	return o
}
func hostsMTLS(v []config.MTLSStanza) []string {
	o := make([]string, len(v))
	for i, x := range v {
		o[i] = x.Host
	}
	return o
}
