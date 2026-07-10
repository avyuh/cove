package connection

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cove/internal/config"
)

// Plan is deliberately value-only: it describes policy and secret file names,
// never a secret value. Compile performs no I/O beyond its supplied snapshot.
type Plan struct {
	Name       string
	Stanza     config.InjectStanza
	BlockBase  bool
	SecretPath string
	Try        string
}

// MTLSPlan is deliberately reference-only. Client identity material remains at
// the user-selected host paths; cove neither copies it nor puts it in output.
type MTLSPlan struct {
	Name      string
	Stanza    config.MTLSStanza
	BlockBase []config.PolicyRef
}

// commitManaged applies a complete policy transition in one managed-config
// replacement.  It is used for multi-host connections (notably GitHub), where
// observing half a transition would be unsafe.
func commitManaged(ctx context.Context, mutate func(*config.ManagedConfig) error) error {
	return config.EditManagedConfig(ctx, func(m *config.ManagedConfig) error {
		m.Version = 1
		return mutate(m)
	})
}

func compileService(s Service, cfg *config.Config) (Plan, error) {
	st := s.Stanza
	st.Secret = "file:" + filepath.Join(config.ConfigDir(), "secrets", s.SecretFile)
	p := Plan{Name: s.Name, Stanza: st, SecretPath: strings.TrimPrefix(st.Secret, "file:"), Try: s.Try}
	for _, current := range cfg.Inject {
		if current.Host == st.Host && current.Name != "" && current.Name != st.Name {
			return Plan{}, fmt.Errorf("%s is already owned by %s", st.Host, current.Name)
		}
		if current.Host == st.Host && current.Name == "" {
			p.BlockBase = true
		}
	}
	return p, nil
}

func commitPlan(ctx context.Context, p Plan, secret []byte) error {
	// Secret first means a crash can leave only an unused host-side credential.
	if err := config.WriteSecretAtomic(p.SecretPath, secret); err != nil {
		return err
	}
	return commitManaged(ctx, func(m *config.ManagedConfig) error {
		if p.BlockBase {
			found := false
			for _, b := range m.Block {
				if b.Kind == "inject" && b.Host == p.Stanza.Host {
					found = true
				}
			}
			if !found {
				m.Block = append(m.Block, config.PolicyRef{Kind: "inject", Host: p.Stanza.Host})
			}
		}
		for i := range m.Inject {
			if m.Inject[i].Name == p.Name {
				m.Inject[i] = p.Stanza
				return nil
			}
		}
		m.Inject = append(m.Inject, p.Stanza)
		return nil
	})
}

func previewPlan(p Plan) string {
	return fmt.Sprintf("protected: %s\nhost: %s:443\ncredential: stored host-side at %s; absent from the box\nresidual: cove stamps the credential only after policy checks\n%s\n", p.Name, p.Stanza.Host, p.SecretPath, p.Try)
}

func compileMTLS(host, certPath, keyPath string, rules []config.MTLSRule, cfg *config.Config) (MTLSPlan, error) {
	rule, err := config.ParseExactRule(host)
	if err != nil {
		return MTLSPlan{}, fmt.Errorf("invalid mTLS host: %w", err)
	}
	canonical := config.FormatExactRule(rule)
	certPath, err = filepath.Abs(certPath)
	if err != nil {
		return MTLSPlan{}, fmt.Errorf("certificate path: %w", err)
	}
	keyPath, err = filepath.Abs(keyPath)
	if err != nil {
		return MTLSPlan{}, fmt.Errorf("key path: %w", err)
	}
	if err := preflightMTLSIdentity(certPath, keyPath); err != nil {
		return MTLSPlan{}, err
	}
	name := mtlsName(canonical)
	p := MTLSPlan{Name: name, Stanza: config.MTLSStanza{
		Name: name, Host: canonical, ClientCert: "file:" + certPath, ClientKey: "file:" + keyPath, Rules: rules,
	}}

	// A managed mTLS policy may replace its own earlier revision. Any other
	// generated policy owns the host and must be removed explicitly first.
	for _, st := range cfg.Inject {
		if samePolicyHost(st.Host, canonical) {
			return MTLSPlan{}, fmt.Errorf("%s is already owned by %s", canonical, policyName(st.Name, "inject"))
		}
	}
	for _, st := range cfg.SigV4 {
		if samePolicyHost(st.Host, canonical) {
			return MTLSPlan{}, fmt.Errorf("%s is already owned by %s", canonical, policyName(st.Name, "sigv4"))
		}
	}
	for _, allow := range cfg.AllowRules {
		if sameRule(allow, rule) {
			if managedAllowForHost(cfg, canonical) {
				return MTLSPlan{}, fmt.Errorf("%s is already owned by a managed allow policy", canonical)
			}
			p.BlockBase = append(p.BlockBase, config.PolicyRef{Kind: "allow", Host: canonical})
		}
	}
	for _, st := range cfg.MTLS {
		if !samePolicyHost(st.Host, canonical) {
			continue
		}
		if st.Name != "" && st.Name != name {
			return MTLSPlan{}, fmt.Errorf("%s is already owned by %s", canonical, st.Name)
		}
		if st.Name == "" {
			p.BlockBase = append(p.BlockBase, config.PolicyRef{Kind: "mtls", Host: canonical})
		}
	}
	return p, nil
}

func managedAllowForHost(cfg *config.Config, host string) bool {
	for _, allow := range cfg.Managed.Allow {
		if samePolicyHost(allow.Host, host) {
			return true
		}
	}
	return false
}

func mtlsName(host string) string { return "mtls-" + strings.ReplaceAll(host, ":", "-") }

func policyName(name, kind string) string {
	if name != "" {
		return name
	}
	return "manual " + kind + " policy"
}

func samePolicyHost(host, canonical string) bool {
	r, err := config.ParseExactRule(host)
	return err == nil && config.FormatExactRule(r) == canonical
}

// preflightMTLSIdentity deliberately reads only host-side files. A pairing
// failure never reaches the managed editor, and therefore cannot enable a
// policy with unavailable identity material.
func preflightMTLSIdentity(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("certificate file is missing")
		}
		return fmt.Errorf("cannot read certificate file: %w", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("key file is missing")
		}
		return fmt.Errorf("cannot stat key file: %w", err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("key file must not be group- or world-readable")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("cannot read key file: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("certificate and key are not a valid PEM pair")
	}
	return nil
}

func commitMTLSPlan(ctx context.Context, p MTLSPlan) error {
	return commitManaged(ctx, func(m *config.ManagedConfig) error {
		for _, block := range p.BlockBase {
			found := false
			for _, current := range m.Block {
				if current == block {
					found = true
				}
			}
			if !found {
				m.Block = append(m.Block, block)
			}
		}
		for i := range m.MTLS {
			if m.MTLS[i].Name == p.Name {
				m.MTLS[i] = p.Stanza
				return nil
			}
		}
		m.MTLS = append(m.MTLS, p.Stanza)
		return nil
	})
}

func previewMTLSPlan(p MTLSPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "protected: mTLS\nhost: %s\nclient certificate: stored host-side; absent from the box\nallowed pairs:\n", p.Stanza.Host)
	for _, rule := range p.Stanza.Rules {
		fmt.Fprintf(&b, "  %s %s\n", rule.Method, rule.PathPrefix)
	}
	b.WriteString("residual: cove presents the client certificate only after the configured method/path pair passes policy checks\n")
	return b.String()
}
