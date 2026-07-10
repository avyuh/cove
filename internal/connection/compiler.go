package connection

import (
	"context"
	"fmt"
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
	return config.EditManagedConfig(ctx, func(m *config.ManagedConfig) error {
		m.Version = 1
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
