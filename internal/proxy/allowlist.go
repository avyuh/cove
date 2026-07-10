package proxy

import (
	"net"
	"strings"

	"cove/internal/config"
)

type compiledRule struct {
	rule   config.AllowRule
	policy Policy
	inject *InjectPolicy
}

type InjectKind uint8

const (
	InjectHeader InjectKind = iota
	InjectSigV4
	InjectMTLS
)

type InjectPolicy struct {
	Kind   InjectKind
	Header *config.InjectStanza
	SigV4  *config.SigV4Stanza
	MTLS   *config.MTLSStanza
}

func NewMatcher(cfg *config.Config) *Matcher {
	m := &Matcher{}
	for _, r := range cfg.AllowRules {
		m.rules = append(m.rules, compiledRule{rule: r, policy: PolicyAllow})
	}
	for i := range cfg.Inject {
		r, err := config.ParseRule(cfg.Inject[i].Host)
		if err != nil {
			continue
		}
		m.rules = append(m.rules, compiledRule{rule: r, policy: PolicyInject, inject: &InjectPolicy{Kind: InjectHeader, Header: &cfg.Inject[i]}})
	}
	for i := range cfg.SigV4 {
		r, err := config.ParseRule(cfg.SigV4[i].Host)
		if err != nil {
			continue
		}
		m.rules = append(m.rules, compiledRule{rule: r, policy: PolicyInject, inject: &InjectPolicy{Kind: InjectSigV4, SigV4: &cfg.SigV4[i]}})
	}
	for i := range cfg.MTLS {
		r, err := config.ParseRule(cfg.MTLS[i].Host)
		if err != nil {
			continue
		}
		m.rules = append(m.rules, compiledRule{rule: r, policy: PolicyInject, inject: &InjectPolicy{Kind: InjectMTLS, MTLS: &cfg.MTLS[i]}})
	}
	return m
}

func (m *Matcher) Match(host string, port int) (Policy, *InjectPolicy) {
	host = strings.Trim(strings.ToLower(host), "[]")
	ip := net.ParseIP(host)
	var exact *compiledRule
	var wild *compiledRule
	for i := range m.rules {
		r := &m.rules[i]
		if r.rule.Port != port {
			continue
		}
		if r.rule.Wildcard {
			if ip == nil && wildcardMatch(host, r.rule.Host) {
				if wild == nil {
					wild = r
				}
			}
			continue
		}
		if host == r.rule.Host {
			if exact == nil {
				exact = r
			}
		}
	}
	if exact != nil {
		return exact.policy, exact.inject
	}
	if ip != nil {
		return PolicyDeny, nil
	}
	if wild != nil {
		return wild.policy, wild.inject
	}
	return PolicyDeny, nil
}

func wildcardMatch(host, suffix string) bool {
	if !strings.HasSuffix(host, "."+suffix) {
		return false
	}
	left := strings.TrimSuffix(host, "."+suffix)
	return left != "" && !strings.Contains(left, ".")
}
