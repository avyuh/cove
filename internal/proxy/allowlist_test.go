package proxy

import (
	"testing"

	"cove/internal/config"
)

func TestMatcher(t *testing.T) {
	cfg, err := config.LoadBytes([]byte(`allow = ["github.com", "*.githubusercontent.com", "1.2.3.4", "ssh.github.com:443", "example.com:8443"]`))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)
	tests := []struct {
		name string
		host string
		port int
		want Policy
	}{
		{"exact", "github.com", 443, PolicyAllow},
		{"case insensitive", "GitHub.COM", 443, PolicyAllow},
		{"non 443 denied without explicit rule", "github.com", 444, PolicyDeny},
		{"explicit port", "example.com", 8443, PolicyAllow},
		{"explicit port does not imply 443", "example.com", 443, PolicyDeny},
		{"single wildcard", "objects.githubusercontent.com", 443, PolicyAllow},
		{"multi wildcard denied", "a.b.githubusercontent.com", 443, PolicyDeny},
		{"bare suffix denied", "githubusercontent.com", 443, PolicyDeny},
		{"unlisted IP literal denied", "5.6.7.8", 443, PolicyDeny},
		{"listed IP literal allowed", "1.2.3.4", 443, PolicyAllow},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if p, _ := m.Match(tt.host, tt.port); p != tt.want {
				t.Fatalf("Match(%q, %d) = %v, want %v", tt.host, tt.port, p, tt.want)
			}
		})
	}
}

func TestMatcherPrecedence(t *testing.T) {
	exactAllow, err := config.ParseRule("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	wildInject, err := config.ParseRule("*.example.com")
	if err != nil {
		t.Fatal(err)
	}
	exactInject, err := config.ParseRule("api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	m := &Matcher{rules: []compiledRule{
		{rule: wildInject, policy: PolicyInject, inject: &config.InjectStanza{Host: "*.example.com"}},
		{rule: exactAllow, policy: PolicyAllow},
	}}
	if p, _ := m.Match("api.example.com", 443); p != PolicyAllow {
		t.Fatalf("exact allow should beat wildcard inject, got %v", p)
	}
	m = &Matcher{rules: []compiledRule{
		{rule: exactAllow, policy: PolicyAllow},
		{rule: exactInject, policy: PolicyInject, inject: &config.InjectStanza{Host: "api.example.com"}},
	}}
	if p, st := m.Match("api.example.com", 443); p != PolicyInject || st == nil {
		t.Fatalf("exact inject should win exact tie, got policy=%v stanza=%v", p, st)
	}
}
