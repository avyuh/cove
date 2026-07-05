package proxy

import (
	"testing"

	"cove/internal/config"
)

func TestMatcher(t *testing.T) {
	cfg, err := config.LoadBytes([]byte(`allow = ["github.com", "*.githubusercontent.com", "1.2.3.4"]`))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)
	if p, _ := m.Match("github.com", 443); p != PolicyAllow {
		t.Fatalf("github exact = %v", p)
	}
	if p, _ := m.Match("objects.githubusercontent.com", 443); p != PolicyAllow {
		t.Fatalf("single wildcard = %v", p)
	}
	if p, _ := m.Match("a.b.githubusercontent.com", 443); p != PolicyDeny {
		t.Fatalf("multi wildcard should deny, got %v", p)
	}
	if p, _ := m.Match("githubusercontent.com", 443); p != PolicyDeny {
		t.Fatalf("bare suffix should deny, got %v", p)
	}
	if p, _ := m.Match("5.6.7.8", 443); p != PolicyDeny {
		t.Fatalf("unlisted IP literal should deny, got %v", p)
	}
	if p, _ := m.Match("1.2.3.4", 443); p != PolicyAllow {
		t.Fatalf("listed IP literal should allow, got %v", p)
	}
}
