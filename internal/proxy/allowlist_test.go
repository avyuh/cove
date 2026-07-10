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
		{rule: wildInject, policy: PolicyInject, inject: &InjectPolicy{Kind: InjectHeader, Header: &config.InjectStanza{Host: "*.example.com"}}},
		{rule: exactAllow, policy: PolicyAllow},
	}}
	if p, _ := m.Match("api.example.com", 443); p != PolicyAllow {
		t.Fatalf("exact allow should beat wildcard inject, got %v", p)
	}
	m = &Matcher{rules: []compiledRule{
		{rule: exactInject, policy: PolicyInject, inject: &InjectPolicy{Kind: InjectHeader, Header: &config.InjectStanza{Host: "api.example.com"}}},
	}}
	if p, st := m.Match("api.example.com", 443); p != PolicyInject || st == nil {
		t.Fatalf("exact inject should win exact tie, got policy=%v stanza=%v", p, st)
	}
}

func TestMatcherTaggedInjectPolicies(t *testing.T) {
	cfg, err := config.LoadBytes([]byte(`
[[inject]]
host="headers.example"
header_name="Authorization"
header_template="Bearer {secret}"
secret="env:HEADER_TEST_SECRET"
[[sigv4]]
host="bucket.s3.us-east-1.amazonaws.com"
access_key_id="env:AWS_ACCESS_KEY_ID"
secret_access_key="env:AWS_SECRET_ACCESS_KEY"
account_id="123456789012"
service="s3"
region="us-east-1"
allowed_methods=["GET"]
allowed_operations=["s3:GetObject"]
allowed_resources=["arn:aws:s3:::bucket/*"]
max_body_bytes=1
[[mtls]]
host="partner.example"
client_cert="file:/tmp/cert"
client_key="file:/tmp/key"
allowed_methods=["GET"]
allowed_path_prefixes=["/"]
`))
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cfg)
	for _, tc := range []struct {
		host string
		kind InjectKind
	}{
		{"headers.example", InjectHeader}, {"bucket.s3.us-east-1.amazonaws.com", InjectSigV4}, {"partner.example", InjectMTLS},
	} {
		policy, inject := m.Match(tc.host, 443)
		if policy != PolicyInject || inject == nil || inject.Kind != tc.kind {
			t.Fatalf("%s: policy=%v inject=%+v", tc.host, policy, inject)
		}
	}
}
