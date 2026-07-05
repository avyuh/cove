package config

import "testing"

func TestSeedValidates(t *testing.T) {
	cfg, err := LoadBytes([]byte(DefaultConfig))
	if err != nil {
		t.Fatalf("seed config did not validate: %v", err)
	}
	if len(cfg.AllowRules) == 0 {
		t.Fatalf("seed allow rules were not compiled")
	}
}

func TestValidateRejectsBareWildcard(t *testing.T) {
	_, err := LoadBytes([]byte(`allow = ["*"]`))
	if err == nil {
		t.Fatalf("expected bare wildcard rejection")
	}
}

func TestValidateRejectsConflict(t *testing.T) {
	_, err := LoadBytes([]byte(`
allow = ["github.com"]
[[inject]]
host = "github.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "env:TOKEN"
`))
	if err == nil {
		t.Fatalf("expected allow/inject conflict")
	}
}

func TestParseWildcard(t *testing.T) {
	r, err := ParseRule("*.githubusercontent.com")
	if err != nil {
		t.Fatal(err)
	}
	if !r.Wildcard || r.Host != "githubusercontent.com" || r.Port != 443 {
		t.Fatalf("bad wildcard parse: %+v", r)
	}
}

func TestValidateRejectsHeaderTemplateWithoutSecret(t *testing.T) {
	_, err := LoadBytes([]byte(`
[[inject]]
host = "api.example.com"
header_name = "Authorization"
header_template = "Bearer token"
secret = "env:TOKEN"
`))
	if err == nil {
		t.Fatalf("expected header_template without {secret} to be rejected")
	}
}

func TestValidateRejectsBroadCredMountAndEnvPassthrough(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"cred star", `[options]` + "\n" + `cred_mount = ["*"]`},
		{"cred tilde", `[options]` + "\n" + `cred_mount = ["~"]`},
		{"cred root", `[options]` + "\n" + `cred_mount = ["/"]`},
		{"env star", `[options]` + "\n" + `env_passthrough = ["*"]`},
		{"env tilde", `[options]` + "\n" + `env_passthrough = ["~"]`},
		{"env root", `[options]` + "\n" + `env_passthrough = ["/"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(tt.body)); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestParseRuleIPLiteralAndHostPort(t *testing.T) {
	tests := []struct {
		raw  string
		host string
		port int
	}{
		{"1.2.3.4", "1.2.3.4", 443},
		{"1.2.3.4:8443", "1.2.3.4", 8443},
		{"github.com:9443", "github.com", 9443},
		{"[2001:db8::1]:443", "2001:db8::1", 443},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			r, err := ParseRule(tt.raw)
			if err != nil {
				t.Fatal(err)
			}
			if r.Host != tt.host || r.Port != tt.port {
				t.Fatalf("ParseRule(%q) = host %q port %d, want %q %d", tt.raw, r.Host, r.Port, tt.host, tt.port)
			}
		})
	}
}

func TestMissingSecretFileInjectStanzaIsInertAtConfigLoad(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
[[inject]]
host = "api.example.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "file:/definitely/missing/cove/test/secret"
`))
	if err != nil {
		t.Fatalf("missing secret file should not reject config: %v", err)
	}
	if len(cfg.Inject) != 1 {
		t.Fatalf("inject len = %d, want 1", len(cfg.Inject))
	}
}
