package config

import (
	"path/filepath"
	"testing"
)

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
		{"cred tilde slash", `[options]` + "\n" + `cred_mount = ["~/"]`},
		{"cred root", `[options]` + "\n" + `cred_mount = ["/"]`},
		{"cred dot", `[options]` + "\n" + `cred_mount = ["."]`},
		{"cred glob", `[options]` + "\n" + `cred_mount = ["~/.config/*"]`},
		{"cred bad suffix", `[options]` + "\n" + `cred_mount = ["~/.codex:ro"]`},
		{"runtime star", `[options]` + "\n" + `runtime_mount = ["*"]`},
		{"runtime tilde", `[options]` + "\n" + `runtime_mount = ["~"]`},
		{"runtime tilde slash", `[options]` + "\n" + `runtime_mount = ["~/"]`},
		{"runtime root", `[options]` + "\n" + `runtime_mount = ["/"]`},
		{"runtime home root", `[options]` + "\n" + `runtime_mount = ["/home"]`},
		{"runtime slash root", `[options]` + "\n" + `runtime_mount = ["/root"]`},
		{"runtime etc", `[options]` + "\n" + `runtime_mount = ["/etc"]`},
		{"runtime parent", `[options]` + "\n" + `runtime_mount = [".."]`},
		{"runtime glob", `[options]` + "\n" + `runtime_mount = ["~/.nvm/*"]`},
		{"runtime rw suffix", `[options]` + "\n" + `runtime_mount = ["~/.nvm:rw"]`},
		{"env star", `[options]` + "\n" + `env_passthrough = ["*"]`},
		{"env tilde", `[options]` + "\n" + `env_passthrough = ["~"]`},
		{"env root", `[options]` + "\n" + `env_passthrough = ["/"]`},
		{"env empty", `[options]` + "\n" + `env_passthrough = [""]`},
		{"env middle glob", `[options]` + "\n" + `env_passthrough = ["AWS_*_KEY"]`},
		{"env double glob", `[options]` + "\n" + `env_passthrough = ["AWS_**"]`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := LoadBytes([]byte(tt.body)); err == nil {
				t.Fatalf("expected rejection")
			}
		})
	}
}

func TestValidateRejectsRuntimeMountHomeOrAncestor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, path := range []string{home, filepath.Dir(home)} {
		t.Run(path, func(t *testing.T) {
			if _, err := LoadBytes([]byte(`[options]` + "\n" + `runtime_mount = ["` + path + `"]`)); err == nil {
				t.Fatalf("expected runtime_mount HOME-or-above rejection for %q", path)
			}
		})
	}
}

func TestValidateAcceptsEnvPassthroughTrailingGlobAndCredRWSuffix(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
[options]
cred_mount = ["~/.codex:rw"]
runtime_mount = ["~/.nvm/versions/node/v22.0.0"]
env_passthrough = ["AWS_*", "EXACT_TOKEN"]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Options.CredMount) != 1 || len(cfg.Options.RuntimeMount) != 1 || len(cfg.Options.EnvPassthrough) != 2 {
		t.Fatalf("options not retained: %+v", cfg.Options)
	}
}

func TestValidateRejectsInvalidWildcardRulesAndPorts(t *testing.T) {
	for _, body := range []string{
		`allow = ["api.*.example.com"]`,
		`allow = ["*."]`,
		`allow = ["example.com:0"]`,
		`allow = ["example.com:70000"]`,
	} {
		t.Run(body, func(t *testing.T) {
			if _, err := LoadBytes([]byte(body)); err == nil {
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
