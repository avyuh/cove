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
