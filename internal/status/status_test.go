package status

import (
	"bytes"
	"testing"

	"cove/internal/config"
)

func TestRenderNeverPrintsCredentialValues(t *testing.T) {
	var b bytes.Buffer
	Render(&b, Report{Checks: []Check{{Name: "service", Detail: "needs a key — cove add service", Level: Warning, Extra: "credential unavailable"}}}, true)
	if bytes.Contains(b.Bytes(), []byte("super-secret")) {
		t.Fatal("secret leaked")
	}
}

func TestCredentialChecksAreAmber(t *testing.T) {
	checks := credentialChecks(&config.Config{Inject: []config.InjectStanza{{Host: "api.example", Secret: "file:/definitely-not-present"}}})
	if len(checks) != 1 || checks[0].Level != Warning || checks[0].Code != 0 {
		t.Fatalf("checks = %+v", checks)
	}
}
