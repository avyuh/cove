package setup

import (
	"bytes"
	"testing"

	"cove/internal/clierr"
)

func TestSetupErrorAdapterKeepsCodeAndRendering(t *testing.T) {
	var out bytes.Buffer
	code := clierr.Print(&out, setupError{code: clierr.EXNoPerm, msg: "setup permission denied"}.CLIError())
	if code != clierr.EXNoPerm {
		t.Fatalf("code = %d", code)
	}
	if got, want := out.String(), "cove: setup permission denied\nfix: cove setup\n"; got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
}
