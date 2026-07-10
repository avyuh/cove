package launcher

import (
	"bytes"
	"testing"

	"cove/internal/clierr"
)

func TestExitErrorAdapterKeepsCodeAndRendering(t *testing.T) {
	var out bytes.Buffer
	code := clierr.Print(&out, ExitError{Code: 127, Msg: "agent not found"}.CLIError())
	if code != 127 {
		t.Fatalf("code = %d", code)
	}
	if got, want := out.String(), "cove: agent not found\nfix: cove status\n"; got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
}
