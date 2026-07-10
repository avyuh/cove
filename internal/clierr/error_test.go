package clierr

import (
	"bytes"
	"testing"
)

func TestPrintThreeBeatsAndEscapesControls(t *testing.T) {
	var out bytes.Buffer
	code := Print(&out, Wrap(EXConfig, "could not load\nthe policy", &Location{Path: "config\t.toml", Line: 4, Column: 2, Detail: "bad\rvalue"}, "cove config edit", nil))
	if code != EXConfig {
		t.Fatalf("code = %d, want %d", code, EXConfig)
	}
	const want = "cove: could not load\\nthe policy\nwhere: config\\t.toml:4:2 — bad\\rvalue\nfix: cove config edit\n"
	if got := out.String(); got != want {
		t.Fatalf("Print() = %q, want %q", got, want)
	}
}

func TestPrintWithoutLocationHasTwoBeats(t *testing.T) {
	var out bytes.Buffer
	Print(&out, Wrap(EXNoPerm, "permission denied", nil, "cove setup", nil))
	const want = "cove: permission denied\nfix: cove setup\n"
	if got := out.String(); got != want {
		t.Fatalf("Print() = %q, want %q", got, want)
	}
	if bytes.Contains(out.Bytes(), []byte("\x1b[")) {
		t.Fatal("non-TTY renderer emitted ANSI color")
	}
}
