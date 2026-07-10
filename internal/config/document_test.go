package config

import (
	"bytes"
	"errors"
	"testing"

	"cove/internal/clierr"
)

func rendered(t *testing.T, data string) (int, string) {
	t.Helper()
	_, err := DecodeDocument("/tmp/cove/config.toml", []byte(data))
	if err == nil {
		t.Fatal("DecodeDocument succeeded")
	}
	var ce *clierr.Error
	if !errors.As(err, &ce) {
		t.Fatalf("error type = %T, want *clierr.Error", err)
	}
	var out bytes.Buffer
	return clierr.Print(&out, err), out.String()
}

func TestDecodeDocumentSyntaxErrorThreeBeats(t *testing.T) {
	code, got := rendered(t, "[options\n")
	if code != clierr.EXConfig {
		t.Fatalf("code = %d", code)
	}
	const want = "cove: could not load the policy\nwhere: /tmp/cove/config.toml:2:9 — expected '.' or ']' to end table name, but got '\\n' instead\nfix: cove config edit\n"
	if got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
}

func TestDecodeDocumentWrongTypeThreeBeats(t *testing.T) {
	code, got := rendered(t, "[options]\nproxy_port = \"not-a-number\"\n")
	if code != clierr.EXConfig {
		t.Fatalf("code = %d", code)
	}
	const want = "cove: could not load the policy\nwhere: /tmp/cove/config.toml:2:1 — toml: line 2 (last key \"options.proxy_port\"): incompatible types: TOML value has type string; destination has type integer\nfix: cove config edit\n"
	if got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
}

func TestDecodeDocumentHostConflictThreeBeats(t *testing.T) {
	code, got := rendered(t, "allow = [\"example.com\"]\n\n[[inject]]\nhost = \"example.com\"\nheader_name = \"Authorization\"\nheader_template = \"Bearer {secret}\"\nsecret = \"file:/tmp/token\"\n")
	if code != clierr.EXConfig {
		t.Fatalf("code = %d", code)
	}
	const want = "cove: could not load the policy\nwhere: /tmp/cove/config.toml:4:1 — host \"example.com\" appears in both allow and inject\nfix: cove config edit\n"
	if got != want {
		t.Fatalf("render = %q, want %q", got, want)
	}
}
