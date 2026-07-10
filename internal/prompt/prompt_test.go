package prompt

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

type eofReader struct {
	r   io.Reader
	eof bool
}

func (r *eofReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if errors.Is(err, io.EOF) {
		r.eof = true
	}
	return n, err
}

func TestReadSecretStdinReadsEOFAndTrimsWhitespace(t *testing.T) {
	r := &eofReader{r: strings.NewReader(" \t\n\u2003secret-value\u2003\r\n")}
	got, err := ReadSecretStdin(r)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "secret-value" {
		t.Fatalf("secret = %q, want trimmed value", got)
	}
	if !r.eof {
		t.Fatal("stdin reader was not consumed to EOF")
	}
}

func TestReadSecretStdinEnforcesOneMiBCap(t *testing.T) {
	_, err := ReadSecretStdin(bytes.NewReader(bytes.Repeat([]byte{'x'}, maxSecret+1)))
	if err == nil || !strings.Contains(err.Error(), "1 MiB") {
		t.Fatalf("expected 1 MiB limit error, got %v", err)
	}
}

func TestReadSecretStdinRejectsEmptyAndNULWithoutEchoing(t *testing.T) {
	for _, input := range [][]byte{[]byte(" \n\t\u2003"), []byte("not-for-output\x00")} {
		_, err := ReadSecretStdin(bytes.NewReader(input))
		if err == nil {
			t.Fatalf("ReadSecretStdin(%q) succeeded", input)
		}
		if strings.Contains(err.Error(), "not-for-output") {
			t.Fatalf("secret was echoed in error: %q", err)
		}
	}
}

// ReadPassword opens /dev/tty and uses term.ReadPassword. A portable stdlib
// openpty seam is not available on all supported platforms; these tests cover
// the explicit non-TTY stdin seam instead, without adding a PTY dependency.
