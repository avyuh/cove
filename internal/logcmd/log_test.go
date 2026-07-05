package logcmd

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestScanFiltersDenyOnlyAndHost(t *testing.T) {
	input := strings.NewReader(`
{"ts":"2026-07-05T00:00:00Z","session":"a","policy":"allow","host":"pypi.org","port":443,"bytes_up":1,"bytes_down":2,"dur_ms":3}
{"ts":"2026-07-05T00:00:00Z","session":"b","policy":"deny","host":"evil.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}
{"ts":"2026-07-05T00:00:00Z","session":"c","policy":"deny","host":"other.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}
`)
	out := captureStdout(t, func() {
		if err := scan(input, Opts{DenyOnly: true, Host: "evil.example.com"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"host":"evil.example.com"`) {
		t.Fatalf("filtered output missing evil record: %q", out)
	}
	if strings.Contains(out, "pypi.org") || strings.Contains(out, "other.example.com") {
		t.Fatalf("filtered output included non-matching records: %q", out)
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	fn()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}
