package logcmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cove/internal/clierr"
	"cove/internal/proxy"
)

func TestRawGoldenStaysByteIdenticalForFiltersAndJSON(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "contract_audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Opts{
		{}, {DenyOnly: true}, {Session: "1a2b3c4d"}, {Host: "api.anthropic.com"},
		{JSON: true, OutputTTY: true}, {JSON: true, DenyOnly: true, OutputTTY: true},
	} {
		var got, want bytes.Buffer
		if err := scanTo(bytes.NewReader(fixture), opts, &got); err != nil {
			t.Fatal(err)
		}
		for _, line := range bytes.SplitAfter(fixture, []byte{'\n'}) {
			if rec, ok := accepts(line, opts); ok {
				_ = rec
				want.Write(line)
			}
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("raw bytes changed for %+v\ngot:  %q\nwant: %q", opts, got.Bytes(), want.Bytes())
		}
		if bytes.Contains(got.Bytes(), []byte("\x1b[")) {
			t.Fatalf("raw output contained ANSI: %q", got.Bytes())
		}
	}
}

func TestRotatedRawScanMalformedAndFutureFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	old := []byte(`{"ts":"2026-07-05T00:00:00Z","session":"old","policy":"deny","host":"old.example","port":443,"future":{"order":[2,1]}}` + "\n")
	new := []byte(`{"ts":"2026-07-06T00:00:00Z","session":"new","policy":"allow","host":"new.example","port":443,"future_field":"untouched"}` + "\n")
	if err := os.WriteFile(path+".1", append(append([]byte{}, old...), []byte("not-json\n{\"ts\":")...), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, new, 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := scanRotated(path, Opts{}, &out); err != nil {
		t.Fatal(err)
	}
	if got, want := out.Bytes(), append(old, new...); !bytes.Equal(got, want) {
		t.Fatalf("rotated raw bytes = %q, want %q", got, want)
	}
}

func TestTTYWidthsAndColor(t *testing.T) {
	rec := mustRecord(t, `{"ts":"2026-07-05T14:02:11Z","session":"a","policy":"deny","host":"very-long-host.example.com","method":"POST","path":"/a/very/long/path/that/is/the/only/truncatable/column","status":403,"bytes_up":1024,"bytes_down":2048,"dur_ms":420,"reason":"host_policy"}`)
	for _, width := range []int{40, 80, 160} {
		var plain, colored bytes.Buffer
		records := []proxy.AuditRecord{rec.proxyRecord()}
		renderTable(&plain, records, width, false)
		renderTable(&colored, records, width, true)
		if strings.Contains(plain.String(), "\x1b[") {
			t.Fatalf("width %d plain has ANSI: %q", width, plain.String())
		}
		if !strings.Contains(colored.String(), "\x1b[31mblocked") {
			t.Fatalf("width %d colored lacks blocked color: %q", width, colored.String())
		}
		if !strings.Contains(plain.String(), "very-long-host.example.com") || !strings.Contains(plain.String(), "host policy") {
			t.Fatalf("width %d truncated host or reason: %q", width, plain.String())
		}
		if width == 40 && !strings.Contains(plain.String(), "…") {
			t.Fatalf("narrow table did not truncate PATH: %q", plain.String())
		}
	}
}

// Keep the literal fixture local while using the production parser, which is
// also the guarantee that future JSON fields do not affect raw copying.
type auditRecord struct{ line []byte }

func mustRecord(t *testing.T, line string) auditRecord   { t.Helper(); return auditRecord{[]byte(line)} }
func (a auditRecord) proxyRecord() (r proxy.AuditRecord) { r, _ = accepts(a.line, Opts{}); return }

func TestSinceValidationAndAuditOff(t *testing.T) {
	now := time.Date(2026, 7, 6, 0, 0, 0, 0, time.UTC)
	if _, err := parseSince("0s", now); err == nil {
		t.Fatal("zero duration accepted")
	}
	if _, err := parseSince("not-a-time", now); err == nil {
		t.Fatal("invalid since accepted")
	}
	if _, err := parseSince("2026-07-07T00:00:00Z", now); err == nil {
		t.Fatal("future since accepted")
	}
	got, err := parseSince("2h", now)
	if err != nil || !got.Equal(now.Add(-2*time.Hour)) {
		t.Fatalf("duration = %v, %v", got, err)
	}
	var tty, raw bytes.Buffer
	if err := scanRotated(filepath.Join(t.TempDir(), "audit.log"), Opts{Session: "deadbeef", auditOff: true, OutputTTY: true}, &tty); err != nil {
		t.Fatal(err)
	}
	if err := scanRotated(filepath.Join(t.TempDir(), "audit.log"), Opts{Session: "deadbeef", auditOff: true}, &raw); err != nil {
		t.Fatal(err)
	}
	if got := tty.String(); got != "session deadbeef: audit was off; no records were stored\n" {
		t.Fatalf("audit-off tty = %q", got)
	}
	if raw.Len() != 0 {
		t.Fatalf("audit-off raw = %q", raw.Bytes())
	}
}

func TestRunRejectsInvalidAndFutureSinceWithUsage(t *testing.T) {
	for _, value := range []string{"bogus", "2999-01-01T00:00:00Z"} {
		err := Run([]string{"--since", value})
		var cli *clierr.Error
		if !errors.As(err, &cli) || cli.Code != clierr.EXUsage {
			t.Fatalf("--since %q error = %#v, want EX_USAGE", value, err)
		}
	}
}
