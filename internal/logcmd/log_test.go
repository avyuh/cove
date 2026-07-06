package logcmd

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const filterFixture = `
{"ts":"2026-07-05T00:00:00Z","session":"a","policy":"allow","host":"pypi.org","port":443,"bytes_up":1,"bytes_down":2,"dur_ms":3}
{"ts":"2026-07-05T00:00:00Z","session":"b","policy":"deny","host":"evil.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}
{"ts":"2026-07-05T00:00:00Z","session":"a","policy":"deny","host":"evil.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}
{"ts":"2026-07-05T00:00:00Z","session":"c","policy":"allow","host":"evil.example.com","port":443,"bytes_up":4,"bytes_down":5,"dur_ms":6}
not-json
{"ts":
`

func TestScanFiltersTable(t *testing.T) {
	tests := []struct {
		name     string
		opts     Opts
		want     []string
		notWant  []string
		lineWant int
	}{
		{
			name:     "default valid records",
			opts:     Opts{},
			want:     []string{`"host":"pypi.org"`, `"session":"b"`, `"session":"a"`, `"session":"c"`},
			notWant:  []string{"not-json"},
			lineWant: 4,
		},
		{
			name:     "deny only",
			opts:     Opts{DenyOnly: true},
			want:     []string{`"session":"b"`, `"session":"a"`},
			notWant:  []string{`"policy":"allow"`, "not-json"},
			lineWant: 2,
		},
		{
			name:     "session",
			opts:     Opts{Session: "a"},
			want:     []string{`"host":"pypi.org"`, `"policy":"deny"`},
			notWant:  []string{`"session":"b"`, `"session":"c"`},
			lineWant: 2,
		},
		{
			name:     "host",
			opts:     Opts{Host: "evil.example.com"},
			want:     []string{`"session":"b"`, `"session":"a"`, `"session":"c"`},
			notWant:  []string{"pypi.org"},
			lineWant: 3,
		},
		{
			name:     "composed",
			opts:     Opts{DenyOnly: true, Session: "a", Host: "evil.example.com"},
			want:     []string{`"session":"a"`, `"policy":"deny"`, `"host":"evil.example.com"`},
			notWant:  []string{`"session":"b"`, `"pypi.org"`, `"policy":"allow"`},
			lineWant: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := scanTo(strings.NewReader(filterFixture), tt.opts, &out); err != nil {
				t.Fatal(err)
			}
			got := out.String()
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("output missing %q: %q", want, got)
				}
			}
			for _, notWant := range tt.notWant {
				if strings.Contains(got, notWant) {
					t.Fatalf("output included %q: %q", notWant, got)
				}
			}
			if lines := strings.Count(got, "\n"); lines != tt.lineWant {
				t.Fatalf("line count = %d, want %d: %q", lines, tt.lineWant, got)
			}
		})
	}
}

func TestPrintIfMatchFiltersAndIgnoresMalformed(t *testing.T) {
	line := []byte(`{"ts":"2026-07-05T00:00:00Z","session":"a","policy":"deny","host":"evil.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}` + "\n")
	tests := []struct {
		name string
		line []byte
		opts Opts
		want bool
	}{
		{name: "match", line: line, opts: Opts{DenyOnly: true, Session: "a", Host: "evil.example.com"}, want: true},
		{name: "deny only mismatch", line: bytes.ReplaceAll(line, []byte(`"policy":"deny"`), []byte(`"policy":"allow"`)), opts: Opts{DenyOnly: true}, want: false},
		{name: "session mismatch", line: line, opts: Opts{Session: "b"}, want: false},
		{name: "host mismatch", line: line, opts: Opts{Host: "other.example.com"}, want: false},
		{name: "malformed", line: []byte(`{"ts":`), opts: Opts{}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			got := printIfMatchTo(&out, tt.line, tt.opts)
			if got != tt.want {
				t.Fatalf("match = %v, want %v", got, tt.want)
			}
			if tt.want && out.String() != string(tt.line) {
				t.Fatalf("output = %q, want %q", out.String(), string(tt.line))
			}
			if !tt.want && out.Len() != 0 {
				t.Fatalf("unexpected output: %q", out.String())
			}
		})
	}
}

func TestFollowPicksUpAppendsRotationAndTruncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out := &safeBuffer{}
	errCh := make(chan error, 1)
	go func() {
		errCh <- followContext(ctx, path, Opts{DenyOnly: true}, out, 10*time.Millisecond)
	}()

	appendFile(t, path, `{"ts":"2026-07-05T00:00:00Z","session":"a","policy":"allow","host":"pypi.org","port":443,"bytes_up":1,"bytes_down":2,"dur_ms":3}`+"\n")
	time.Sleep(40 * time.Millisecond)
	if strings.Contains(out.String(), "pypi.org") {
		t.Fatalf("deny-only follow printed allow record: %q", out.String())
	}

	partial := `{"ts":"2026-07-05T00:00:00Z","session":"b","policy":"deny","host":"partial.example.com"`
	appendFile(t, path, partial)
	time.Sleep(40 * time.Millisecond)
	if strings.Contains(out.String(), "partial.example.com") {
		t.Fatalf("follow printed a partial line: %q", out.String())
	}
	appendFile(t, path, `,"port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}`+"\n")
	waitContains(t, out, "partial.example.com")

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"ts":"2026-07-05T00:00:00Z","session":"c","policy":"deny","host":"rotated.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}`+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	waitContains(t, out, "rotated.example.com")

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(40 * time.Millisecond)
	appendFile(t, path, `{"ts":"2026-07-05T00:00:00Z","session":"d","policy":"deny","host":"truncated.example.com","port":443,"status":403,"bytes_up":0,"bytes_down":0,"dur_ms":0}`+"\n")
	waitContains(t, out, "truncated.example.com")
	if got := strings.Count(out.String(), "partial.example.com"); got != 1 {
		t.Fatalf("partial record count = %d, want 1: %q", got, out.String())
	}

	cancel()
	if err := <-errCh; err != context.Canceled {
		t.Fatalf("follow err = %v, want context.Canceled", err)
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
	defer func() { os.Stdout = old }()
	fn()
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	return buf.String()
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func appendFile(t *testing.T, path, data string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(data); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func waitContains(t *testing.T, out *safeBuffer, needle string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), needle) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in %q", needle, out.String())
}
