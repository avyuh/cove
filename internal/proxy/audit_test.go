package proxy

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditRecordJSONShape(t *testing.T) {
	rec := AuditRecord{
		TS:      time.Date(2026, 7, 5, 14, 3, 22, 145000000, time.UTC),
		Session: "1a2b3c4d",
		Policy:  "deny",
		Host:    "evil.example.com",
		Port:    443,
		Method:  "-",
		Path:    "-",
		Status:  403,
		BytesUp: 12,
		BytesDn: 34,
		DurMS:   56,
		Agent:   "agent",
	}
	b, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"ts", "session", "policy", "host", "port", "method", "path", "status", "bytes_up", "bytes_down", "dur_ms", "agent"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing JSON field %q in %s", key, b)
		}
	}
}

func TestAuditWriterRotatesAt64MiBAndKeepsFive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	for i := 1; i <= 5; i++ {
		if err := os.WriteFile(path+"."+itoaAudit(i), []byte{byte('0' + i)}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate((64 << 20) + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	a, err := NewAuditWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	a.Emit(&AuditRecord{TS: time.Now().UTC(), Session: "s", Policy: "deny", Host: "h", Port: 443, Status: 403})
	for _, name := range []string{"audit.log", "audit.log.1", "audit.log.2", "audit.log.3", "audit.log.4", "audit.log.5"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing after rotation: %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "audit.log.6")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("audit.log.6 exists or stat failed: %v", err)
	}
}

func TestCountingReadCloserCountsAndClosesOnce(t *testing.T) {
	base := &panicOnDoubleCloseReadCloser{r: strings.NewReader("abcdef")}
	var counts []int64
	c := &countingReadCloser{
		rc: base,
		onClose: func(n int64) {
			counts = append(counts, n)
		},
	}
	buf := make([]byte, 4)
	if n, err := c.Read(buf); n != 4 || err != nil {
		t.Fatalf("first read n=%d err=%v", n, err)
	}
	if n, err := c.Read(buf); n != 2 || err != nil {
		t.Fatalf("second read n=%d err=%v", n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if base.closes != 1 {
		t.Fatalf("underlying closes = %d, want 1", base.closes)
	}
	if len(counts) != 1 || counts[0] != 6 {
		t.Fatalf("counts = %v, want [6]", counts)
	}
}

func TestInjectAuditFinalizesAtBodyClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	a, err := NewAuditWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	c := &Conn{
		sess:    Session{ID: "abc12345", Agent: "claude"},
		audit:   a,
		started: time.Now().Add(-time.Second),
	}
	resp := &http.Response{
		StatusCode: 200,
		Request:    mustRequest(t, "POST", "https://api.test/v1/messages?beta=true"),
	}
	rec := c.newInjectRecord(Target{Host: "api.test", Port: 443}, resp, 7)
	if rec.Status != 200 || rec.Method != "POST" || rec.Path != "/v1/messages?beta=true" {
		t.Fatalf("header-stage record missing status/method/path: %+v", rec)
	}
	if data, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if len(data) != 0 {
		t.Fatalf("record emitted before body close: %q", data)
	}
	body := &countingReadCloser{rc: io.NopCloser(strings.NewReader("chunk-one\nchunk-two\n")), onClose: func(n int64) {
		rec.BytesDn = n
		rec.DurMS = time.Since(c.started).Milliseconds()
		c.emit(rec)
	}}
	if _, err := io.ReadAll(body); err != nil {
		t.Fatal(err)
	}
	if err := body.Close(); err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	recs := readAuditRecords(t, path)
	if len(recs) != 1 {
		t.Fatalf("audit records = %d, want 1", len(recs))
	}
	got := recs[0]
	if got.Policy != "inject" || got.Status != 200 || got.BytesUp != 7 || got.BytesDn == 0 || got.DurMS == 0 {
		t.Fatalf("unexpected finalized inject record: %+v", got)
	}
}

type panicOnDoubleCloseReadCloser struct {
	r      *strings.Reader
	closes int
}

func (p *panicOnDoubleCloseReadCloser) Read(b []byte) (int, error) {
	return p.r.Read(b)
}

func (p *panicOnDoubleCloseReadCloser) Close() error {
	p.closes++
	if p.closes > 1 {
		panic("double close")
	}
	return nil
}

var _ io.ReadCloser = (*panicOnDoubleCloseReadCloser)(nil)

func mustRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return req
}
