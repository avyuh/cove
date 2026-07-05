package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cove/internal/config"
)

func TestConnRejectsMalformedAndNonConnect(t *testing.T) {
	tests := []struct {
		name string
		req  string
		want string
	}{
		{"malformed", "\r\n", "HTTP/1.1 400 Bad Request"},
		{"non connect", "GET http://example.com/ HTTP/1.1\r\n\r\n", "HTTP/1.1 405 Method Not Allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line := runConnRequest(t, nil, tt.req, nil)
			if line != tt.want {
				t.Fatalf("status = %q, want %q", line, tt.want)
			}
		})
	}
}

func TestConnRejectsOffAllowlistBeforeResolve(t *testing.T) {
	var lookups atomic.Int32
	p := &Proxyd{
		log: io.Discard,
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			lookups.Add(1)
			return nil, fmt.Errorf("resolver should not be called")
		},
	}
	line := runConnRequest(t, p, "CONNECT denied.example.com:443 HTTP/1.1\r\nHost: denied.example.com\r\n\r\n", nil)
	if line != "HTTP/1.1 403 Forbidden" {
		t.Fatalf("status = %q, want 403", line)
	}
	if got := lookups.Load(); got != 0 {
		t.Fatalf("resolver calls = %d, want 0", got)
	}
}

func TestConnAllowOpaqueSpliceAuditsAtClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		time.Sleep(2 * time.Millisecond)
		_, _ = c.Write([]byte("pong"))
	}()

	_, portText, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadBytes([]byte(`allow = ["127.0.0.1:` + portText + `"]`))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	audit, err := NewAuditWriter(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	client, server := net.Pipe()
	p := &Proxyd{log: io.Discard}
	conn := &Conn{
		raw:     server,
		br:      bufio.NewReader(server),
		sess:    Session{ID: "abc12345", Agent: "agent"},
		proxy:   p,
		matcher: NewMatcher(cfg),
		audit:   audit,
	}
	handled := make(chan struct{})
	go func() {
		defer close(handled)
		conn.handle()
	}()
	fmt.Fprintf(client, "CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nping", portText)
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(line, "\r\n") != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("status = %q", line)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if h == "\r\n" {
			break
		}
	}
	body := make([]byte, 4)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatal(err)
	}
	if string(body) != "pong" {
		t.Fatalf("body = %q, want pong", body)
	}
	_ = client.Close()
	<-handled
	<-done
	_ = audit.Close()
	recs := readAuditRecords(t, filepath.Join(dir, "audit.log"))
	if len(recs) != 1 {
		t.Fatalf("audit records = %d, want 1", len(recs))
	}
	rec := recs[0]
	if rec.Policy != "allow" || rec.Host != "127.0.0.1" || rec.BytesUp == 0 || rec.BytesDn == 0 || rec.DurMS == 0 {
		t.Fatalf("unexpected audit record: %+v", rec)
	}
}

func TestParseTargetRejectsBadConnectTargets(t *testing.T) {
	for _, target := range []string{"example.com", "example.com:notaport", "example.com:0", "example.com:70000"} {
		t.Run(target, func(t *testing.T) {
			if _, err := parseTarget(target); err == nil {
				t.Fatalf("expected parseTarget(%q) to fail", target)
			}
		})
	}
}

func runConnRequest(t *testing.T, p *Proxyd, req string, cfg *config.Config) string {
	t.Helper()
	if cfg == nil {
		var err error
		cfg, err = config.LoadBytes([]byte(`allow = []`))
		if err != nil {
			t.Fatal(err)
		}
	}
	if p == nil {
		p = &Proxyd{log: io.Discard}
	}
	client, server := net.Pipe()
	defer client.Close()
	conn := &Conn{
		raw:     server,
		br:      bufio.NewReader(server),
		sess:    Session{ID: "abc12345", Agent: "agent"},
		proxy:   p,
		matcher: NewMatcher(cfg),
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn.handle()
	}()
	if _, err := io.WriteString(client, req); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	<-done
	return strings.TrimRight(line, "\r\n")
}

func readAuditRecords(t *testing.T, path string) []AuditRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var recs []AuditRecord
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var rec AuditRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		recs = append(recs, rec)
	}
	return recs
}
