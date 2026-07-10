package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"cove/internal/config"
)

func TestAcquireProxydLockSingletonAndReclaim(t *testing.T) {
	dir := t.TempDir()
	lock, held, err := acquireProxydLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("first lock acquisition was not held")
	}
	second, held, err := acquireProxydLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if held {
		_ = second.Close()
		t.Fatal("second lock acquisition unexpectedly succeeded")
	}
	if second != nil {
		t.Fatal("second lock returned a file when not held")
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	reclaimed, held, err := acquireProxydLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("lock was not reclaimable after close")
	}
	_ = reclaimed.Close()
}

func TestSweepSessionSocketsRemovesOnlyDeadSockets(t *testing.T) {
	dir := t.TempDir()
	stalePath := filepath.Join(dir, "stale.sock")
	stale, err := net.Listen("unix", stalePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := stale.Close(); err != nil {
		t.Fatal(err)
	}

	livePath := filepath.Join(dir, "live.sock")
	live, err := net.Listen("unix", livePath)
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		c, err := live.Accept()
		if err == nil {
			_ = c.Close()
		}
	}()

	if err := sweepSessionSockets(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stalePath); !os.IsNotExist(err) {
		t.Fatalf("stale socket still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(livePath); err != nil {
		t.Fatalf("live socket was removed: %v", err)
	}
	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("live socket probe was not accepted")
	}
}

func TestRegisterUnlinksSessionSocketOnControlClose(t *testing.T) {
	p := &Proxyd{sessDir: t.TempDir(), log: io.Discard}
	client, server := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.register(server, Session{ID: "abc12345", Agent: "agent"})
	}()
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	path := controlSocket(t, line)
	if path == "" {
		t.Fatalf("register response = %q, want OK", line)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("session socket missing after register: %v", err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("register did not return after control close")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("session socket still exists after control close or stat failed: %v", err)
	}
}

func TestSessionSocketHandlesParallelConnectsAndAuditsOneSession(t *testing.T) {
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(c, buf); err != nil {
					return
				}
				_, _ = c.Write([]byte("pong"))
			}(c)
		}
	}()
	_, portText, err := net.SplitHostPort(upstream.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadBytes([]byte(`allow = ["127.0.0.1:` + portText + `"]`))
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := NewAuditWriter(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	p := &Proxyd{
		sessDir: t.TempDir(),
		matcher: NewMatcher(cfg),
		audit:   audit,
		log:     io.Discard,
	}
	control, server := net.Pipe()
	registerDone := make(chan struct{})
	go func() {
		defer close(registerDone)
		p.register(server, Session{ID: "feedbeef", Agent: "agent", Audit: true})
	}()
	line, err := bufio.NewReader(control).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	sock := controlSocket(t, line)
	if sock == "" {
		t.Fatalf("register response = %q, want OK", line)
	}

	const n = 40
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- connectOnce(sock, portText)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = control.Close()
	select {
	case <-registerDone:
	case <-time.After(time.Second):
		t.Fatal("register did not return after parallel requests")
	}
	var recs []AuditRecord
	for i := 0; i < 100; i++ {
		recs = readAuditRecords(t, auditPath)
		if len(recs) == n {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = audit.Close()
	if len(recs) != n {
		t.Fatalf("audit records = %d, want %d", len(recs), n)
	}
	for _, rec := range recs {
		if rec.Session != "feedbeef" || rec.Policy != "allow" || rec.BytesUp == 0 || rec.BytesDn == 0 {
			t.Fatalf("unexpected audit record: %+v", rec)
		}
	}
	_ = upstream.Close()
	<-upstreamDone
}

func controlSocket(t *testing.T, line string) string {
	t.Helper()
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "OK/2 ") {
		return ""
	}
	var ok controlOK
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "OK/2 ")), &ok); err != nil {
		t.Fatal(err)
	}
	return ok.Socket
}

func connectOnce(sock, portText string) error {
	c, err := net.DialTimeout("unix", sock, time.Second)
	if err != nil {
		return err
	}
	defer c.Close()
	if _, err := fmt.Fprintf(c, "CONNECT 127.0.0.1:%s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\nping", portText); err != nil {
		return err
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimRight(line, "\r\n") != "HTTP/1.1 200 Connection Established" {
		return fmt.Errorf("status = %q", line)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			return err
		}
		if h == "\r\n" {
			break
		}
	}
	body := make([]byte, 4)
	if _, err := io.ReadFull(br, body); err != nil {
		return err
	}
	if string(body) != "pong" {
		return fmt.Errorf("body = %q, want pong", body)
	}
	return nil
}
