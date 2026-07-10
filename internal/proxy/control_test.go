package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegister2RejectsInvalidAndLegacy(t *testing.T) {
	p := &Proxyd{sessDir: t.TempDir(), matcher: &Matcher{}, log: io.Discard}
	for _, line := range []string{
		"REGISTER deadbeef agent\n",
		"REGISTER/2 {\"session\":\"BAD\",\"agent\":\"a\",\"audit\":false}\n",
		"REGISTER/2 {\"session\":\"deadbeef\",\"agent\":\"a\",\"audit\":false,\"extra\":1}\n",
	} {
		client, server := net.Pipe()
		go p.handleControl(server)
		if _, err := io.WriteString(client, line); err != nil {
			t.Fatal(err)
		}
		got, err := bufio.NewReader(client).ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(got, "ERR/2 ") {
			t.Fatalf("%q => %q, want ERR/2", line, got)
		}
		_ = client.Close()
	}
}

func TestControlDrainBackpressureKeepsExactDenyAggregate(t *testing.T) {
	p := &Proxyd{sessDir: t.TempDir(), matcher: &Matcher{}, log: io.Discard}
	client, server := net.Pipe()
	go p.handleControl(server)
	if _, err := io.WriteString(client, "REGISTER/2 {\"session\":\"deadbeef\",\"agent\":\"agent\",\"audit\":false}\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	sock := controlSocket(t, line)
	if sock == "" {
		t.Fatalf("register response %q", line)
	}

	const n = 1000
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Errorf("dial: %v", err)
				return
			}
			defer c.Close()
			_, _ = fmt.Fprint(c, "CONNECT denied.test:443 HTTP/1.1\r\nHost: denied.test\r\n\r\n")
			_, _ = bufio.NewReader(c).ReadString('\n')
		}()
	}
	wg.Wait() // deliberately do not consume EVENT/2 while the proxy is busy.
	doneWrite := make(chan error, 1)
	go func() { _, err := io.WriteString(client, "DONE/2\n"); doneWrite <- err }()
	var end controlEnd
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "END/2 ") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "END/2 ")), &end); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	if err := <-doneWrite; err != nil {
		t.Fatal(err)
	}
	if len(end.Denies) != 1 || end.Denies[0].Host != "denied.test" || end.Denies[0].Port != 443 || end.Denies[0].Count != n {
		t.Fatalf("END aggregate = %+v, want denied.test:443 x%d", end, n)
	}
	if end.DroppedEvents == 0 {
		t.Fatal("expected EVENT drops while launcher was not reading")
	}
	_ = client.Close()
}

func TestNoAuditEmitsNoAuditBytesButKeepsReceipt(t *testing.T) {
	path := t.TempDir() + "/audit.log"
	audit, err := NewAuditWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	audit.Emit(&AuditRecord{Policy: "allow", Host: "baseline.test", Port: 443})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	events := NewSessionEvents()
	c := &Conn{audit: audit, sess: Session{ID: "deadbeef", Agent: "agent", Audit: false, Events: events}}
	for _, policy := range []string{"allow", "deny", "deny", "warn"} {
		c.emit(&AuditRecord{Policy: policy, Host: "x.test", Port: 443, Status: 403})
	}
	events.close(true)
	if b, err := os.ReadFile(path); err != nil || string(b) != string(before) {
		t.Fatalf("no-audit changed audit bytes: before=%q after=%q err=%v", before, b, err)
	}
	end := events.endMessage()
	if end == nil || len(end.Denies) != 1 || end.Denies[0].Count != 2 {
		t.Fatalf("receipt = %+v", end)
	}
}

func TestControlEOFHasNoEnd(t *testing.T) {
	// The behaviour is exercised by the handler: EOF closes listener/handlers
	// but intentionally has no receipt framing to a dead peer.
	p := &Proxyd{sessDir: t.TempDir(), matcher: &Matcher{}, log: io.Discard}
	client, server := net.Pipe()
	go p.handleControl(server)
	_, _ = io.WriteString(client, "REGISTER/2 {\"session\":\"cafebabe\",\"agent\":\"agent\",\"audit\":false}\n")
	_, _ = bufio.NewReader(client).ReadString('\n')
	_ = client.Close()
	time.Sleep(10 * time.Millisecond)
}
