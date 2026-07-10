package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cove/internal/box"
	"cove/internal/config"
	"cove/internal/secret"

	"golang.org/x/net/http2"
)

func TestInjectStripThenInjectH2H1InertAndStreaming(t *testing.T) {
	const host = "api.test"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	rootPath := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(rootPath, upstreamPEM, 0644); err != nil {
		t.Fatal(err)
	}
	emptyCertDir := filepath.Join(t.TempDir(), "empty-certs")
	if err := os.Mkdir(emptyCertDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", rootPath)
	t.Setenv("SSL_CERT_DIR", emptyCertDir)

	t.Run("strip inject over h2 and h1", func(t *testing.T) {
		for _, leg := range []string{"h2", "http/1.1"} {
			t.Run(leg, func(t *testing.T) {
				var captured atomic.Value
				upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					captured.Store(map[string]string{
						"authorization": r.Header.Get("Authorization"),
						"x-api-key":     r.Header.Get("x-api-key"),
						"method":        r.Method,
						"path":          r.URL.RequestURI(),
					})
					_ = json.NewEncoder(w).Encode(map[string]string{"ok": "true"})
				}))
				defer upstream.Close()

				port := serverPort(t, upstream.URL)
				secretPath := writeSecret(t, "real-token")
				auditPath := filepath.Join(t.TempDir(), "audit.log")
				audit, err := NewAuditWriter(auditPath)
				if err != nil {
					t.Fatal(err)
				}
				resp, body, cleanup := requestThroughInject(t, injectRequest{
					Leg:        leg,
					Host:       host,
					Port:       port,
					Path:       "/v1/messages?beta=true",
					Body:       "hello",
					SecretRef:  "file:" + secretPath,
					CoveCA:     coveCA,
					CoveCAPEM:  covePEM,
					Headers:    http.Header{"x-api-key": []string{"dummy-key"}},
					ProxyAudit: audit,
				})
				cleanup()
				_ = audit.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("status = %d body=%q", resp.StatusCode, body)
				}
				gotAny := captured.Load()
				if gotAny == nil {
					t.Fatal("upstream did not receive request")
				}
				got := gotAny.(map[string]string)
				if got["authorization"] != "Bearer real-token" {
					t.Fatalf("Authorization = %q, want injected Bearer", got["authorization"])
				}
				if got["x-api-key"] != "" {
					t.Fatalf("x-api-key leaked upstream: %q", got["x-api-key"])
				}
				if got["method"] != "POST" || got["path"] != "/v1/messages?beta=true" {
					t.Fatalf("unexpected upstream request: %+v", got)
				}
				recs := readAuditRecords(t, auditPath)
				if len(recs) != 1 {
					t.Fatalf("audit records = %d, want 1", len(recs))
				}
				if recs[0].Policy != "inject" || recs[0].BytesUp != int64(len("hello")) || recs[0].BytesDn == 0 {
					t.Fatalf("unexpected inject audit record: %+v", recs[0])
				}
			})
		}
	})

	t.Run("inert empty secret does not add authorization", func(t *testing.T) {
		var captured atomic.Value
		upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			captured.Store(map[string]string{
				"authorization": r.Header.Get("Authorization"),
				"x-api-key":     r.Header.Get("x-api-key"),
			})
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "ok")
		}))
		defer upstream.Close()
		port := serverPort(t, upstream.URL)
		secretPath := writeSecret(t, "")
		resp, body, cleanup := requestThroughInject(t, injectRequest{
			Leg:       "h2",
			Host:      host,
			Port:      port,
			Path:      "/anonymous",
			SecretRef: "file:" + secretPath,
			CoveCA:    coveCA,
			CoveCAPEM: covePEM,
			Headers:   http.Header{"x-api-key": []string{"dummy-key"}},
		})
		cleanup()
		if resp.StatusCode != http.StatusOK || string(body) != "ok" {
			t.Fatalf("status/body = %d %q, want 200 ok", resp.StatusCode, body)
		}
		got := captured.Load().(map[string]string)
		if got["authorization"] != "" {
			t.Fatalf("Authorization = %q, want absent for inert inject", got["authorization"])
		}
		if got["x-api-key"] != "" {
			t.Fatalf("x-api-key leaked upstream: %q", got["x-api-key"])
		}
	})

	t.Run("h2 streaming flushes incrementally", func(t *testing.T) {
		firstFlushed := make(chan struct{})
		allowSecond := make(chan struct{})
		upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Error("upstream response writer is not a flusher")
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: one\n\n")
			flusher.Flush()
			close(firstFlushed)
			select {
			case <-allowSecond:
			case <-time.After(2 * time.Second):
				t.Error("client did not observe first event before timeout")
				return
			}
			_, _ = io.WriteString(w, "data: two\n\n")
			flusher.Flush()
		}))
		defer upstream.Close()
		port := serverPort(t, upstream.URL)
		secretPath := writeSecret(t, "real-token")
		resp, cleanup := openInjectResponse(t, injectRequest{
			Leg:       "h2",
			Host:      host,
			Port:      port,
			Path:      "/stream",
			SecretRef: "file:" + secretPath,
			CoveCA:    coveCA,
			CoveCAPEM: covePEM,
		})
		defer cleanup()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
		select {
		case <-firstFlushed:
		case <-time.After(500 * time.Millisecond):
			t.Fatal("upstream did not flush first event")
		}
		bodyReader := bufio.NewReader(resp.Body)
		lineCh := make(chan string, 1)
		errCh := make(chan error, 1)
		go func() {
			line, err := bodyReader.ReadString('\n')
			if err != nil {
				errCh <- err
				return
			}
			lineCh <- line
		}()
		select {
		case line := <-lineCh:
			if line != "data: one\n" {
				t.Fatalf("first streamed line = %q", line)
			}
		case err := <-errCh:
			t.Fatalf("read first streamed line: %v", err)
		case <-time.After(500 * time.Millisecond):
			t.Fatal("first streamed event was buffered instead of flushed")
		}
		close(allowSecond)
		rest, err := io.ReadAll(bodyReader)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(rest), "data: two") {
			t.Fatalf("remaining stream = %q, want second event", rest)
		}
	})
}

func TestInjectPolicyFailuresAuditOnceAndDoNotLeakSecret(t *testing.T) {
	const host = "api.test"
	const testSecret = "CARD4-SECRET-MUST-NOT-LEAK"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	rootPath := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(rootPath, upstreamPEM, 0644); err != nil {
		t.Fatal(err)
	}
	emptyCertDir := filepath.Join(t.TempDir(), "empty-certs")
	if err := os.Mkdir(emptyCertDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", rootPath)
	t.Setenv("SSL_CERT_DIR", emptyCertDir)

	for _, leg := range []string{"h2", "http/1.1"} {
		t.Run("deny before dial/"+leg, func(t *testing.T) {
			var hits atomic.Int32
			upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			defer upstream.Close()
			auditPath := filepath.Join(t.TempDir(), "audit.log")
			audit, err := NewAuditWriter(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			cfg := injectConfig(t, host, serverPort(t, upstream.URL), "keyring:unavailable", leg)
			resp, _, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{Leg: leg, Host: host, Port: serverPort(t, upstream.URL), CoveCA: coveCA, CoveCAPEM: covePEM, ProxyAudit: audit})
			cleanup()
			_ = audit.Close()
			if resp.StatusCode != http.StatusBadGateway {
				t.Fatalf("status=%d, want 502", resp.StatusCode)
			}
			if hits.Load() != 0 {
				t.Fatalf("upstream hits=%d, want 0", hits.Load())
			}
			recs := readAuditRecords(t, auditPath)
			if len(recs) != 1 || recs[0].Policy != "deny" || recs[0].Reason != "secret_unavailable" {
				t.Fatalf("records=%+v", recs)
			}
		})
	}

	t.Run("authorized transport failure is inject and secret-free", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		var accepted atomic.Int32
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := listener.Accept()
			if err == nil {
				accepted.Add(1)
				_ = c.Close()
			}
		}()
		auditPath := filepath.Join(t.TempDir(), "audit.log")
		audit, err := NewAuditWriter(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		secretPath := writeSecret(t, testSecret)
		port := listener.Addr().(*net.TCPAddr).Port
		resp, _, cleanup := requestThroughInject(t, injectRequest{Leg: "h2", Host: host, Port: port, SecretRef: "file:" + secretPath, CoveCA: coveCA, CoveCAPEM: covePEM, ProxyAudit: audit, ProxyLog: &stderr})
		cleanup()
		wg.Wait()
		_ = audit.Close()
		if resp.StatusCode != http.StatusBadGateway {
			t.Fatalf("status=%d, want 502", resp.StatusCode)
		}
		if accepted.Load() != 1 {
			t.Fatalf("authorized transport attempts=%d, want 1", accepted.Load())
		}
		recs := readAuditRecords(t, auditPath)
		if len(recs) != 1 || recs[0].Policy != "inject" || recs[0].Reason != "upstream_tls" {
			t.Fatalf("records=%+v", recs)
		}
		data, err := os.ReadFile(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(testSecret)) || bytes.Contains(stderr.Bytes(), []byte(testSecret)) {
			t.Fatal("secret leaked to audit or stderr")
		}
	})
}

func TestSeedInjectStanzasRoundTripToStubUpstreams(t *testing.T) {
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	rootPath := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(rootPath, upstreamPEM, 0644); err != nil {
		t.Fatal(err)
	}
	emptyCertDir := filepath.Join(t.TempDir(), "empty-certs")
	if err := os.Mkdir(emptyCertDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", rootPath)
	t.Setenv("SSL_CERT_DIR", emptyCertDir)

	seed, err := config.LoadBytes([]byte(config.DefaultConfig))
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range seed.Inject {
		st := st
		rule, err := config.ParseRule(st.Host)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(st.Host, func(t *testing.T) {
			secretValue := "seed-secret-" + strings.ReplaceAll(rule.Host, ".", "-")
			var captured atomic.Value
			upstream := newInjectUpstream(t, upstreamCA, rule.Host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				headers := map[string]string{
					"method": r.Method,
					"path":   r.URL.RequestURI(),
					"inject": r.Header.Get(st.HeaderName),
				}
				for _, h := range st.StripHeaders {
					headers["strip:"+strings.ToLower(h)] = r.Header.Get(h)
				}
				captured.Store(headers)
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, "seed-ok")
			}))
			defer upstream.Close()

			st.Host = net.JoinHostPort(rule.Host, strconv.Itoa(serverPort(t, upstream.URL)))
			secretPath := writeSecret(t, secretValue)
			st.Secret = "file:" + secretPath
			cfg := &config.Config{Inject: []config.InjectStanza{st}}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			headers := http.Header{}
			for _, h := range st.StripHeaders {
				headers.Set(h, "client-dummy")
			}
			resp, body, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{
				Leg:       st.ALPN,
				Host:      rule.Host,
				Port:      serverPort(t, upstream.URL),
				Path:      "/seed/check?provider=" + url.QueryEscape(rule.Host),
				Body:      "seed-body",
				CoveCA:    coveCA,
				CoveCAPEM: covePEM,
				Headers:   headers,
			})
			cleanup()
			if resp.StatusCode != http.StatusCreated || string(body) != "seed-ok" {
				t.Fatalf("status/body = %d %q, want 201 seed-ok", resp.StatusCode, body)
			}
			gotAny := captured.Load()
			if gotAny == nil {
				t.Fatal("upstream did not receive request")
			}
			got := gotAny.(map[string]string)
			wantHeader := strings.ReplaceAll(st.HeaderTemplate, "{secret}", secretValue)
			if got["inject"] != wantHeader {
				t.Fatalf("%s = %q, want %q", st.HeaderName, got["inject"], wantHeader)
			}
			for _, h := range st.StripHeaders {
				if got["strip:"+strings.ToLower(h)] != "" {
					t.Fatalf("strip header %s leaked upstream as %q", h, got["strip:"+strings.ToLower(h)])
				}
			}
			if got["method"] != http.MethodPost || !strings.HasPrefix(got["path"], "/seed/check?") {
				t.Fatalf("unexpected upstream request: %+v", got)
			}
		})
	}
}

func TestBufConnDrainsBufferedBytesBeforeRawConn(t *testing.T) {
	rawR, rawW := net.Pipe()
	defer rawR.Close()
	br := bufio.NewReader(rawR)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = rawW.Write([]byte("abcdef"))
		time.Sleep(20 * time.Millisecond)
		_, _ = rawW.Write([]byte("gh"))
		_ = rawW.Close()
	}()
	if _, err := br.Peek(6); err != nil {
		t.Fatal(err)
	}
	wrapped := newBufConn(br, rawR)
	got, err := io.ReadAll(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if string(got) != "abcdefgh" {
		t.Fatalf("read = %q, want buffered bytes before raw bytes", got)
	}
}

func TestBlockingOneShotListenerBlocksUntilConnClose(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	l := newBlockingOneShotListener(server)
	accepted, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		_, err := accepted.Write([]byte("x"))
		writeDone <- err
	}()
	buf := make([]byte, 1)
	if _, err := io.ReadFull(client, buf); err != nil {
		t.Fatal(err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	second := make(chan error, 1)
	go func() {
		_, err := l.Accept()
		second <- err
	}()
	select {
	case err := <-second:
		t.Fatalf("second Accept returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	_ = accepted.Close()
	_ = accepted.Close()
	select {
	case err := <-second:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("second Accept err = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second Accept did not unblock after conn close")
	}
}

func TestReloginWarningIsRateLimitedAndRedacted(t *testing.T) {
	dir := t.TempDir()
	audit, err := NewAuditWriter(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer audit.Close()
	var log bytes.Buffer
	c := &Conn{
		sess:  Session{ID: "abc12345", Agent: "claude"},
		proxy: &Proxyd{log: &log},
		audit: audit,
	}
	c.warnReloginRateLimited("SECRET-TOKEN-VALUE", Target{Host: "api.anthropic.com", Port: 443})
	c.warnReloginRateLimited("SECRET-TOKEN-VALUE", Target{Host: "api.anthropic.com", Port: 443})
	if strings.Count(log.String(), reloginWarning) != 1 {
		t.Fatalf("proxyd warning log = %q, want one warning", log.String())
	}
	if strings.Contains(log.String(), "SECRET-TOKEN-VALUE") {
		t.Fatalf("secret leaked to proxyd log: %q", log.String())
	}
	_ = audit.Close()
	recs := readAuditRecords(t, filepath.Join(dir, "audit.log"))
	if len(recs) != 1 {
		t.Fatalf("warn audit records = %d, want 1", len(recs))
	}
	if recs[0].Policy != "warn" || recs[0].Level != "warn" || recs[0].Message != reloginWarning {
		t.Fatalf("unexpected warn audit record: %+v", recs[0])
	}
	if strings.Contains(recs[0].Message, "SECRET-TOKEN-VALUE") {
		t.Fatalf("secret leaked to warn audit: %+v", recs[0])
	}
}

func TestInjectOAuthRefresh401PassesThroughAndWarns(t *testing.T) {
	const host = "api.test"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	rootPath := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(rootPath, upstreamPEM, 0644); err != nil {
		t.Fatal(err)
	}
	emptyCertDir := filepath.Join(t.TempDir(), "empty-certs")
	if err := os.Mkdir(emptyCertDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", rootPath)
	t.Setenv("SSL_CERT_DIR", emptyCertDir)

	upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "expired token")
	}))
	defer upstream.Close()
	secretPath := writeSecret(t, "expired-oauth-token")
	cfg := injectConfig(t, host, serverPort(t, upstream.URL), "file:"+secretPath, "http/1.1")
	cfg.Inject[0].Mode = "oauth-refresh"
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := NewAuditWriter(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	var log bytes.Buffer
	resp, body, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{
		Leg:        "http/1.1",
		Host:       host,
		Port:       serverPort(t, upstream.URL),
		Path:       "/v1/messages",
		SecretRef:  "file:" + secretPath,
		CoveCA:     coveCA,
		CoveCAPEM:  covePEM,
		ProxyAudit: audit,
		ProxyLog:   &log,
	})
	cleanup()
	_ = audit.Close()
	if resp.StatusCode != http.StatusUnauthorized || string(body) != "expired token" {
		t.Fatalf("status/body = %d %q, want 401 expired token", resp.StatusCode, body)
	}
	if strings.Count(log.String(), reloginWarning) != 1 {
		t.Fatalf("proxyd warning log = %q, want one warning", log.String())
	}
	if strings.Contains(log.String(), "expired-oauth-token") {
		t.Fatalf("secret leaked to proxyd log: %q", log.String())
	}
	recs := readAuditRecords(t, auditPath)
	var sawWarn, sawInject bool
	for _, rec := range recs {
		if rec.Policy == "warn" && rec.Level == "warn" && rec.Status == http.StatusUnauthorized && rec.Message == reloginWarning {
			sawWarn = true
		}
		if rec.Policy == "inject" && rec.Status == http.StatusUnauthorized {
			sawInject = true
		}
		if strings.Contains(rec.Message, "expired-oauth-token") {
			t.Fatalf("secret leaked to audit: %+v", rec)
		}
	}
	if !sawWarn || !sawInject {
		t.Fatalf("audit records missing warn/inject 401 records: %+v", recs)
	}
}

func TestGitHubBasicTransformH2H1(t *testing.T) {
	const host = "github.com"
	const token = "REAL"
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	rootPath := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(rootPath, upstreamPEM, 0644); err != nil {
		t.Fatal(err)
	}
	emptyCertDir := filepath.Join(t.TempDir(), "empty-certs")
	if err := os.Mkdir(emptyCertDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", rootPath)
	t.Setenv("SSL_CERT_DIR", emptyCertDir)

	for _, leg := range []string{"h2", "http/1.1"} {
		for _, tc := range []struct {
			name    string
			headers http.Header
		}{
			{"dummy", http.Header{"Authorization": {"Basic ZHVtbXk="}, "X-Dummy": {"remove-me"}}},
			{"probe", nil},
			{"alternate", http.Header{"Authorization": {"Bearer malicious", "Basic ZHVtbXk="}, "X-Dummy": {"remove-me"}}},
		} {
			t.Run(leg+"/"+tc.name, func(t *testing.T) {
				var authorization, dummy string
				upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					authorization, dummy = r.Header.Get("Authorization"), r.Header.Get("X-Dummy")
					w.WriteHeader(http.StatusOK)
				}))
				defer upstream.Close()
				secretPath := writeSecret(t, token)
				cfg := githubBasicConfig(t, serverPort(t, upstream.URL), "file:"+secretPath, leg, []string{"owner/repo"}, []string{"GET", "POST"})
				auditPath := filepath.Join(t.TempDir(), "audit.log")
				audit, err := NewAuditWriter(auditPath)
				if err != nil {
					t.Fatal(err)
				}
				resp, _, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{Leg: leg, Host: host, Port: serverPort(t, upstream.URL), Path: "/owner/repo.git/info/refs", Method: http.MethodGet, CoveCA: coveCA, CoveCAPEM: covePEM, Headers: tc.headers, ProxyAudit: audit})
				cleanup()
				_ = audit.Close()
				if resp.StatusCode != http.StatusOK || authorization != want || dummy != "" {
					t.Fatalf("status/auth/dummy = %d/%q/%q, want 200/%q/empty", resp.StatusCode, authorization, dummy, want)
				}
				recs := readAuditRecords(t, auditPath)
				if len(recs) != 1 || recs[0].AuthMode != "github-basic" || recs[0].Reason != "" {
					t.Fatalf("unexpected audit records: %+v", recs)
				}
			})
		}
	}
}

func TestGitHubBasicRequestGuard(t *testing.T) {
	allowed := []string{"owner/repo", "org/*"}
	for _, tc := range []struct {
		name string
		path string
		ok   bool
	}{
		{"refs", "/owner/repo.git/info/refs", true},
		{"upload", "/owner/repo.git/git-upload-pack", true},
		{"receive", "/owner/repo.git/git-receive-pack", true},
		{"lfs", "/owner/repo.git/info/lfs/objects/batch", true},
		{"wildcard", "/org/any.git/info/refs", true},
		{"other-owner", "/other/repo.git/info/refs", false},
		{"other-repo", "/owner/other.git/info/refs", false},
		{"encoded-slash", "/owner%2Frepo.git/info/refs", false},
		{"traversal", "/owner/%2e%2e.git/info/refs", false},
		{"malformed-percent", "/owner/repo.git/info/%zz", false},
		{"web", "/owner/repo", false},
		{"lfs-root", "/owner/repo.git/info/lfs", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{URL: &url.URL{Path: tc.path, RawPath: tc.path}}
			err := matchGitHubGitRequest(req, allowed)
			if (err == nil) != tc.ok {
				t.Fatalf("matchGitHubGitRequest(%q) error = %v, want allowed=%v", tc.path, err, tc.ok)
			}
		})
	}

}

func TestGitHubBasicDenialsAreAudited(t *testing.T) {
	const host = "github.com"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	rootPath := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(rootPath, upstreamPEM, 0644); err != nil {
		t.Fatal(err)
	}
	emptyCertDir := filepath.Join(t.TempDir(), "empty-certs")
	if err := os.Mkdir(emptyCertDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", rootPath)
	t.Setenv("SSL_CERT_DIR", emptyCertDir)
	for _, tc := range []struct{ name, path, method, reason string }{
		{"resource", "/owner/other.git/info/refs", http.MethodGet, "policy_resource"},
		{"method", "/owner/repo.git/info/refs", http.MethodPost, "policy_method"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
			defer upstream.Close()
			secretPath := writeSecret(t, "REAL")
			cfg := githubBasicConfig(t, serverPort(t, upstream.URL), "file:"+secretPath, "h2", []string{"owner/repo"}, []string{"GET"})
			auditPath := filepath.Join(t.TempDir(), "audit.log")
			audit, err := NewAuditWriter(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			resp, _, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Path: tc.path, Method: tc.method, CoveCA: coveCA, CoveCAPEM: covePEM, ProxyAudit: audit})
			cleanup()
			_ = audit.Close()
			if resp.StatusCode != http.StatusForbidden || called {
				t.Fatalf("status/called = %d/%v, want 403/false", resp.StatusCode, called)
			}
			recs := readAuditRecords(t, auditPath)
			if len(recs) != 1 || recs[0].Reason != tc.reason || recs[0].AuthMode != "github-basic" {
				t.Fatalf("unexpected audit records: %+v", recs)
			}
		})
	}
}

func TestGitHubAPIBearerUsesTemplateInjection(t *testing.T) {
	secretPath := writeSecret(t, "REAL")
	st := &config.InjectStanza{
		HeaderName:     "Authorization",
		HeaderTemplate: "Bearer {secret}",
		Secret:         "file:" + secretPath,
		StripHeaders:   []string{"Authorization"},
		Transform:      "template",
	}
	req := &http.Request{Header: http.Header{"Authorization": {"Bearer dummy"}}}
	decision, err := newHeaderAuthorizer(st, Target{Host: "api.github.com"}, nil, secret.NewCache(io.Discard)).Authorize(req)
	if err != nil || !decision.Applied || req.Header.Get("Authorization") != "Bearer REAL" {
		t.Fatalf("template decision/header/error = %+v/%q/%v", decision, req.Header.Get("Authorization"), err)
	}

	emptyPath := writeSecret(t, "")
	st.Secret = "file:" + emptyPath
	req.Header.Set("Authorization", "Bearer dummy")
	decision, err = newHeaderAuthorizer(st, Target{Host: "api.github.com"}, nil, secret.NewCache(io.Discard)).Authorize(req)
	if err != nil || decision.Applied || req.Header.Get("Authorization") != "" {
		t.Fatalf("empty template decision/header/error = %+v/%q/%v", decision, req.Header.Get("Authorization"), err)
	}
}

func TestGitHubBasicEmptySecretForwardsAnonymously(t *testing.T) {
	emptyPath := writeSecret(t, "")
	st := &config.InjectStanza{
		Transform:          "github-basic",
		HeaderName:         "Authorization",
		BasicUsername:      "x-access-token",
		Secret:             "file:" + emptyPath,
		StripHeaders:       []string{"Authorization"},
		GitHubRepositories: []string{"owner/repo"},
		AllowedMethods:     []string{"GET"},
	}
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/owner/repo.git/info/refs"}, Header: http.Header{"Authorization": {"Basic dummy"}}}
	decision, err := newHeaderAuthorizer(st, Target{Host: "github.com"}, nil, secret.NewCache(io.Discard)).Authorize(req)
	if err != nil || decision.Applied || req.Header.Get("Authorization") != "" {
		t.Fatalf("empty github-basic decision/header/error = %+v/%q/%v", decision, req.Header.Get("Authorization"), err)
	}
}

func TestGitHTTPBackendThroughGitHubBasicProxy(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed: " + err.Error())
	}
	const dummy = "cove-dummy-do-not-use"
	const real = "REAL-GITHUB-TOKEN"
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+real))

	root := t.TempDir()
	repo := filepath.Join(root, "owner", "repo.git")
	if err := os.MkdirAll(filepath.Dir(repo), 0755); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, nil, "init", "--bare", repo)
	runGit(t, root, nil, "-C", repo, "config", "http.receivepack", "true")
	seed := filepath.Join(root, "seed")
	runGit(t, root, nil, "init", seed)
	runGit(t, seed, nil, "config", "user.email", "test@example.invalid")
	runGit(t, seed, nil, "config", "user.name", "Cove Test")
	if err := os.WriteFile(filepath.Join(seed, "README"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, seed, nil, "add", "README")
	runGit(t, seed, nil, "commit", "-m", "seed")
	runGit(t, seed, nil, "remote", "add", "origin", repo)
	runGit(t, seed, nil, "push", "origin", "HEAD:main")

	var upstreamAuths []string
	var upstreamMu sync.Mutex
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	upstream := newInjectUpstream(t, upstreamCA, "github.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamMu.Lock()
		upstreamAuths = append(upstreamAuths, r.Header.Get("Authorization"))
		upstreamMu.Unlock()
		if r.Header.Get("Authorization") != wantAuth {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		serveGitHTTPBackend(t, root, w, r)
	}))
	defer upstream.Close()

	rootPath := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(rootPath, upstreamPEM, 0644); err != nil {
		t.Fatal(err)
	}
	emptyCertDir := filepath.Join(t.TempDir(), "empty-certs")
	if err := os.Mkdir(emptyCertDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", rootPath)
	t.Setenv("SSL_CERT_DIR", emptyCertDir)

	secretPath := writeSecret(t, real)
	coveCA, covePEM, _ := newTestCA(t)
	cfg := githubBasicConfig(t, 443, "file:"+secretPath, "http/1.1", []string{"owner/repo"}, []string{"GET", "POST"})
	proxyAddr, stopProxy := startGitProxy(t, cfg, coveCA, upstream.URL)
	defer stopProxy()

	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0700); err != nil {
		t.Fatal(err)
	}
	gitEnv := box.BuildEnv(box.Directives{ProxyEnabled: true, ProxyPort: 1, Inject: []box.InjectDirective{{Transform: "github-basic", DummyValue: dummy}}})
	gitEnv = replaceEnv(gitEnv, "HOME", home)
	gitEnv = replaceEnv(gitEnv, "HTTPS_PROXY", "http://"+proxyAddr)
	gitEnv = replaceEnv(gitEnv, "HTTP_PROXY", "http://"+proxyAddr)
	gitEnv = replaceEnv(gitEnv, "https_proxy", "http://"+proxyAddr)
	gitEnv = replaceEnv(gitEnv, "http_proxy", "http://"+proxyAddr)
	covePath := filepath.Join(t.TempDir(), "cove-ca.pem")
	if err := os.WriteFile(covePath, covePEM, 0644); err != nil {
		t.Fatal(err)
	}
	gitEnv = replaceEnv(gitEnv, "GIT_SSL_CAINFO", covePath)
	gitEnv = replaceEnv(gitEnv, "SSL_CERT_FILE", covePath)
	clone := filepath.Join(root, "clone")
	runGit(t, root, gitEnv, "clone", "https://github.com/owner/repo.git", clone)
	runGit(t, clone, gitEnv, "config", "user.email", "test@example.invalid")
	runGit(t, clone, gitEnv, "config", "user.name", "Cove Test")
	if err := os.WriteFile(filepath.Join(clone, "PUSHED"), []byte("pushed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runGit(t, clone, gitEnv, "add", "PUSHED")
	runGit(t, clone, gitEnv, "commit", "-m", "push")
	runGit(t, clone, gitEnv, "push", "origin", "HEAD:main")

	for _, operation := range []string{"approve", "reject"} {
		cmd := exec.Command("git", "credential", operation)
		cmd.Env = gitEnv
		cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\nusername=x-access-token\npassword=" + dummy + "\n\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git credential %s: %v: %s", operation, err, out)
		}
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("credential store/erase persisted in HOME: %+v", entries)
	}
	t.Run("empty resolved token propagates upstream 401", func(t *testing.T) {
		empty := writeSecret(t, "")
		emptyCfg := githubBasicConfig(t, 443, "file:"+empty, "http/1.1", []string{"owner/repo"}, []string{"GET", "POST"})
		emptyProxy, stop := startGitProxy(t, emptyCfg, coveCA, upstream.URL)
		defer stop()
		env := replaceEnv(gitEnv, "HTTPS_PROXY", "http://"+emptyProxy)
		env = replaceEnv(env, "HTTP_PROXY", "http://"+emptyProxy)
		env = replaceEnv(env, "https_proxy", "http://"+emptyProxy)
		env = replaceEnv(env, "http_proxy", "http://"+emptyProxy)
		cmd := exec.Command("git", "push", "origin", "HEAD:main")
		cmd.Dir, cmd.Env = clone, env
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "Authentication failed") {
			t.Fatalf("empty-token git push error/output = %v/%q, want upstream authentication failure", err, out)
		}
	})
	upstreamMu.Lock()
	defer upstreamMu.Unlock()
	if len(upstreamAuths) == 0 {
		t.Fatal("git http-backend received no requests")
	}
	sawReal := false
	for _, got := range upstreamAuths {
		if strings.Contains(got, dummy) {
			t.Fatalf("upstream Authorization leaked dummy: %q", got)
		}
		if got == wantAuth {
			sawReal = true
		}
	}
	if !sawReal {
		t.Fatalf("upstream never received real Basic header: %q", upstreamAuths)
	}
}

func runGit(t *testing.T, dir string, env []string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if env != nil {
		cmd.Env = env
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

func replaceEnv(env []string, name, value string) []string {
	prefix := name + "="
	for i, item := range env {
		if strings.HasPrefix(item, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func startGitProxy(t *testing.T, cfg *config.Config, coveCA *CA, upstreamURL string) (string, func()) {
	t.Helper()
	upstreamAddr := strings.TrimPrefix(upstreamURL, "https://")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &Proxyd{
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
		dialTCP: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstreamAddr)
		},
		log: io.Discard,
	}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			wg.Add(1)
			go func(raw net.Conn) {
				defer wg.Done()
				(&Conn{raw: raw, br: bufio.NewReader(raw), sess: Session{ID: "git", Agent: "git"}, proxy: p, matcher: NewMatcher(cfg), ca: coveCA, secrets: secret.NewCache(io.Discard), started: time.Now()}).handle()
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { close(done); _ = ln.Close(); wg.Wait() }
}

func serveGitHTTPBackend(t *testing.T, root string, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	cmd := exec.Command("git", "http-backend")
	cmd.Env = append(os.Environ(), "GIT_PROJECT_ROOT="+root, "GIT_HTTP_EXPORT_ALL=1", "REQUEST_METHOD="+r.Method, "PATH_INFO="+r.URL.Path, "QUERY_STRING="+r.URL.RawQuery, "CONTENT_TYPE="+r.Header.Get("Content-Type"), "CONTENT_LENGTH="+strconv.FormatInt(r.ContentLength, 10))
	cmd.Stdin = r.Body
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git http-backend: %v", err)
	}
	headEnd := bytes.Index(out, []byte("\r\n\r\n"))
	if headEnd < 0 {
		headEnd = bytes.Index(out, []byte("\n\n"))
	}
	if headEnd < 0 {
		t.Fatalf("git http-backend malformed response: %q", out)
	}
	head, body := string(out[:headEnd]), out[headEnd+4:]
	if !strings.Contains(string(out[:headEnd]), "\r\n") {
		body = out[headEnd+2:]
	}
	status := http.StatusOK
	for _, line := range strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(name, "Status") {
			fmt.Sscanf(strings.TrimSpace(value), "%d", &status)
			continue
		}
		w.Header().Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

type injectRequest struct {
	Leg        string
	Host       string
	Port       int
	Path       string
	Method     string
	Body       string
	SecretRef  string
	CoveCA     *CA
	CoveCAPEM  []byte
	Headers    http.Header
	ProxyAudit *AuditWriter
	ProxyLog   io.Writer
}

func requestThroughInject(t *testing.T, req injectRequest) (*http.Response, []byte, func()) {
	t.Helper()
	resp, cleanup := openInjectResponse(t, req)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return resp, body, cleanup
}

func openInjectResponse(t *testing.T, req injectRequest) (*http.Response, func()) {
	t.Helper()
	cfg := injectConfig(t, req.Host, req.Port, req.SecretRef, req.Leg)
	return openInjectResponseWithConfig(t, cfg, req)
}

func requestThroughInjectConfig(t *testing.T, cfg *config.Config, req injectRequest) (*http.Response, []byte, func()) {
	t.Helper()
	resp, cleanup := openInjectResponseWithConfig(t, cfg, req)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return resp, body, cleanup
}

func openInjectResponseWithConfig(t *testing.T, cfg *config.Config, req injectRequest) (*http.Response, func()) {
	t.Helper()
	client, server := net.Pipe()
	p := &Proxyd{
		log: req.ProxyLog,
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
	}
	if p.log == nil {
		p.log = io.Discard
	}
	conn := &Conn{
		raw:     server,
		br:      bufio.NewReader(server),
		sess:    Session{ID: "abc12345", Agent: "claude"},
		proxy:   p,
		matcher: NewMatcher(cfg),
		ca:      req.CoveCA,
		secrets: secret.NewCache(io.Discard),
		audit:   req.ProxyAudit,
		started: time.Now(),
	}
	handled := make(chan struct{})
	go func() {
		defer close(handled)
		conn.handle()
	}()
	fmt.Fprintf(client, "CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", req.Host, req.Port, req.Host)
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(line, "\r\n") != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("CONNECT status = %q", line)
	}
	for {
		h, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	tlsConn := tls.Client(newBufConn(br, client), &tls.Config{
		ServerName: req.Host,
		RootCAs:    certPoolFromPEM(t, req.CoveCAPEM),
		NextProtos: []string{req.Leg},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	httpReq := newClientRequest(t, req)
	var resp *http.Response
	var h2cc *http2.ClientConn
	if req.Leg == "h2" {
		h2cc, err = (&http2.Transport{}).NewClientConn(tlsConn)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = h2cc.RoundTrip(httpReq)
	} else {
		httpReq.Close = true
		err = httpReq.Write(tlsConn)
		if err == nil {
			resp, err = http.ReadResponse(bufio.NewReader(tlsConn), httpReq)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if h2cc != nil {
			_ = h2cc.Close()
		}
		_ = tlsConn.Close()
		_ = client.Close()
		select {
		case <-handled:
		case <-time.After(time.Second):
			t.Fatalf("proxy handler did not exit")
		}
	}
	return resp, cleanup
}

func newClientRequest(t *testing.T, req injectRequest) *http.Request {
	t.Helper()
	path := req.Path
	if path == "" {
		path = "/"
	}
	u := &url.URL{Scheme: "https", Host: net.JoinHostPort(req.Host, strconv.Itoa(req.Port))}
	parsedPath, err := url.ParseRequestURI(path)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = parsedPath.Path
	u.RawQuery = parsedPath.RawQuery
	method := req.Method
	if method == "" {
		method = http.MethodPost
	}
	httpReq, err := http.NewRequest(method, u.String(), strings.NewReader(req.Body))
	if err != nil {
		t.Fatal(err)
	}
	httpReq.Host = req.Host
	for k, vals := range req.Headers {
		for _, v := range vals {
			httpReq.Header.Add(k, v)
		}
	}
	return httpReq
}

func injectConfig(t *testing.T, host string, port int, secretRef, alpn string) *config.Config {
	t.Helper()
	data := fmt.Sprintf(`
[[inject]]
host = %q
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = %q
strip_headers = ["x-api-key"]
alpn = %q
`, net.JoinHostPort(host, strconv.Itoa(port)), secretRef, alpn)
	cfg, err := config.LoadBytes([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func githubBasicConfig(t *testing.T, port int, secretRef, alpn string, repositories, methods []string) *config.Config {
	t.Helper()
	data := fmt.Sprintf(`
[[inject]]
host = %q
transform = "github-basic"
header_name = "Authorization"
basic_username = "x-access-token"
secret = %q
strip_headers = ["Authorization", "X-Dummy"]
github_repositories = [%s]
allowed_methods = [%s]
alpn = %q
`, net.JoinHostPort("github.com", strconv.Itoa(port)), secretRef, tomlStrings(repositories), tomlStrings(methods), alpn)
	cfg, err := config.LoadBytes([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func tomlStrings(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, strconv.Quote(value))
	}
	return strings.Join(quoted, ", ")
}

func newInjectUpstream(t *testing.T, ca *CA, host string, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCertForHost(t, ca, host)},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	return srv
}

func serverPort(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	_, portText, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func writeSecret(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
