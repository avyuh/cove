package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

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

type injectRequest struct {
	Leg        string
	Host       string
	Port       int
	Path       string
	Body       string
	SecretRef  string
	CoveCA     *CA
	CoveCAPEM  []byte
	Headers    http.Header
	ProxyAudit *AuditWriter
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
		log: io.Discard,
		lookupIP: func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		},
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
	httpReq, err := http.NewRequest(http.MethodPost, u.String(), strings.NewReader(req.Body))
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
