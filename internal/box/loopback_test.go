package box

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
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
	"cove/internal/proxy"
)

func TestBaseURLLoopbackDynamicPortConnectsThroughInjectPath(t *testing.T) {
	const host = "127.0.0.1"
	_, covePEM, coveKeyPEM := newBoxTestCA(t)
	upstreamCA, upstreamPEM, _ := newBoxTestCA(t)
	var captured atomic.Value
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured.Store(map[string]string{
			"authorization": r.Header.Get("Authorization"),
			"x-api-key":     r.Header.Get("x-api-key"),
			"path":          r.URL.RequestURI(),
		})
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "loopback-ok")
	}))
	leaf, err := upstreamCA.LeafFor(host)
	if err != nil {
		t.Fatal(err)
	}
	upstream.TLS = &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	upstream.StartTLS()
	defer upstream.Close()
	upstreamPort := mustServerPort(t, upstream.URL)

	cfgHome := t.TempDir()
	cfgDir := filepath.Join(cfgHome, "cove")
	if err := os.MkdirAll(cfgDir, 0700); err != nil {
		t.Fatal(err)
	}
	stateHome := t.TempDir()
	stateDir := filepath.Join(stateHome, "cove")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "ca.pem"), covePEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "ca-key.pem"), coveKeyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(t.TempDir(), "kimi-api-key")
	if err := os.WriteFile(secretPath, []byte("loopback-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	configText := fmt.Sprintf(`
[[inject]]
host = %q
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = %q
strip_headers = ["x-api-key"]
dummy_env = "KIMI_API_KEY"
base_url_env = "KIMI_BASE_URL"
base_url_value = "http://127.0.0.1:0"
`, net.JoinHostPort(host, strconv.Itoa(upstreamPort)), "file:"+secretPath)
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte(configText), 0600); err != nil {
		t.Fatal(err)
	}
	upstreamRoot := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(upstreamRoot, upstreamPEM, 0644); err != nil {
		t.Fatal(err)
	}
	emptyCertDir := filepath.Join(t.TempDir(), "empty-certs")
	if err := os.Mkdir(emptyCertDir, 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", cfgHome)
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("SSL_CERT_FILE", upstreamRoot)
	t.Setenv("SSL_CERT_DIR", emptyCertDir)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	controlSock := filepath.Join(stateDir, "proxyd.sock")
	proxyErr := make(chan error, 1)
	go func() {
		proxyErr <- proxy.Serve(cfg, controlSock)
	}()
	waitForUnixSocket(t, controlSock)
	control, sessionSock := registerProxySession(t, controlSock)
	defer control.Close()

	connectLine := make(chan string, 1)
	stopShim, proxyPort := startTestShim(t, sessionSock, connectLine)
	defer stopShim()

	d := Directives{
		ProxyPort: proxyPort,
		CAPEM:     covePEM,
		Inject: []InjectDirective{{
			Host:         host,
			Port:         upstreamPort,
			BaseURLEnv:   "KIMI_BASE_URL",
			BaseURLValue: dynamicBaseURLLoopback,
		}},
	}
	stopLoopbacks, err := startBaseURLLoopbacks(&d)
	if err != nil {
		t.Fatal(err)
	}
	defer stopLoopbacks()
	baseURL := d.Inject[0].BaseURLValue
	if baseURL == dynamicBaseURLLoopback {
		t.Fatal("dynamic base URL was not rewritten")
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host == net.JoinHostPort("127.0.0.1", strconv.Itoa(proxyPort)) {
		t.Fatalf("loopback port collided with shim port: %s", baseURL)
	}

	client := &http.Client{Transport: &http.Transport{Proxy: nil}}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions?model=kimi", strings.NewReader(`{"ok":true}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("x-api-key", "client-dummy")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted || string(body) != "loopback-ok" {
		t.Fatalf("status/body = %d %q, want 202 loopback-ok", resp.StatusCode, body)
	}
	select {
	case line := <-connectLine:
		want := "CONNECT " + net.JoinHostPort(host, strconv.Itoa(upstreamPort)) + " HTTP/1.1"
		if line != want {
			t.Fatalf("CONNECT line = %q, want %q", line, want)
		}
	case <-time.After(time.Second):
		t.Fatal("shim did not observe CONNECT")
	}
	gotAny := captured.Load()
	if gotAny == nil {
		t.Fatal("upstream did not receive request")
	}
	got := gotAny.(map[string]string)
	if got["authorization"] != "Bearer loopback-secret" {
		t.Fatalf("Authorization = %q, want injected secret", got["authorization"])
	}
	if got["x-api-key"] != "" {
		t.Fatalf("dummy x-api-key leaked upstream: %q", got["x-api-key"])
	}
	if got["path"] != "/v1/chat/completions?model=kimi" {
		t.Fatalf("upstream path = %q", got["path"])
	}

	select {
	case err := <-proxyErr:
		if err != nil {
			t.Fatalf("proxy returned early: %v", err)
		}
	default:
	}
}

func startTestShim(t *testing.T, sessionSock string, connectLine chan<- string) (func(), int) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go forwardTestShimConn(c, sessionSock, connectLine)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	return func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("test shim did not stop")
		}
	}, port
}

func forwardTestShimConn(c net.Conn, sessionSock string, connectLine chan<- string) {
	defer c.Close()
	u, err := net.Dial("unix", sessionSock)
	if err != nil {
		return
	}
	defer u.Close()
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	select {
	case connectLine <- strings.TrimRight(line, "\r\n"):
	default:
	}
	if _, err := io.WriteString(u, line); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(u, br)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(c, u)
		done <- struct{}{}
	}()
	<-done
}

func waitForUnixSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, err := net.DialTimeout("unix", path, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s: %v", path, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func registerProxySession(t *testing.T, controlSock string) (net.Conn, string) {
	t.Helper()
	c, err := net.DialTimeout("unix", controlSock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(c, "REGISTER/2 {\"session\":\"abc12345\",\"agent\":\"kimi\",\"audit\":true}\n"); err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		_ = c.Close()
		t.Fatal(err)
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "OK/2 ") {
		_ = c.Close()
		t.Fatalf("REGISTER response = %q", line)
	}
	var ok struct {
		Socket string `json:"socket"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "OK/2 ")), &ok); err != nil || ok.Socket == "" {
		_ = c.Close()
		t.Fatalf("REGISTER response = %q, err=%v", line, err)
	}
	return c, ok.Socket
}

func mustServerPort(t *testing.T, rawURL string) int {
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

func newBoxTestCA(t *testing.T) (*proxy.CA, []byte, []byte) {
	t.Helper()
	certPEM, keyPEM := generateBoxTestCAPEM(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	ca, err := proxy.LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return ca, certPEM, keyPEM
}

func generateBoxTestCAPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "cove box test CA",
			Organization: []string{"cove-test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
