package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cove/internal/config"
	"cove/internal/secret"

	"golang.org/x/net/http2"
)

func TestMTLSUpstreamTerminationH2AndH1(t *testing.T) {
	const host = "partner.example.test"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	clientCA, clientCAPEM, _ := newTestCA(t)
	pair := clientLeafFor(t, clientCA, "cove-mtls-client")
	certRef, keyRef := writeClientPair(t, pair)
	root := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(root, upstreamPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", root)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	wantFingerprint := certificateFingerprint(pair.Certificate[0])
	for _, tc := range []struct {
		name       string
		leg        string
		maxVersion uint16
		wantTLS    uint16
	}{
		{name: "h2-tls12", leg: "h2", maxVersion: tls.VersionTLS12, wantTLS: tls.VersionTLS12},
		{name: "http1-tls12", leg: "http/1.1", maxVersion: tls.VersionTLS12, wantTLS: tls.VersionTLS12},
		{name: "h2-tls13-default", leg: "h2", wantTLS: tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := newMTLSUpstream(t, upstreamCA, clientCAPEM, host, tc.maxVersion, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if tc.leg == "h2" && r.ProtoMajor != 2 {
					t.Errorf("upstream protocol=%s, want HTTP/2", r.Proto)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if tc.leg == "http/1.1" && r.ProtoMajor != 1 {
					t.Errorf("upstream protocol=%s, want HTTP/1.1", r.Proto)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if len(r.TLS.VerifiedChains) != 1 || certificateFingerprint(r.TLS.PeerCertificates[0].Raw) != wantFingerprint {
					t.Error("upstream did not receive the configured client certificate")
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.TLS.Version != tc.wantTLS {
					t.Errorf("upstream TLS version=%x, want %x", r.TLS.Version, tc.wantTLS)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.TLS.ServerName != host {
					t.Errorf("upstream SNI=%q, want %q", r.TLS.ServerName, host)
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
				if r.Method != http.MethodPost || r.URL.Path != "/v1/limited/resource" {
					t.Error("unexpected request escaped mTLS policy")
					w.WriteHeader(http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer upstream.Close()
			cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), certRef, keyRef, tc.leg)
			resp, _, cleanup := requestThroughMTLSConfig(t, cfg, injectRequest{Leg: tc.leg, Host: host, Port: serverPort(t, upstream.URL), Method: http.MethodPost, Path: "/v1/limited/resource", CoveCA: coveCA, CoveCAPEM: covePEM}, nil)
			cleanup()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status=%d, want 204", resp.StatusCode)
			}
			if hits.Load() != 1 {
				t.Fatalf("upstream hits=%d, want 1", hits.Load())
			}
		})
	}
}

func TestMTLSRejectsPolicyBeforeUpstream(t *testing.T) {
	st := &config.MTLSStanza{AllowedMethods: []string{http.MethodGet}, AllowedPrefixes: []string{"/v1/limited/"}}
	a := mtlsAuthorizer{stanza: st}
	for _, tc := range []struct{ method, path, reason string }{
		{http.MethodPost, "/v1/limited/x", "policy_method"},
		{http.MethodGet, "/v1/other", "policy_resource"},
		{http.MethodGet, "/v1%2flimited/x", "policy_resource"},
		{http.MethodGet, "/v1/limited/%2e%2e/x", "policy_resource"},
	} {
		t.Run(tc.reason+tc.path, func(t *testing.T) {
			r, err := http.NewRequest(tc.method, "https://partner.example.test"+tc.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = a.Authorize(r)
			pe, ok := err.(*PolicyError)
			if !ok || pe.Status != http.StatusForbidden || pe.Reason != tc.reason {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestMTLSMissingCertificateDoesNotDial(t *testing.T) {
	st := &config.MTLSStanza{ClientCert: "env:NOT_SET", ClientKey: "env:NOT_SET"}
	callback := mtlsClientCertificate(nil, st)
	if _, err := callback(nil); err == nil {
		t.Fatal("missing client material was accepted")
	}
}

func TestMTLSMissingMaterialFailsClosed(t *testing.T) {
	const host = "partner-missing.example.test"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	_, clientCAPEM, _ := newTestCA(t)
	root := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(root, upstreamPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", root)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	var hits atomic.Int32
	upstream := newMTLSUpstream(t, upstreamCA, clientCAPEM, host, tls.VersionTLS12, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer upstream.Close()
	missing := filepath.Join(t.TempDir(), "missing")
	cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), "file:"+missing, "file:"+missing+"-key", "h2")
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := NewAuditWriter(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Method: http.MethodPost, Path: "/v1/limited/resource", CoveCA: coveCA, CoveCAPEM: covePEM, ProxyAudit: audit})
	cleanup()
	_ = audit.Close()
	if resp.StatusCode != http.StatusBadGateway || hits.Load() != 0 {
		t.Fatalf("status=%d upstream hits=%d, want 502 and 0", resp.StatusCode, hits.Load())
	}
	recs := readAuditRecords(t, auditPath)
	if len(recs) != 1 || recs[0].Policy != "inject" || recs[0].Reason != "upstream_tls" || recs[0].AuthMode != "mtls" {
		t.Fatalf("unexpected audit records: %+v", recs)
	}
}

func TestMTLSNoClientCertificateRequestFailsClosed(t *testing.T) {
	const host = "partner-no-request.example.test"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	clientCA, clientCAPEM, _ := newTestCA(t)
	pair := clientLeafFor(t, clientCA, "configured-client")
	certRef, keyRef := writeClientPair(t, pair)
	trustUpstreamCA(t, upstreamPEM)

	var hits atomic.Int32
	upstream := newMTLSUpstreamWithClientAuth(t, upstreamCA, clientCAPEM, host, tls.VersionTLS12, tls.NoClientCert, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), certRef, keyRef, "h2")
	assertMTLSRequestFailsClosed(t, cfg, injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Method: http.MethodPost, Path: "/v1/limited/resource", CoveCA: coveCA, CoveCAPEM: covePEM}, &hits, http.StatusBadGateway, "deny", "mtls_not_requested")
}

func TestMTLSInvalidClientIdentityFailsClosed(t *testing.T) {
	const host = "partner-invalid-client.example.test"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	clientCA, clientCAPEM, _ := newTestCA(t)
	wrongCA, _, _ := newTestCA(t)
	validPair := clientLeafFor(t, clientCA, "valid-client")
	trustUpstreamCA(t, upstreamPEM)

	t.Run("wrong-client-ca", func(t *testing.T) {
		certRef, keyRef := writeClientPair(t, clientLeafFor(t, wrongCA, "wrong-ca-client"))
		var hits atomic.Int32
		upstream := newMTLSUpstream(t, upstreamCA, clientCAPEM, host, tls.VersionTLS12, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
		defer upstream.Close()
		cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), certRef, keyRef, "h2")
		assertMTLSRequestFailsClosed(t, cfg, injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Method: http.MethodPost, Path: "/v1/limited/resource", CoveCA: coveCA, CoveCAPEM: covePEM}, &hits, http.StatusBadGateway, "inject", "upstream_tls")
	})

	t.Run("mismatched-key", func(t *testing.T) {
		otherPair := clientLeafFor(t, clientCA, "other-key-client")
		certRef, keyRef := writeClientMaterial(t, validPair.Certificate, otherPair.PrivateKey)
		var hits atomic.Int32
		upstream := newMTLSUpstream(t, upstreamCA, clientCAPEM, host, tls.VersionTLS12, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
		defer upstream.Close()
		cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), certRef, keyRef, "h2")
		assertMTLSRequestFailsClosed(t, cfg, injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Method: http.MethodPost, Path: "/v1/limited/resource", CoveCA: coveCA, CoveCAPEM: covePEM}, &hits, http.StatusBadGateway, "inject", "upstream_tls")
	})

	t.Run("expired-client-certificate", func(t *testing.T) {
		expired := clientLeafForValidity(t, clientCA, "expired-client", time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
		certRef, keyRef := writeClientPair(t, expired)
		var hits atomic.Int32
		upstream := newMTLSUpstream(t, upstreamCA, clientCAPEM, host, tls.VersionTLS12, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
		defer upstream.Close()
		cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), certRef, keyRef, "h2")
		assertMTLSRequestFailsClosed(t, cfg, injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Method: http.MethodPost, Path: "/v1/limited/resource", CoveCA: coveCA, CoveCAPEM: covePEM}, &hits, http.StatusBadGateway, "inject", "upstream_tls")
	})

	t.Run("wrong-server-hostname", func(t *testing.T) {
		certRef, keyRef := writeClientPair(t, validPair)
		var hits atomic.Int32
		upstream := newMTLSUpstream(t, upstreamCA, clientCAPEM, "different-server-name.example.test", tls.VersionTLS12, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
		defer upstream.Close()
		cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), certRef, keyRef, "h2")
		assertMTLSRequestFailsClosed(t, cfg, injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Method: http.MethodPost, Path: "/v1/limited/resource", CoveCA: coveCA, CoveCAPEM: covePEM}, &hits, http.StatusBadGateway, "inject", "upstream_tls")
	})
}

func TestMTLSPolicyRejectionE2E(t *testing.T) {
	const host = "partner-policy.example.test"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	clientCA, clientCAPEM, _ := newTestCA(t)
	certRef, keyRef := writeClientPair(t, clientLeafFor(t, clientCA, "policy-client"))
	trustUpstreamCA(t, upstreamPEM)

	for _, tc := range []struct {
		name, method, path, reason string
	}{
		{name: "method", method: http.MethodGet, path: "/v1/limited/resource", reason: "policy_method"},
		{name: "path", method: http.MethodPost, path: "/v1/other", reason: "policy_resource"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := newMTLSUpstream(t, upstreamCA, clientCAPEM, host, tls.VersionTLS12, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
			defer upstream.Close()
			cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), certRef, keyRef, "h2")
			assertMTLSRequestFailsClosed(t, cfg, injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Method: tc.method, Path: tc.path, CoveCA: coveCA, CoveCAPEM: covePEM}, &hits, http.StatusForbidden, "deny", tc.reason)
		})
	}
}

func TestMTLSClientCertificateRotation(t *testing.T) {
	const host = "partner-rotation.example.test"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	clientCA, clientCAPEM, _ := newTestCA(t)
	firstPair := clientLeafFor(t, clientCA, "rotation-first")
	secondPair := clientLeafFor(t, clientCA, "rotation-second")
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	writeClientMaterialAt(t, certPath, keyPath, firstPair.Certificate, firstPair.PrivateKey)
	trustUpstreamCA(t, upstreamPEM)

	fingerprints := make(chan string, 2)
	var hits atomic.Int32
	upstream := newMTLSUpstream(t, upstreamCA, clientCAPEM, host, tls.VersionTLS12, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		fingerprints <- certificateFingerprint(r.TLS.PeerCertificates[0].Raw)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	cfg := mtlsConfig(t, host, serverPort(t, upstream.URL), "file:"+certPath, "file:"+keyPath, "h2")
	cache := secret.NewCache(io.Discard)
	request := injectRequest{Leg: "h2", Host: host, Port: serverPort(t, upstream.URL), Method: http.MethodPost, Path: "/v1/limited/resource", CoveCA: coveCA, CoveCAPEM: covePEM}

	resp, _, cleanup := requestThroughMTLSConfig(t, cfg, request, cache)
	cleanup()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("first status=%d, want 204", resp.StatusCode)
	}
	writeClientMaterialAt(t, certPath, keyPath, secondPair.Certificate, secondPair.PrivateKey)
	rotatedTime := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(certPath, rotatedTime, rotatedTime); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(keyPath, rotatedTime, rotatedTime); err != nil {
		t.Fatal(err)
	}

	resp, _, cleanup = requestThroughMTLSConfig(t, cfg, request, cache)
	cleanup()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("rotated status=%d, want 204", resp.StatusCode)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits=%d, want 2", hits.Load())
	}
	if got := <-fingerprints; got != certificateFingerprint(firstPair.Certificate[0]) {
		t.Fatalf("first fingerprint=%s, want first certificate", got)
	}
	if got := <-fingerprints; got != certificateFingerprint(secondPair.Certificate[0]) {
		t.Fatalf("second fingerprint=%s, want rotated certificate", got)
	}
}

func mtlsConfig(t *testing.T, host string, port int, certRef, keyRef, alpn string) *config.Config {
	t.Helper()
	cfg, err := config.LoadBytes([]byte(fmt.Sprintf(`
[[mtls]]
host = %q
client_cert = %q
client_key = %q
allowed_methods = ["POST"]
allowed_path_prefixes = ["/v1/limited/"]
alpn = %q
`, fmt.Sprintf("%s:%d", host, port), certRef, keyRef, alpn)))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func newMTLSUpstream(t *testing.T, serverCA *CA, clientCAPEM []byte, host string, maxVersion uint16, h http.Handler) *httptest.Server {
	t.Helper()
	return newMTLSUpstreamWithClientAuth(t, serverCA, clientCAPEM, host, maxVersion, tls.RequireAndVerifyClientCert, h)
}

func newMTLSUpstreamWithClientAuth(t *testing.T, serverCA *CA, clientCAPEM []byte, host string, maxVersion uint16, clientAuth tls.ClientAuthType, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCertForHost(t, serverCA, host)}, ClientAuth: clientAuth, ClientCAs: certPoolFromPEM(t, clientCAPEM), NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}
	if maxVersion != 0 {
		tlsConfig.MaxVersion = maxVersion
	}
	srv.TLS = tlsConfig
	srv.StartTLS()
	return srv
}

func writeClientPair(t *testing.T, pair tls.Certificate) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	writeClientMaterialAt(t, certPath, keyPath, pair.Certificate, pair.PrivateKey)
	return "file:" + certPath, "file:" + keyPath
}

func writeClientMaterial(t *testing.T, certificates [][]byte, privateKey any) (string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	writeClientMaterialAt(t, certPath, keyPath, certificates, privateKey)
	return "file:" + certPath, "file:" + keyPath
}

func writeClientMaterialAt(t *testing.T, certPath, keyPath string, certificates [][]byte, privateKey any) {
	t.Helper()
	var certPEM []byte
	for _, der := range certificates {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("client key type=%T", privateKey)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
}

func certificateFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func clientLeafForValidity(t *testing.T, ca *CA, cn string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
}

func trustUpstreamCA(t *testing.T, upstreamPEM []byte) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "upstream-root.pem")
	if err := os.WriteFile(root, upstreamPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", root)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
}

func assertMTLSRequestFailsClosed(t *testing.T, cfg *config.Config, req injectRequest, hits *atomic.Int32, wantStatus int, wantPolicy, wantReason string) {
	t.Helper()
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := NewAuditWriter(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	req.ProxyAudit = audit
	resp, _, cleanup := requestThroughMTLSConfig(t, cfg, req, nil)
	cleanup()
	if err := audit.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != wantStatus || resp.StatusCode >= 200 && resp.StatusCode < 300 {
		t.Fatalf("status=%d, want fail-closed status %d", resp.StatusCode, wantStatus)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hits=%d, want 0 (no fallback tunnel)", hits.Load())
	}
	recs := readAuditRecords(t, auditPath)
	if len(recs) != 1 {
		t.Fatalf("audit records=%d, want exactly 1: %+v", len(recs), recs)
	}
	rec := recs[0]
	if rec.Policy != wantPolicy || rec.Status != wantStatus || rec.Reason != wantReason || rec.AuthMode != "mtls" {
		t.Fatalf("unexpected sanitized audit record: %+v", rec)
	}
	serialized := fmt.Sprintf("%+v", rec)
	if strings.Contains(serialized, "BEGIN CERTIFICATE") || strings.Contains(serialized, "PRIVATE KEY") {
		t.Fatalf("credential material appeared in audit record")
	}
}

func requestThroughMTLSConfig(t *testing.T, cfg *config.Config, req injectRequest, cache *secret.Cache) (*http.Response, []byte, func()) {
	t.Helper()
	resp, cleanup := openMTLSResponseWithConfig(t, cfg, req, cache)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return resp, body, cleanup
}

func openMTLSResponseWithConfig(t *testing.T, cfg *config.Config, req injectRequest, cache *secret.Cache) (*http.Response, func()) {
	t.Helper()
	if cache == nil {
		cache = secret.NewCache(io.Discard)
	}
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
		sess:    Session{ID: "mtls-test", Agent: "claude"},
		proxy:   p,
		matcher: NewMatcher(cfg),
		ca:      req.CoveCA,
		secrets: cache,
		audit:   req.ProxyAudit,
		started: time.Now(),
	}
	handled := make(chan struct{})
	go func() {
		defer close(handled)
		conn.handle()
	}()
	if _, err := fmt.Fprintf(client, "CONNECT %s:%d HTTP/1.1\r\nHost: %s\r\n\r\n", req.Host, req.Port, req.Host); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(client)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimRight(line, "\r\n") != "HTTP/1.1 200 Connection Established" {
		t.Fatalf("CONNECT status=%q", line)
	}
	for {
		header, err := br.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if header == "\r\n" || header == "\n" {
			break
		}
	}
	clientTLSConfig := &tls.Config{
		ServerName: req.Host,
		RootCAs:    certPoolFromPEM(t, req.CoveCAPEM),
		NextProtos: []string{req.Leg},
		MinVersion: tls.VersionTLS12,
	}
	if len(clientTLSConfig.Certificates) != 0 || clientTLSConfig.GetClientCertificate != nil {
		t.Fatal("in-box client unexpectedly configured with a client certificate")
	}
	tlsConn := tls.Client(newBufConn(br, client), clientTLSConfig)
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	httpReq := newClientRequest(t, req)
	var resp *http.Response
	var h2cc *http2.ClientConn
	if req.Leg == "h2" {
		h2cc, err = (&http2.Transport{}).NewClientConn(tlsConn)
		if err == nil {
			resp, err = h2cc.RoundTrip(httpReq)
		}
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
