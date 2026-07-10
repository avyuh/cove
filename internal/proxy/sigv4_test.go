package proxy

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cove/internal/config"
)

// This is deliberately an E2E test: the client speaks CONNECT/TLS to cove,
// while the upstream independently verifies the SDK-produced signature.
func TestSigV4ResignsThroughMITM(t *testing.T) {
	const host = "my-bucket.s3.us-east-1.amazonaws.com"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, upstreamPEM := sharedUpstreamTestCA(t)
	root := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(root, upstreamPEM, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", root)
	t.Setenv("SSL_CERT_DIR", t.TempDir())
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	var hits atomic.Int32
	upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if _, err := verifySigV4(r, sigV4Secret, sigV4AccessKey); err != nil {
			t.Errorf("independent verifier: %v", err)
			w.WriteHeader(500)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			w.WriteHeader(500)
			return
		}
		h := sha256.Sum256(body)
		if got := r.Header.Get("X-Amz-Content-Sha256"); got != fmt.Sprintf("%x", h[:]) {
			t.Errorf("payload hash=%q", got)
			w.WriteHeader(500)
			return
		}
		if r.Header.Get("X-Amz-Date") == "19990101T000000Z" || r.Header.Get("X-Amz-Security-Token") != sigV4Token {
			t.Error("real signing headers absent")
			w.WriteHeader(500)
			return
		}
		if strings.Contains(strings.Join(r.Header.Values("Authorization"), ""), "DUMMY") {
			t.Error("dummy auth leaked")
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	for _, leg := range []string{"h2", "http/1.1"} {
		t.Run(leg, func(t *testing.T) {
			access, secretKey, token := writeSecret(t, sigV4AccessKey), writeSecret(t, sigV4Secret), writeSecret(t, sigV4Token)
			cfg, err := config.LoadBytes([]byte(fmt.Sprintf(`
[[sigv4]]
host = %q
access_key_id = %q
secret_access_key = %q
session_token = %q
account_id = "123456789012"
service = "s3"
region = "us-east-1"
allowed_methods = ["PUT"]
allowed_operations = ["s3:PutObject"]
allowed_resources = ["arn:aws:s3:::my-bucket/*"]
max_body_bytes = 1024
alpn = %q
`, host+fmt.Sprintf(":%d", serverPort(t, upstream.URL)), "file:"+access, "file:"+secretKey, "file:"+token, leg)))
			if err != nil {
				t.Fatal(err)
			}
			audit, err := NewAuditWriter(filepath.Join(t.TempDir(), "audit.log"))
			if err != nil {
				t.Fatal(err)
			}
			resp, _, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{Leg: leg, Host: host, Port: serverPort(t, upstream.URL), Path: "/object", Method: http.MethodPut, Body: "true body", CoveCA: coveCA, CoveCAPEM: covePEM, Headers: http.Header{"Authorization": {"AWS4-HMAC-SHA256 Credential=AKIDDUMMY/20260315/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + strings.Repeat("0", 64)}, "X-Amz-Date": {"19990101T000000Z"}, "X-Amz-Content-Sha256": {strings.Repeat("0", 64)}, "X-Amz-Security-Token": {"DUMMYSESSIONTOKEN"}}, ProxyAudit: audit, ProxyLog: os.Stderr})
			cleanup()
			_ = audit.Close()
			if resp.StatusCode != http.StatusNoContent {
				t.Fatalf("status=%d", resp.StatusCode)
			}
		})
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits=%d", hits.Load())
	}
}

func TestSigV4SpoolCapAndSecretFailureDoNotDial(t *testing.T) {
	for _, tc := range []struct {
		name, body, ref string
		want            int
	}{{"cap", "too big", "env:AK", http.StatusRequestEntityTooLarge}, {"missing", "ok", "file:/does/not/exist", http.StatusBadGateway}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AK", sigV4AccessKey)
			st := &config.SigV4Stanza{AccessKeyID: tc.ref, SecretAccessKey: "env:SK", Service: "s3", Region: "us-east-1", MaxBodyBytes: 2}
			t.Setenv("SK", sigV4Secret)
			r, _ := http.NewRequest(http.MethodPut, "https://my-bucket.s3.us-east-1.amazonaws.com/object", strings.NewReader(tc.body))
			r.Header.Set("X-Amz-Content-Sha256", strings.Repeat("0", 64))
			called := false
			rt := newSigV4RoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) { called = true; return nil, nil }), &Proxyd{stateDir: t.TempDir(), now: func() time.Time { return sigV4Time }}, nil, st)
			_, err := rt.RoundTrip(r)
			var pe *PolicyError
			if !errors.As(err, &pe) || pe.Status != tc.want || called {
				t.Fatalf("err=%v called=%v", err, called)
			}
		})
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestSigV4NegativeRequestsFailClosedThroughMITM deliberately goes through the
// CONNECT/TLS proxy harness.  Unit classifier tests are useful, but cannot
// prove that a rejected request cannot escape through the MITM engine.
func TestRejectSigV4SemicolonQueryEvasion(t *testing.T) {
	// This direct-boundary check is defense-in-depth: url.ParseQuery itself also
	// rejects semicolon-containing fields. The raw guard deliberately duplicates
	// that rejection before decoded-key scanning, so the case is not presented as
	// isolating behavior that ParseQuery would otherwise allow.
	for _, rawQuery := range []string{"x=1;X-Amz-Signature=x", "x=1;value"} {
		r := httptest.NewRequest("PUT", "https://my-bucket.s3.us-east-1.amazonaws.com/object?"+rawQuery, nil)
		if _, err := url.ParseQuery(rawQuery); err == nil {
			t.Fatalf("ParseQuery unexpectedly accepted %q", rawQuery)
		}
		pe := rejectUnsupportedSigV4Mode(r, false)
		if pe == nil || pe.Status != 400 || pe.Reason != "malformed_request" {
			t.Fatalf("semicolon query %q not rejected: %+v", rawQuery, pe)
		}
	}
	// A well-formed presigned query is still classified precisely.
	r2 := httptest.NewRequest("PUT", "https://my-bucket.s3.us-east-1.amazonaws.com/object?X-Amz-Signature=x", nil)
	if pe := rejectUnsupportedSigV4Mode(r2, false); pe == nil || pe.Reason != "presigned_url" {
		t.Fatalf("well-formed presigned not classified: %+v", pe)
	}
}

func TestSigV4NegativeRequestsFailClosedThroughMITM(t *testing.T) {
	const host = "my-bucket.s3.us-east-1.amazonaws.com"
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, _ := sharedUpstreamTestCA(t)
	var hits atomic.Int32
	upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer upstream.Close()
	port := serverPort(t, upstream.URL)

	valid := func() http.Header {
		return http.Header{
			"Authorization":        {"AWS4-HMAC-SHA256 Credential=AKIDDUMMY/20260315/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256, Signature=00"},
			"X-Amz-Content-Sha256": {strings.Repeat("0", 64)},
		}
	}
	tests := []struct {
		name, path, method, body, reason string
		status                           int
		mutate                           func(http.Header, *config.SigV4Stanza)
	}{
		{"presigned", "/object?X-Amz-Signature=x", "PUT", "", "presigned_url", 400, nil},
		// The ';'-separated presign-evasion case is proven at the guard boundary in
		// TestRejectSigV4SemicolonQueryEvasion instead: Go's HTTP stack drops a
		// ';'-containing query entirely before it reaches the proxy, so it cannot be
		// delivered end-to-end (and, dropped, carries no marker to smuggle anyway).
		{"streaming-payload", "/object", "PUT", "", "streaming_signature", 400, func(h http.Header, _ *config.SigV4Stanza) {
			h.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		}},
		{"streaming-trailer", "/object", "PUT", "", "streaming_signature", 400, func(h http.Header, _ *config.SigV4Stanza) {
			h.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
		}},
		{"streaming-other", "/object", "PUT", "", "streaming_signature", 400, func(h http.Header, _ *config.SigV4Stanza) {
			h.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER")
		}},
		{"aws-chunked", "/object", "PUT", "", "streaming_signature", 400, func(h http.Header, _ *config.SigV4Stanza) { h.Set("Content-Encoding", "aws-chunked") }},
		{"sigv4a", "/object", "PUT", "", "sigv4a", 400, func(h http.Header, _ *config.SigV4Stanza) {
			h.Set("Authorization", "AWS4-ECDSA-P256-SHA256 Credential=AKIDDUMMY/x")
		}},
		{"no-authorization", "/object", "PUT", "", "malformed_request", 400, func(h http.Header, _ *config.SigV4Stanza) { h.Del("Authorization") }},
		{"duplicate-authorization", "/object", "PUT", "", "malformed_request", 400, func(h http.Header, _ *config.SigV4Stanza) {
			h.Add("Authorization", "AWS4-HMAC-SHA256 Credential=OTHER/x")
		}},
		{"unknown-payload", "/object", "PUT", "", "malformed_request", 400, func(h http.Header, _ *config.SigV4Stanza) { h.Set("X-Amz-Content-Sha256", "NOT-A-PAYLOAD-MODE") }},
		{"method", "/object", "GET", "", "policy_method", 403, nil},
		{"resource", "/outside", "PUT", "", "policy_resource", 403, nil},
		{"multipart", "/object?uploads", "PUT", "", "policy_operation", 403, nil},
		{"privilege-header", "/object", "PUT", "", "policy_header", 403, func(h http.Header, _ *config.SigV4Stanza) { h.Set("X-Amz-Acl", "public-read") }},
		{"wrong-region", "/object", "PUT", "", "policy_resource", 403, func(_ http.Header, s *config.SigV4Stanza) { s.Region = "us-west-2" }},
		{"body-cap", "/object", "PUT", "too-big", "body_too_large", 413, func(_ http.Header, s *config.SigV4Stanza) { s.MaxBodyBytes = 2 }},
		{"missing-secret", "/object", "PUT", "", "secret_unavailable", 502, func(_ http.Header, s *config.SigV4Stanza) { s.SecretAccessKey = "file:/definitely/missing-cove-secret" }},
		{"missing-session-token", "/object", "PUT", "", "secret_unavailable", 502, func(_ http.Header, s *config.SigV4Stanza) { s.SessionToken = "file:" + writeSecret(t, "") }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Isolate the shared upstream hit counter per subtest so a single
			// upstream-contacting failure cannot cascade false failures into
			// later subtests.
			hits.Store(0)
			access, key := writeSecret(t, sigV4AccessKey), writeSecret(t, sigV4Secret)
			cfg, err := config.LoadBytes([]byte(fmt.Sprintf(`
[[sigv4]]
host = %q
access_key_id = %q
secret_access_key = %q
account_id = "123456789012"
service = "s3"
region = "us-east-1"
allowed_methods = ["PUT"]
allowed_operations = ["s3:PutObject"]
allowed_resources = ["arn:aws:s3:::my-bucket/object"]
max_body_bytes = 1024
alpn = "http/1.1"
`, fmt.Sprintf("%s:%d", host, port), "file:"+access, "file:"+key)))
			if err != nil {
				t.Fatal(err)
			}
			headers := valid()
			if tc.mutate != nil {
				tc.mutate(headers, &cfg.SigV4[0])
			}
			auditPath := filepath.Join(t.TempDir(), "audit.log")
			audit, err := NewAuditWriter(auditPath)
			if err != nil {
				t.Fatal(err)
			}
			resp, _, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{Leg: "http/1.1", Host: host, Port: port, Path: tc.path, Method: tc.method, Body: tc.body, Headers: headers, CoveCA: coveCA, CoveCAPEM: covePEM, ProxyAudit: audit})
			cleanup()
			_ = audit.Close()
			if resp.StatusCode != tc.status {
				t.Fatalf("status=%d, want %d", resp.StatusCode, tc.status)
			}
			recs := readAuditRecords(t, auditPath)
			if len(recs) != 1 || recs[0].Policy != "deny" || recs[0].Reason != tc.reason {
				t.Fatalf("audit=%+v, want one deny/%s", recs, tc.reason)
			}
			if got := hits.Load(); got != 0 {
				t.Fatalf("upstream hits=%d, want 0", got)
			}
		})
	}
}
