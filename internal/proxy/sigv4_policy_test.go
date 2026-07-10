package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cove/internal/config"
)

const sigPolicyAuthorization = "AWS4-HMAC-SHA256 Credential=AKIDDUMMY/20260315/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0000000000000000000000000000000000000000000000000000000000000000"

func sigPolicyRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	r, err := http.NewRequest(method, "https://bucket.s3.us-east-1.amazonaws.com"+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Host = "bucket.s3.us-east-1.amazonaws.com"
	r.Header.Set("Authorization", sigPolicyAuthorization)
	r.Header.Set("X-Amz-Content-Sha256", strings.Repeat("0", 64))
	return r
}

func TestRejectUnsupportedSigV4Mode(t *testing.T) {
	tests := []struct{ name, target, header, value, reason string }{
		{"presigned-algorithm", "/x?x-AmZ-aLgOrItHm=AWS4-HMAC-SHA256", "", "", "presigned_url"},
		{"presigned-credential", "/x?X-Amz-Credential=x", "", "", "presigned_url"},
		{"presigned-signature", "/x?X-Amz-Signature=x", "", "", "presigned_url"},
		{"presigned-signedheaders", "/x?X-Amz-SignedHeaders=host", "", "", "presigned_url"},
		{"presigned-expires", "/x?X-Amz-Expires=60", "", "", "presigned_url"},
		{"sigv4a", "/x", "Authorization", "AWS4-ECDSA-P256-SHA256 Credential=x", "sigv4a"},
		{"streaming-payload", "/x", "X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "streaming_signature"},
		{"streaming-trailer", "/x", "X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER", "streaming_signature"},
		{"aws-chunked", "/x", "Content-Encoding", "gzip, aws-chunked", "streaming_signature"},
		{"trailer", "/x", "X-Amz-Trailer", "x-amz-checksum-crc32", "streaming_signature"},
		{"decoded-length", "/x", "X-Amz-Decoded-Content-Length", "3", "streaming_signature"},
		{"chunk-marker", "/x", "X-Amz-Chunk-Signature", "x", "streaming_signature"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := sigPolicyRequest(t, http.MethodPut, tt.target)
			if tt.header != "" {
				r.Header.Set(tt.header, tt.value)
			}
			pe := rejectUnsupportedSigV4Mode(r)
			if pe == nil || pe.Status != http.StatusBadRequest || pe.Reason != tt.reason {
				t.Fatalf("got %#v", pe)
			}
		})
	}
	r := sigPolicyRequest(t, http.MethodGet, "/x")
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	if pe := rejectUnsupportedSigV4Mode(r); pe == nil || pe.Reason != "streaming_signature" {
		t.Fatalf("websocket got %#v", pe)
	}
	if pe := rejectUnsupportedSigV4Mode(sigPolicyRequest(t, http.MethodGet, "/x")); pe != nil {
		t.Fatalf("well-formed authorization was rejected: %#v", pe)
	}
}

func TestSigV4MalformedQueryAndAuthFormsFailBeforeSecretsOrDial(t *testing.T) {
	tests := []struct {
		name   string
		target string
		mutate func(*http.Request)
		reason string
	}{
		{name: "malformed presigned query", target: "/object?x=1;X-Amz-Signature=abc", reason: "malformed_request"},
		{name: "decoded presigned key", target: "/object?X-Amz-%53ignature=abc", reason: "presigned_url"},
		{name: "too many query parameters", target: "/object?" + strings.Repeat("x=&", maxSigV4QueryParameters) + "x=", reason: "malformed_request"},
		{name: "no authorization", target: "/object", mutate: func(r *http.Request) { r.Header.Del("Authorization") }, reason: "malformed_request"},
		{name: "bearer", target: "/object", mutate: func(r *http.Request) { r.Header.Set("Authorization", "Bearer dummy") }, reason: "malformed_request"},
		{name: "malformed aws4", target: "/object", mutate: func(r *http.Request) { r.Header.Set("Authorization", "AWS4-HMAC-SHA256 garbage") }, reason: "malformed_request"},
		{name: "missing signed headers", target: "/object", mutate: func(r *http.Request) {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDDUMMY/20260315/us-east-1/s3/aws4_request, Signature=00")
		}, reason: "malformed_request"},
		{name: "missing signature", target: "/object", mutate: func(r *http.Request) {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDDUMMY/20260315/us-east-1/s3/aws4_request, SignedHeaders=host")
		}, reason: "malformed_request"},
		{name: "foreign trailing token", target: "/object", mutate: func(r *http.Request) { r.Header.Set("Authorization", sigPolicyAuthorization+", Bearer ignored") }, reason: "malformed_request"},
		{name: "skeletal foreign token", target: "/object", mutate: func(r *http.Request) { r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=x, Bearer ignored") }, reason: "malformed_request"},
		{name: "malformed credential scope", target: "/object", mutate: func(r *http.Request) {
			r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIDDUMMY/20260315/us-east-1/s3, SignedHeaders=host, Signature=00")
		}, reason: "malformed_request"},
		{name: "duplicate authorization", target: "/object", mutate: func(r *http.Request) { r.Header.Add("Authorization", "AWS4-HMAC-SHA256 Credential=OTHER/scope") }, reason: "malformed_request"},
		{name: "unknown content sha256", target: "/object", mutate: func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "NOT-A-PAYLOAD-MODE") }, reason: "malformed_request"},
		{name: "uppercase content sha256", target: "/object", mutate: func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", strings.Repeat("A", 64)) }, reason: "malformed_request"},
		{name: "unsigned without opt in", target: "/object", mutate: func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD") }, reason: "malformed_request"},
		{name: "duplicate content sha256", target: "/object", mutate: func(r *http.Request) { r.Header.Add("X-Amz-Content-Sha256", strings.Repeat("1", 64)) }, reason: "malformed_request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := sigPolicyRequest(t, http.MethodPut, tt.target)
			if tt.mutate != nil {
				tt.mutate(r)
			}
			stanza := &config.SigV4Stanza{
				AccessKeyID:       "file:/must-not-be-resolved",
				SecretAccessKey:   "file:/must-not-be-resolved",
				AccountID:         "123456789012",
				Service:           "s3",
				Region:            "us-east-1",
				AllowedMethods:    []string{http.MethodPut},
				AllowedOperations: []string{"s3:PutObject"},
				AllowedResources:  []string{"arn:aws:s3:::bucket/*"},
				MaxBodyBytes:      1024,
			}
			dialed := false
			transport := newSigV4RoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
				dialed = true
				return nil, errors.New("unexpected dial")
			}), &Proxyd{stateDir: t.TempDir(), now: func() time.Time { return sigV4Time }}, nil, stanza)
			_, err := (authorizingRoundTripper{transport: transport, auth: sigV4Authorizer{target: Target{Host: r.Host, Port: 443}, stanza: stanza}}).RoundTrip(r)
			var pe *PolicyError
			if !errors.As(err, &pe) || pe.Status != http.StatusBadRequest || pe.Reason != tt.reason {
				t.Fatalf("error = %#v, want 400 %s", err, tt.reason)
			}
			if dialed {
				t.Fatal("upstream transport was called")
			}
		})
	}
}

func TestInferS3Endpoint(t *testing.T) {
	for _, tt := range []struct {
		host, region, bucket string
		virtual              bool
		ok                   bool
	}{
		{"s3.amazonaws.com", "us-east-1", "", false, true}, {"s3.eu-west-1.amazonaws.com", "eu-west-1", "", false, true},
		{"bucket.s3.us-east-1.amazonaws.com", "us-east-1", "bucket", true, true}, {"*.s3.us-east-1.amazonaws.com", "us-east-1", "", true, true},
		{"s3.dualstack.us-east-1.amazonaws.com", "", "", false, false}, {"bucket.s3-accelerate.amazonaws.com", "", "", false, false},
		{"s3.us-gov-west-1.amazonaws.com", "", "", false, false}, {"s3.cn-north-1.amazonaws.com", "", "", false, false},
		{"s3.us-iso-east-1.amazonaws.com", "", "", false, false}, {"s3.us-isob-east-1.amazonaws.com", "", "", false, false},
		{"bucket.s3.dualstack.us-east-1.amazonaws.com", "", "", false, false}, {"s3-fips.us-east-1.amazonaws.com", "", "", false, false},
		{"ap.s3-accesspoint.us-east-1.amazonaws.com", "", "", false, false}, {"ap.s3-outposts.us-east-1.amazonaws.com", "", "", false, false},
		{"name.mrap.accesspoint.s3-global.amazonaws.com", "", "", false, false}, {"s3-control.us-east-1.amazonaws.com", "", "", false, false},
	} {
		t.Run(tt.host, func(t *testing.T) {
			got, err := inferS3Endpoint(tt.host)
			if (err == nil) != tt.ok || got.Region != tt.region || got.Bucket != tt.bucket || got.VirtualHost != tt.virtual {
				t.Fatalf("got %#v, %v", got, err)
			}
		})
	}
}

func TestClassifyS3WriteHeadersClosed(t *testing.T) {
	virtual, _ := inferS3Endpoint("bucket.s3.us-east-1.amazonaws.com")
	privileged := []struct {
		method string
		name   string
		value  string
	}{
		{http.MethodPut, "X-Amz-Acl", "public-read"},
		{http.MethodPut, "X-Amz-Grant-Read", "uri=everyone"},
		{http.MethodPut, "X-Amz-Tagging", "role=admin"},
		{http.MethodPut, "X-Amz-Object-Lock-Mode", "GOVERNANCE"},
		{http.MethodPut, "X-Amz-Object-Lock-Retain-Until-Date", "2099-01-01T00:00:00Z"},
		{http.MethodPut, "X-Amz-Object-Lock-Legal-Hold", "ON"},
		{http.MethodPut, "X-Amz-Legal-Hold", "ON"},
		{http.MethodPut, "X-Amz-Website-Redirect-Location", "/admin"},
		{http.MethodPut, "X-Amz-Server-Side-Encryption", "aws:kms"},
		{http.MethodPut, "X-Amz-Server-Side-Encryption-Aws-Kms-Key-Id", "alias/admin"},
		{http.MethodPut, "X-Amz-Server-Side-Encryption-Context", "e30="},
		{http.MethodPut, "X-Amz-Unmodeled-Privilege", "true"},
		{http.MethodDelete, "X-Amz-Bypass-Governance-Retention", "true"},
	}
	for _, tt := range privileged {
		t.Run(tt.method+"/"+tt.name, func(t *testing.T) {
			r := sigPolicyRequest(t, tt.method, "/object")
			r.Header.Set(tt.name, tt.value)
			stanza := &config.SigV4Stanza{
				Region: "us-east-1", Service: "s3", AccountID: "123456789012", MaxBodyBytes: 1024,
				AllowedMethods: []string{tt.method}, AllowedOperations: []string{"s3:PutObject", "s3:DeleteObject"}, AllowedResources: []string{"arn:aws:s3:::bucket/*"},
			}
			dialed := false
			transport := newSigV4RoundTripper(roundTripFunc(func(*http.Request) (*http.Response, error) {
				dialed = true
				return nil, errors.New("unexpected dial")
			}), &Proxyd{stateDir: t.TempDir()}, nil, stanza)
			_, err := (authorizingRoundTripper{transport: transport, auth: sigV4Authorizer{target: Target{Host: r.Host, Port: 443}, stanza: stanza}}).RoundTrip(r)
			var pe *PolicyError
			if !errors.As(err, &pe) || pe.Status != http.StatusForbidden || pe.Reason != "policy_header" {
				t.Fatalf("error = %#v, want 403 policy_header", err)
			}
			if dialed {
				t.Fatal("upstream transport was called")
			}
		})
	}

	stanza := &config.SigV4Stanza{
		Region: "us-east-1", Service: "s3", AccountID: "123456789012",
		AllowedMethods: []string{http.MethodPut}, AllowedOperations: []string{"s3:PutObject"}, AllowedResources: []string{"arn:aws:s3:::bucket/*"},
	}
	functional := []struct {
		name    string
		headers http.Header
	}{
		{name: "ordinary object headers", headers: http.Header{
			"Content-Type":                 {"application/octet-stream"},
			"X-Amz-Meta-Project":           {"cove"},
			"X-Amz-Storage-Class":          {"STANDARD_IA"},
			"X-Amz-Server-Side-Encryption": {"AES256"},
		}},
		{name: "SDK checksum", headers: http.Header{
			"X-Amz-Sdk-Checksum-Algorithm": {"CRC32"},
			"X-Amz-Checksum-Crc32":         {"AAAAAA=="},
		}},
		{name: "expected bucket owner", headers: http.Header{
			"X-Amz-Expected-Bucket-Owner": {"123456789012"},
		}},
	}
	for _, tt := range functional {
		t.Run(tt.name, func(t *testing.T) {
			r := sigPolicyRequest(t, http.MethodPut, "/object")
			for name, values := range tt.headers {
				r.Header[name] = values
			}
			got, pe := classifyS3Request(r, virtual)
			if pe != nil || got.Operation != "s3:PutObject" {
				t.Fatalf("legitimate PUT = %#v, %#v", got, pe)
			}
			if _, err := authorizeSigV4Policy(r, Target{Host: r.Host, Port: 443}, stanza); err != nil {
				t.Fatalf("legitimate PUT did not pass policy: %v", err)
			}
		})
	}
}

func TestClassifyS3Request(t *testing.T) {
	virtual, _ := inferS3Endpoint("bucket.s3.us-east-1.amazonaws.com")
	pathStyle, _ := inferS3Endpoint("s3.us-east-1.amazonaws.com")
	tests := []struct {
		name, method, target, op, resource, reason string
		endpoint                                   s3Endpoint
	}{
		{"get-virtual", "GET", "/project/a", "s3:GetObject", "arn:aws:s3:::bucket/project/a", "", virtual},
		{"head", "HEAD", "/project/a", "s3:HeadObject", "arn:aws:s3:::bucket/project/a", "", virtual},
		{"put", "PUT", "/project/a", "s3:PutObject", "arn:aws:s3:::bucket/project/a", "", virtual},
		{"delete", "DELETE", "/project/a", "s3:DeleteObject", "arn:aws:s3:::bucket/project/a", "", virtual},
		{"list-empty", "GET", "/", "s3:ListBucket", "arn:aws:s3:::bucket", "", virtual},
		{"list-v2", "GET", "/?list-type=2&prefix=x&max-keys=2", "s3:ListBucket", "arn:aws:s3:::bucket", "", virtual},
		{"path-style", "GET", "/other/key", "s3:GetObject", "arn:aws:s3:::other/key", "", pathStyle},
		{"unknown-list-query", "GET", "/?acl", "", "", "policy_operation", virtual},
		{"multipart", "PUT", "/x?uploads", "", "", "policy_operation", virtual},
		{"bucket-delete", "DELETE", "/", "", "", "policy_operation", virtual},
		{"encoded-slash", "GET", "/a%2Fb", "", "", "policy_resource", virtual},
		{"encoded-backslash", "GET", "/a%5Cb", "", "", "policy_resource", virtual},
		{"post", "POST", "/a", "", "", "policy_method", virtual},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := sigPolicyRequest(t, tt.method, tt.target)
			got, pe := classifyS3Request(r, tt.endpoint)
			if tt.reason != "" {
				if pe == nil || pe.Reason != tt.reason {
					t.Fatalf("got %#v, %#v", got, pe)
				}
				return
			}
			if pe != nil || got.Operation != tt.op || got.Resource != tt.resource {
				t.Fatalf("got %#v, %#v", got, pe)
			}
		})
	}
	r := sigPolicyRequest(t, http.MethodPut, "/dst")
	r.Header.Set("X-Amz-Copy-Source", "/source-bucket/source/key")
	got, pe := classifyS3Request(r, virtual)
	if pe != nil || got.Operation != "s3:CopyObject" || got.SourceResource != "arn:aws:s3:::source-bucket/source/key" {
		t.Fatalf("got %#v, %#v", got, pe)
	}
}

func TestMatchS3ResourceAndPolicy(t *testing.T) {
	allowed := []string{"arn:aws:s3:::bucket/project/*", "arn:aws:s3:::bucket/exact", "arn:aws:s3:::bucket"}
	for _, tt := range []struct {
		resource string
		want     bool
	}{
		{"arn:aws:s3:::bucket/project/a", true}, {"arn:aws:s3:::bucket/project/", true}, {"arn:aws:s3:::bucket/projectx/a", false}, {"arn:aws:s3:::bucket/exact", true}, {"arn:aws:s3:::bucket", true}, {"arn:aws:s3:::other/project/a", false},
	} {
		if got := matchS3Resource(tt.resource, allowed); got != tt.want {
			t.Fatalf("%q: got %v", tt.resource, got)
		}
	}

	st := &config.SigV4Stanza{Region: "us-east-1", Service: "s3", AccountID: "123456789012", AllowedMethods: []string{"PUT"}, AllowedOperations: []string{"s3:CopyObject"}, AllowedResources: []string{"arn:aws:s3:::bucket/*", "arn:aws:s3:::source/*"}}
	r := sigPolicyRequest(t, http.MethodPut, "/dst")
	r.Header.Set("X-Amz-Copy-Source", "/source/key")
	if _, err := authorizeSigV4Policy(r, Target{Host: r.Host, Port: 443}, st); err != nil {
		t.Fatal(err)
	}
	r.Header.Set("X-Amz-Copy-Source", "/outside/key")
	if _, err := authorizeSigV4Policy(r, Target{Host: r.Host, Port: 443}, st); err == nil {
		t.Fatal("copy source outside policy was accepted")
	}
}

func TestSigV4SpoolFailureAuditsLocalDenyWithoutDial(t *testing.T) {
	const host = "bucket.s3.us-east-1.amazonaws.com"
	blockedState := filepath.Join(t.TempDir(), "state-is-a-file")
	if err := os.WriteFile(blockedState, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", blockedState)
	coveCA, covePEM, _ := newTestCA(t)
	upstreamCA, _ := sharedUpstreamTestCA(t)
	var hits atomic.Int32
	upstream := newInjectUpstream(t, upstreamCA, host, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()
	port := serverPort(t, upstream.URL)
	cfg, err := config.LoadBytes([]byte(fmt.Sprintf(`
[[sigv4]]
host = %q
access_key_id = "env:UNUSED_ACCESS"
secret_access_key = "env:UNUSED_SECRET"
account_id = "123456789012"
service = "s3"
region = "us-east-1"
allowed_methods = ["PUT"]
allowed_operations = ["s3:PutObject"]
allowed_resources = ["arn:aws:s3:::bucket/*"]
max_body_bytes = 1024
alpn = "http/1.1"
`, fmt.Sprintf("%s:%d", host, port))))
	if err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(t.TempDir(), "audit.log")
	audit, err := NewAuditWriter(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	resp, _, cleanup := requestThroughInjectConfig(t, cfg, injectRequest{
		Leg: "http/1.1", Host: host, Port: port, Path: "/object", Method: http.MethodPut, Body: "body",
		CoveCA: coveCA, CoveCAPEM: covePEM, ProxyAudit: audit,
		Headers: http.Header{"Authorization": {sigPolicyAuthorization}, "X-Amz-Content-Sha256": {strings.Repeat("0", 64)}},
	})
	cleanup()
	_ = audit.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hits = %d, want 0", hits.Load())
	}
	recs := readAuditRecords(t, auditPath)
	if len(recs) != 1 || recs[0].Policy != "deny" || recs[0].Reason != "spool_failure" {
		t.Fatalf("audit records = %+v", recs)
	}
}

func TestEarlyRejectionIsCredentialFree(t *testing.T) {
	// The core accepts no resolver or transport. This regression test keeps the
	// required ordering explicit: every rejection returns before policy success.
	for _, target := range []string{"/x?X-Amz-Signature=x", "/x"} {
		r := sigPolicyRequest(t, "PUT", target)
		if target == "/x" {
			r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		}
		if pe := rejectUnsupportedSigV4Mode(r); pe == nil {
			t.Fatalf("%q was not rejected", target)
		}
	}
}
