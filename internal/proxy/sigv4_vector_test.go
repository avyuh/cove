package proxy

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	sigV4AccessKey = "AKIDEXAMPLE"
	sigV4Secret    = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	sigV4Token     = "fake-session-token-for-cove-tests"
)

var sigV4Time = time.Date(2026, 3, 15, 12, 0, 0, 0, time.UTC)
var sigV4GoldenTime = time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)

func TestSigV4VerifyVectors(t *testing.T) {
	// Immutable fixtures from AWS's published aws-sig-v4-test-suite. Keeping the
	// expected canonical request, string-to-sign, and signature here means the
	// SDK signer and our independent verifier cannot merely agree on a shared bug.
	tests := []struct {
		name, method, target, body                string
		headers                                   [][2]string
		canonicalRequest, stringToSign, signature string
	}{
		{
			name: "get-vanilla", method: "GET", target: "/",
			canonicalRequest: "GET\n/\n\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\nhost;x-amz-date\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			stringToSign:     "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nbb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63",
			signature:        "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
		},
		{
			name: "post-x-www-form-urlencoded", method: "POST", target: "/", body: "Param1=value1",
			headers:          [][2]string{{"Content-Type", "application/x-www-form-urlencoded"}},
			canonicalRequest: "POST\n/\n\ncontent-type:application/x-www-form-urlencoded\nhost:example.amazonaws.com\nx-amz-date:20150830T123600Z\n\ncontent-type;host;x-amz-date\n9095672bbd1f56dfc5b65f3e153adc8731a4a654192329106275f4c7b24d0b6e",
			stringToSign:     "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\n42a5e5bb34198acb3e84da4f085bb7927f2bc277ca766e6d19c73c2154021281",
			signature:        "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := sigV4GoldenRequest(t, tt.method, tt.target, tt.body, tt.headers)
			signSigV4Golden(t, r)
			got, err := verifySigV4(r, sigV4Secret, sigV4AccessKey)
			if err != nil {
				t.Fatalf("official signer output failed independent verifier: %v", err)
			}
			if got.CanonicalRequest != tt.canonicalRequest || got.StringToSign != tt.stringToSign || got.Signature != tt.signature {
				t.Fatalf("immutable AWS vector mismatch\ncanonical got: %q\nwant: %q\nstring-to-sign got: %q\nwant: %q\nsignature got: %s\nwant: %s", got.CanonicalRequest, tt.canonicalRequest, got.StringToSign, tt.stringToSign, got.Signature, tt.signature)
			}
			if !strings.HasSuffix(r.Header.Get("Authorization"), "Signature="+tt.signature) {
				t.Fatalf("official signer signature=%q, want %q", r.Header.Get("Authorization"), tt.signature)
			}
		})
	}
}

func TestSigV4VerifierRejectsMutations(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*http.Request)
	}{
		{"method", func(r *http.Request) { r.Method = http.MethodPut }},
		{"path", func(r *http.Request) { r.URL.Path = "/changed" }},
		{"query", func(r *http.Request) { r.URL.RawQuery = "item=changed" }},
		{"signed-header", func(r *http.Request) { r.Header.Set("X-Test", "changed") }},
		{"body", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("tampered"))
			r.ContentLength = int64(len("tampered"))
		}},
		{"access-key-id", func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "Credential="+sigV4AccessKey, "Credential=WRONGAKID", 1))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := sigV4Request(t, http.MethodPost, "/object?item=original", "original", [][2]string{{"X-Test", "original"}})
			signSigV4At(t, r, "service", false, sigV4GoldenTime)
			if _, err := verifySigV4(r, sigV4Secret, sigV4AccessKey); err != nil {
				t.Fatalf("unmodified signed request did not verify: %v", err)
			}
			tt.mutate(r)
			if _, err := verifySigV4(r, sigV4Secret, sigV4AccessKey); err == nil {
				t.Fatal("tampered request verified")
			}
		})
	}
}

func TestSigV4VerifyDifferential(t *testing.T) {
	for _, target := range []string{
		"/space%20here", "/encoded%2Fslash", "/plus+sign", "/%E1%88%B4/%E3%81%82",
		"/query?z=2&z=1&empty=&space=a%20b&plus=a+b", "/a/../b", "/double//slash",
	} {
		t.Run(target, func(t *testing.T) {
			r := sigV4Request(t, "GET", target, "", nil)
			signSigV4(t, r, "s3", true)
			if _, err := verifySigV4(r, sigV4Secret, sigV4AccessKey); err != nil {
				t.Fatalf("LOUD SigV4 signer/verifier disagreement for %q: %v; reject this path shape in card 7B", target, err)
			}
		})
	}
}

func sigV4GoldenRequest(t *testing.T, method, target, body string, headers [][2]string) *http.Request {
	t.Helper()
	u, err := url.Parse("https://example.amazonaws.com" + target)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(method, u.String(), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = u.Host
	// The AWS suite's published Authorization fixture does not sign Content-Length.
	// Keep this request's body while suppressing Go's automatic length header so
	// the official v2 signer is evaluated against that exact fixture shape.
	r.ContentLength = -1
	for _, h := range headers {
		r.Header.Add(h[0], h[1])
	}
	return r
}

func sigV4Request(t *testing.T, method, target, body string, headers [][2]string) *http.Request {
	t.Helper()
	u, err := url.Parse("https://example.amazonaws.com" + target)
	if err != nil {
		t.Fatal(err)
	}
	r, err := http.NewRequest(method, u.String(), strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	r.Host = u.Host
	payload := sha256.Sum256([]byte(body))
	r.Header.Set("X-Amz-Content-Sha256", fmt.Sprintf("%x", payload))
	for _, h := range headers {
		r.Header.Add(h[0], h[1])
	}
	return r
}

func signSigV4(t *testing.T, r *http.Request, service string, s3 bool) {
	signSigV4At(t, r, service, s3, sigV4Time)
}

func signSigV4At(t *testing.T, r *http.Request, service string, s3 bool, when time.Time) {
	t.Helper()
	if s3 {
		r.URL.Opaque = "//" + r.Host + r.URL.EscapedPath()
	}
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: sigV4AccessKey, SecretAccessKey: sigV4Secret, SessionToken: sigV4Token}, r, r.Header.Get("X-Amz-Content-Sha256"), service, "us-east-1", when, func(o *v4.SignerOptions) { o.DisableURIPathEscaping = s3 }); err != nil {
		t.Fatal(err)
	}
}

func signSigV4Golden(t *testing.T, r *http.Request) {
	t.Helper()
	payload, err := sigV4PayloadHash(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{AccessKeyID: sigV4AccessKey, SecretAccessKey: sigV4Secret}, r, payload, "service", "us-east-1", sigV4GoldenTime, func(*v4.SignerOptions) {}); err != nil {
		t.Fatal(err)
	}
}
