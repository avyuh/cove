package proxy

// This file intentionally does not import the AWS Go SDK. It is an independent,
// test-only verifier used to cross-check signatures produced by the official SDK.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type sigV4Verification struct {
	CanonicalRequest string
	StringToSign     string
	Signature        string
}

// verifySigV4 independently rebuilds the AWS4-HMAC-SHA256 signature from the
// request as received. The request's X-Amz-Date is deliberately authoritative.
func verifySigV4(r *http.Request, secret, expectedAccessKey string) (sigV4Verification, error) {
	auth := r.Header.Get("Authorization")
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(auth, prefix) {
		return sigV4Verification{}, fmt.Errorf("missing AWS4-HMAC-SHA256 authorization")
	}
	parts := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(auth, prefix), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			parts[kv[0]] = kv[1]
		}
	}
	credential, signed, received := parts["Credential"], parts["SignedHeaders"], parts["Signature"]
	scope := strings.Split(credential, "/")
	if len(scope) != 5 || scope[0] != expectedAccessKey || scope[4] != "aws4_request" || signed == "" || received == "" {
		return sigV4Verification{}, fmt.Errorf("malformed authorization")
	}
	timestamp := r.Header.Get("X-Amz-Date")
	if len(timestamp) < 8 || timestamp[:8] != scope[1] {
		return sigV4Verification{}, fmt.Errorf("invalid X-Amz-Date")
	}
	payload := r.Header.Get("X-Amz-Content-Sha256")
	actualPayload, err := sigV4PayloadHash(r)
	if err != nil {
		return sigV4Verification{}, err
	}
	if payload == "" {
		payload = actualPayload
	} else if payload != "UNSIGNED-PAYLOAD" && !strings.HasPrefix(payload, "STREAMING-") && payload != actualPayload {
		return sigV4Verification{}, fmt.Errorf("payload hash mismatch")
	}
	canonicalHeaders, err := sigV4CanonicalHeaders(r, strings.Split(signed, ";"))
	if err != nil {
		return sigV4Verification{}, err
	}
	canonical := strings.Join([]string{
		r.Method,
		sigV4CanonicalPath(r.URL, scope[3]),
		sigV4CanonicalQuery(r.URL.RawQuery),
		canonicalHeaders,
		signed,
		payload,
	}, "\n")
	h := sha256.Sum256([]byte(canonical))
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", timestamp, strings.Join(scope[1:], "/"), hex.EncodeToString(h[:])}, "\n")
	kDate := sigV4HMAC([]byte("AWS4"+secret), scope[1])
	kRegion := sigV4HMAC(kDate, scope[2])
	kService := sigV4HMAC(kRegion, scope[3])
	want := hex.EncodeToString(sigV4HMAC(sigV4HMAC(kService, "aws4_request"), stringToSign))
	if _, err := hex.DecodeString(received); err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(received)) != 1 {
		return sigV4Verification{}, fmt.Errorf("signature mismatch")
	}
	return sigV4Verification{CanonicalRequest: canonical, StringToSign: stringToSign, Signature: want}, nil
}

// sigV4PayloadHash preserves r.Body so the same independently verified request
// can continue to the test handler. It makes body-tampering tests meaningful.
func sigV4PayloadHash(r *http.Request) (string, error) {
	if r.Body == nil {
		h := sha256.Sum256(nil)
		return hex.EncodeToString(h[:]), nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("read payload: %w", err)
	}
	if err := r.Body.Close(); err != nil {
		return "", fmt.Errorf("close payload: %w", err)
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	h := sha256.Sum256(body)
	return hex.EncodeToString(h[:]), nil
}

func sigV4HMAC(key []byte, text string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(text))
	return h.Sum(nil)
}

func sigV4CanonicalPath(u *url.URL, service string) string {
	p := u.EscapedPath()
	if p == "" {
		return "/"
	}
	if service != "s3" {
		// Generic SigV4 signs a once-more escaped raw path; S3 deliberately does
		// not, per AWS's S3-specific DisableURIPathEscaping option.
		return strings.ReplaceAll(sigV4Escape(p), "%2F", "/")
	}
	return p
}

func sigV4CanonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	pairs := make([]string, 0, strings.Count(raw, "&")+1)
	for _, field := range strings.Split(raw, "&") {
		kv := strings.SplitN(field, "=", 2)
		key, _ := url.QueryUnescape(kv[0])
		value := ""
		if len(kv) == 2 {
			value, _ = url.QueryUnescape(kv[1])
		}
		pairs = append(pairs, sigV4Escape(key)+"="+sigV4Escape(value))
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func sigV4Escape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func sigV4CanonicalHeaders(r *http.Request, names []string) (string, error) {
	var b strings.Builder
	for _, name := range names {
		name = strings.ToLower(name)
		var values []string
		if name == "host" {
			values = []string{r.Host}
		} else if name == "content-length" && r.ContentLength > 0 {
			values = []string{strconv.FormatInt(r.ContentLength, 10)}
		} else {
			values = r.Header.Values(name)
		}
		if len(values) == 0 {
			return "", fmt.Errorf("signed header %q missing", name)
		}
		for i := range values {
			values[i] = strings.Join(strings.Fields(values[i]), " ")
		}
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(values, ","))
		b.WriteByte('\n')
	}
	return b.String(), nil
}
