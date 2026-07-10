package proxy

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"cove/internal/config"
	"cove/internal/secret"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsv4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// s3Endpoint is the unambiguous S3 endpoint information needed to turn an
// HTTP request into an S3 resource.  It intentionally supports only the
// endpoint spellings accepted by config validation.
type s3Endpoint struct {
	Region      string
	Bucket      string
	VirtualHost bool
}

const maxSigV4QueryParameters = 1024

// rejectUnsupportedSigV4Mode rejects modes whose signature cannot be safely
// replaced by a single header SigV4 signature.  It must run before credentials
// are resolved or an upstream transport is invoked.
func rejectUnsupportedSigV4Mode(req *http.Request, unsignedAllowed ...bool) *PolicyError {
	if req == nil || req.URL == nil {
		return sigV4MalformedRequest()
	}
	// A ';' in the raw query is not a valid SigV4 request separator; url.ParseQuery
	// folds it into a value rather than surfacing following keys, which would let a
	// presign marker (e.g. "?x=1;X-Amz-Signature=...") evade the decoded-key scan
	// below. Reject it outright before any classification/signing.
	if strings.Contains(req.URL.RawQuery, ";") {
		return sigV4MalformedRequest()
	}
	if raw := req.URL.RawQuery; raw != "" && strings.Count(raw, "&")+1 > maxSigV4QueryParameters {
		return sigV4MalformedRequest()
	}
	query, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return sigV4MalformedRequest()
	}
	parameterCount := 0
	for key, values := range query {
		parameterCount += len(values)
		if parameterCount > maxSigV4QueryParameters {
			return sigV4MalformedRequest()
		}
		switch strings.ToLower(key) {
		case "x-amz-algorithm", "x-amz-credential", "x-amz-signature", "x-amz-signedheaders", "x-amz-expires":
			return &PolicyError{Status: http.StatusBadRequest, Reason: "presigned_url", AuthMode: "sigv4"}
		}
	}
	authorizations := req.Header.Values("Authorization")
	for _, authorization := range authorizations {
		if strings.HasPrefix(strings.TrimSpace(authorization), "AWS4-ECDSA-P256-SHA256") {
			return &PolicyError{Status: http.StatusBadRequest, Reason: "sigv4a", AuthMode: "sigv4"}
		}
	}
	payloadModes := req.Header.Values("X-Amz-Content-Sha256")
	hasTrailer := headerPresentFold(req.Header, "X-Amz-Trailer")
	hasDecodedLength := headerPresentFold(req.Header, "X-Amz-Decoded-Content-Length")
	if containsStreamingPayloadMode(payloadModes) ||
		headerContainsToken(req.Header.Values("Content-Encoding"), "aws-chunked") ||
		hasTrailer || hasDecodedLength ||
		hasStreamingMarker(req.Header) || isWebSocketUpgrade(req) {
		return &PolicyError{Status: http.StatusBadRequest, Reason: "streaming_signature", AuthMode: "sigv4"}
	}
	if len(authorizations) != 1 || !validSigV4Authorization(authorizations[0]) {
		return sigV4MalformedRequest()
	}
	if len(payloadModes) != 1 {
		return sigV4MalformedRequest()
	}
	allowUnsigned := len(unsignedAllowed) != 0 && unsignedAllowed[0]
	if !validSigV4PayloadMode(payloadModes[0], allowUnsigned) {
		return sigV4MalformedRequest()
	}
	return nil
}

func sigV4MalformedRequest() *PolicyError {
	return &PolicyError{Status: http.StatusBadRequest, Reason: "malformed_request", AuthMode: "sigv4"}
}

func containsStreamingPayloadMode(values []string) bool {
	for _, value := range values {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(value)), "STREAMING-") {
			return true
		}
	}
	return false
}

func validSigV4Authorization(value string) bool {
	const scheme = "AWS4-HMAC-SHA256"
	value = strings.TrimSpace(value)
	gotScheme, parameters, ok := strings.Cut(value, " ")
	if !ok || gotScheme != scheme {
		return false
	}
	parts := strings.Split(strings.TrimSpace(parameters), ",")
	if len(parts) != 3 {
		return false
	}
	values := make([]string, len(parts))
	for i, name := range []string{"Credential", "SignedHeaders", "Signature"} {
		key, parameter, ok := strings.Cut(strings.TrimSpace(parts[i]), "=")
		if !ok || key != name || parameter == "" {
			return false
		}
		values[i] = parameter
	}
	return validSigV4CredentialScope(values[0]) &&
		validSigV4SignedHeaders(values[1]) &&
		validSigV4Signature(values[2])
}

func validSigV4CredentialScope(credential string) bool {
	parts := strings.Split(credential, "/")
	if len(parts) != 5 || parts[0] == "" || parts[2] == "" || parts[3] == "" || parts[4] != "aws4_request" {
		return false
	}
	for _, c := range parts[0] {
		if c <= ' ' || c > '~' || c == ',' || c == '=' {
			return false
		}
	}
	if len(parts[1]) != 8 {
		return false
	}
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	for _, scopePart := range parts[2:4] {
		for _, c := range scopePart {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validSigV4SignedHeaders(value string) bool {
	for _, name := range strings.Split(value, ";") {
		if name == "" {
			return false
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return false
			}
		}
	}
	return true
}

func validSigV4Signature(value string) bool {
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return value != ""
}

func validSigV4PayloadMode(value string, allowUnsigned bool) bool {
	if value == "UNSIGNED-PAYLOAD" {
		return allowUnsigned
	}
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func headerPresentFold(h http.Header, want string) bool {
	for key := range h {
		if strings.EqualFold(key, want) {
			return true
		}
	}
	return false
}

func headerContainsToken(values []string, want string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), want) {
				return true
			}
		}
	}
	return false
}

func hasStreamingMarker(h http.Header) bool {
	for key, values := range h {
		key = strings.ToLower(key)
		if strings.Contains(key, "chunk-signature") || strings.Contains(key, "trailer-signature") {
			return true
		}
		for _, value := range values {
			value = strings.ToLower(value)
			if strings.Contains(value, "chunk-signature") || strings.Contains(value, "trailer-signature") {
				return true
			}
		}
	}
	return false
}

func isWebSocketUpgrade(req *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(req.Header.Get("Upgrade")), "websocket") &&
		headerContainsToken(req.Header.Values("Connection"), "upgrade")
}

// inferS3Endpoint recognizes exactly the V1 S3 endpoint forms.  A wildcard
// endpoint is represented by the literal configured spelling and has no bucket;
// requests routed through it use their concrete one-label virtual-host spelling.
func inferS3Endpoint(host string) (s3Endpoint, error) {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))
	if excludedS3EndpointHost(host) {
		return s3Endpoint{}, errors.New("unsupported S3 endpoint form")
	}
	if host == "s3.amazonaws.com" {
		return s3Endpoint{Region: "us-east-1"}, nil
	}
	parts := strings.Split(host, ".")
	if len(parts) == 4 && parts[0] == "s3" && parts[2] == "amazonaws" && parts[3] == "com" && supportedS3Region(parts[1]) {
		return s3Endpoint{Region: parts[1]}, nil
	}
	if len(parts) == 5 && parts[1] == "s3" && parts[3] == "amazonaws" && parts[4] == "com" && validS3Bucket(parts[0]) && supportedS3Region(parts[2]) {
		return s3Endpoint{Region: parts[2], Bucket: parts[0], VirtualHost: true}, nil
	}
	if len(parts) == 5 && parts[0] == "*" && parts[1] == "s3" && parts[3] == "amazonaws" && parts[4] == "com" && supportedS3Region(parts[2]) {
		return s3Endpoint{Region: parts[2], VirtualHost: true}, nil
	}
	return s3Endpoint{}, errors.New("unsupported S3 endpoint form")
}

func supportedS3Region(region string) bool {
	if !validS3Region(region) {
		return false
	}
	for _, prefix := range []string{"us-gov-", "cn-", "us-iso-", "us-isob-", "us-isof-", "eu-isoe-"} {
		if strings.HasPrefix(region, prefix) {
			return false
		}
	}
	return true
}

func excludedS3EndpointHost(host string) bool {
	if strings.HasSuffix(host, ".amazonaws.com.cn") {
		return true
	}
	for _, marker := range []string{
		"s3-accelerate", "s3.dualstack.", ".s3.dualstack.", "s3-fips", "s3-accesspoint",
		"s3-outposts", "s3-control", ".mrap.", ".accesspoint.s3-global.",
	} {
		if strings.Contains(host, marker) {
			return true
		}
	}
	return false
}

func validS3Region(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

func validS3Bucket(s string) bool {
	if len(s) < 3 || len(s) > 63 || s[0] == '.' || s[0] == '-' || s[len(s)-1] == '.' || s[len(s)-1] == '-' {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-') {
			return false
		}
	}
	return true
}

type s3Request struct {
	Operation      string
	Resource       string
	SourceResource string
}

// classifyS3Request derives an S3 operation without cleaning or normalizing
// the escaped path.  Unsupported semantics are policy-operation failures.
func classifyS3Request(req *http.Request, endpoint s3Endpoint) (s3Request, *PolicyError) {
	if req == nil || req.URL == nil {
		return s3Request{}, sigV4PolicyError("policy_operation")
	}
	bucket, key, err := s3BucketAndKey(req.URL, endpoint)
	if err != nil || bucket == "" {
		return s3Request{}, sigV4PolicyError("policy_resource")
	}
	if hasUnsupportedS3Query(req.URL.Query()) {
		return s3Request{}, sigV4PolicyError("policy_operation")
	}
	resource := s3ARN(bucket, key)
	if key == "" {
		if req.Method != http.MethodGet {
			if req.Method == http.MethodHead || req.Method == http.MethodPut || req.Method == http.MethodDelete {
				return s3Request{}, sigV4PolicyError("policy_operation")
			}
			return s3Request{}, sigV4PolicyError("policy_method")
		}
		if !validListQuery(req.URL.Query()) {
			return s3Request{}, sigV4PolicyError("policy_operation")
		}
		classified := s3Request{Operation: "s3:ListBucket", Resource: resource}
		if !validS3FunctionalHeaders(req, classified.Operation) {
			return s3Request{}, sigV4PolicyError("policy_header")
		}
		return classified, nil
	}
	if len(req.URL.Query()) != 0 {
		return s3Request{}, sigV4PolicyError("policy_operation")
	}
	var classified s3Request
	switch req.Method {
	case http.MethodGet:
		classified = s3Request{Operation: "s3:GetObject", Resource: resource}
	case http.MethodHead:
		classified = s3Request{Operation: "s3:HeadObject", Resource: resource}
	case http.MethodDelete:
		classified = s3Request{Operation: "s3:DeleteObject", Resource: resource}
	case http.MethodPut:
		copySource := req.Header.Get("X-Amz-Copy-Source")
		if copySource == "" {
			classified = s3Request{Operation: "s3:PutObject", Resource: resource}
			break
		}
		source, ok := parseCopySource(copySource)
		if !ok {
			return s3Request{}, sigV4PolicyError("policy_resource")
		}
		classified = s3Request{Operation: "s3:CopyObject", Resource: resource, SourceResource: source}
	default:
		return s3Request{}, sigV4PolicyError("policy_method")
	}
	if !validS3FunctionalHeaders(req, classified.Operation) {
		return s3Request{}, sigV4PolicyError("policy_header")
	}
	return classified, nil
}

// validS3FunctionalHeaders is intentionally closed for x-amz-* headers. Each
// operation admits only the non-privilege request headers in its S3 API request
// syntax; signer-generated headers are accepted for every operation.
func validS3FunctionalHeaders(req *http.Request, operation string) bool {
	for rawName, values := range req.Header {
		name := strings.ToLower(rawName)
		if !strings.HasPrefix(name, "x-amz-") {
			continue
		}
		switch name {
		case "x-amz-content-sha256", "x-amz-date", "x-amz-security-token":
			continue
		case "x-amz-expected-bucket-owner", "x-amz-request-payer":
			continue
		}
		switch operation {
		case "s3:GetObject", "s3:HeadObject":
			if name == "x-amz-checksum-mode" {
				continue
			}
		case "s3:PutObject":
			if strings.HasPrefix(name, "x-amz-meta-") && len(name) > len("x-amz-meta-") {
				continue
			}
			switch name {
			case "x-amz-storage-class", "x-amz-sdk-checksum-algorithm",
				"x-amz-checksum-crc32", "x-amz-checksum-crc32c", "x-amz-checksum-crc64nvme",
				"x-amz-checksum-sha1", "x-amz-checksum-sha256":
				continue
			}
			if validS3SSES3Header(name, values) {
				continue
			}
		case "s3:CopyObject":
			if strings.HasPrefix(name, "x-amz-meta-") && len(name) > len("x-amz-meta-") {
				continue
			}
			switch name {
			case "x-amz-copy-source", "x-amz-copy-source-if-match", "x-amz-copy-source-if-modified-since",
				"x-amz-copy-source-if-none-match", "x-amz-copy-source-if-unmodified-since",
				"x-amz-copy-source-server-side-encryption-customer-algorithm",
				"x-amz-copy-source-server-side-encryption-customer-key",
				"x-amz-copy-source-server-side-encryption-customer-key-md5",
				"x-amz-source-expected-bucket-owner", "x-amz-storage-class", "x-amz-checksum-algorithm":
				continue
			case "x-amz-metadata-directive", "x-amz-tagging-directive":
				if validS3CopyDirective(values) {
					continue
				}
			}
			if validS3SSES3Header(name, values) {
				continue
			}
		}
		return false
	}
	return true
}

func validS3SSES3Header(name string, values []string) bool {
	return name == "x-amz-server-side-encryption" && len(values) == 1 && strings.TrimSpace(values[0]) == "AES256"
}

func validS3CopyDirective(values []string) bool {
	if len(values) != 1 {
		return false
	}
	value := strings.TrimSpace(values[0])
	return value == "COPY" || value == "REPLACE"
}

func sigV4PolicyError(reason string) *PolicyError {
	return &PolicyError{Status: http.StatusForbidden, Reason: reason, AuthMode: "sigv4"}
}

func s3BucketAndKey(u *url.URL, endpoint s3Endpoint) (string, string, error) {
	escaped := u.EscapedPath()
	if escaped == "" {
		escaped = "/"
	}
	if !strings.HasPrefix(escaped, "/") {
		return "", "", errors.New("path is not absolute")
	}
	if endpoint.VirtualHost && endpoint.Bucket != "" {
		key := strings.TrimPrefix(escaped, "/")
		if !safeS3EscapedKey(key) {
			return "", "", errors.New("unsafe key")
		}
		return endpoint.Bucket, key, nil
	}
	parts := strings.Split(strings.TrimPrefix(escaped, "/"), "/")
	if len(parts) == 0 || !validS3Bucket(parts[0]) || !safeS3EscapedSegment(parts[0]) {
		return "", "", errors.New("unsafe bucket")
	}
	key := ""
	if len(parts) > 1 {
		key = strings.Join(parts[1:], "/")
	}
	if !safeS3EscapedKey(key) {
		return "", "", errors.New("unsafe key")
	}
	return parts[0], key, nil
}

func safeS3EscapedKey(key string) bool {
	if strings.Contains(key, "\\") || strings.Contains(strings.ToLower(key), "%2f") || strings.Contains(strings.ToLower(key), "%5c") {
		return false
	}
	for _, part := range strings.Split(key, "/") {
		if !safeS3EscapedSegment(part) {
			return false
		}
	}
	return true
}

func safeS3EscapedSegment(segment string) bool {
	if strings.Contains(segment, "\\") {
		return false
	}
	decoded, err := url.PathUnescape(segment)
	if err != nil || strings.ContainsAny(decoded, "/\\") {
		return false
	}
	return true
}

func hasUnsupportedS3Query(query url.Values) bool {
	for key := range query {
		switch key {
		case "uploads", "uploadId", "partNumber":
			return true
		}
	}
	return false
}

func validListQuery(query url.Values) bool {
	for key := range query {
		switch key {
		case "list-type", "prefix", "delimiter", "marker", "max-keys", "continuation-token", "start-after", "encoding-type", "fetch-owner":
		default:
			return false
		}
	}
	return true
}

func parseCopySource(value string) (string, bool) {
	if strings.Contains(value, "?") || strings.Contains(value, "#") {
		return "", false
	}
	value = strings.TrimPrefix(value, "/")
	parts := strings.Split(value, "/")
	if len(parts) < 2 || !validS3Bucket(parts[0]) || !safeS3EscapedSegment(parts[0]) {
		return "", false
	}
	key := strings.Join(parts[1:], "/")
	if key == "" || !safeS3EscapedKey(key) {
		return "", false
	}
	return s3ARN(parts[0], key), true
}

func s3ARN(bucket, key string) string {
	if key == "" {
		return "arn:aws:s3:::" + bucket
	}
	return "arn:aws:s3:::" + bucket + "/" + key
}

// matchS3Resource implements the deliberately small resource language
// validated by config: exact bucket/key ARNs and one trailing-star prefix.
func matchS3Resource(resource string, allowed []string) bool {
	for _, pattern := range allowed {
		if strings.HasSuffix(pattern, "*") {
			if strings.HasPrefix(resource, strings.TrimSuffix(pattern, "*")) {
				return true
			}
			continue
		}
		if resource == pattern {
			return true
		}
	}
	return false
}

// authorizeSigV4Policy is deliberately credential-free. Card 7B calls it
// before spooling/resolution/signing so every request has passed this core.
func authorizeSigV4Policy(req *http.Request, target Target, stanza *config.SigV4Stanza) (*AuthDecision, error) {
	if req == nil || stanza == nil || !strings.EqualFold(req.Host, target.Host) {
		return nil, sigV4PolicyError("policy_resource")
	}
	if pe := rejectUnsupportedSigV4Mode(req, stanza.AllowUnsigned); pe != nil {
		return nil, pe
	}
	endpoint, err := inferS3Endpoint(target.Host)
	if err != nil || endpoint.Region != stanza.Region {
		return nil, sigV4PolicyError("policy_resource")
	}
	classified, pe := classifyS3Request(req, endpoint)
	if pe != nil {
		return nil, pe
	}
	if !containsString(stanza.AllowedMethods, req.Method) {
		return nil, sigV4PolicyError("policy_method")
	}
	if !containsString(stanza.AllowedOperations, classified.Operation) {
		return nil, sigV4PolicyError("policy_operation")
	}
	if !matchS3Resource(classified.Resource, stanza.AllowedResources) ||
		(classified.SourceResource != "" && !matchS3Resource(classified.SourceResource, stanza.AllowedResources)) {
		return nil, sigV4PolicyError("policy_resource")
	}
	return &AuthDecision{Applied: true, Operation: classified.Operation, Resource: classified.Resource, Account: stanza.AccountID, Region: stanza.Region, Service: stanza.Service}, nil
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

type sigV4Authorizer struct {
	target Target
	stanza *config.SigV4Stanza
}

func (a sigV4Authorizer) Mode() string { return "sigv4" }
func (a sigV4Authorizer) Authorize(req *http.Request) (*AuthDecision, error) {
	return authorizeSigV4Policy(req, a.target, a.stanza)
}

type sigV4RoundTripper struct {
	transport http.RoundTripper
	proxy     *Proxyd
	secrets   *secret.Cache
	stanza    *config.SigV4Stanza
}

func newSigV4RoundTripper(transport http.RoundTripper, p *Proxyd, secrets *secret.Cache, stanza *config.SigV4Stanza) http.RoundTripper {
	return &sigV4RoundTripper{transport: transport, proxy: p, secrets: secrets, stanza: stanza}
}

func (c *Conn) serveSigV4(raw net.Conn, br *bufio.Reader, target Target, stanza *config.SigV4Stanza) error {
	base, err := newBaseTransport(target, nil)
	if err != nil {
		return err
	}
	base.DialContext = c.proxy.dialResolved(target)
	return c.serveMITM(raw, br, target, stanza.ALPN, newSigV4RoundTripper(base, c.proxy, c.secrets, stanza), sigV4Authorizer{target: target, stanza: stanza})
}

func (t *sigV4RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// The request has passed the credential-free classifier in authorizingRoundTripper.
	unsigned := strings.EqualFold(strings.TrimSpace(req.Header.Get("X-Amz-Content-Sha256")), "UNSIGNED-PAYLOAD")
	for _, h := range []string{"Authorization", "X-Amz-Date", "X-Amz-Security-Token", "X-Amz-Content-Sha256", "X-Amz-Region-Set", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto"} {
		req.Header.Del(h)
	}
	if unsigned && !t.stanza.AllowUnsigned {
		return nil, &PolicyError{Status: http.StatusForbidden, Reason: "policy_operation", AuthMode: "sigv4"}
	}
	body, hash, size, err := spoolAndHashBody(req.Body, t.spoolDir(), t.stanza.MaxBodyBytes)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return nil, &PolicyError{Status: http.StatusRequestEntityTooLarge, Reason: "body_too_large", AuthMode: "sigv4"}
		}
		return nil, &PolicyError{Status: http.StatusBadGateway, Reason: "spool_failure", AuthMode: "sigv4"}
	}
	req.Body = body
	req.ContentLength = size
	req.TransferEncoding = nil
	payloadHash := hash
	if unsigned {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	creds, err := resolveAWSCredentials(t.secrets, t.stanza)
	if err != nil {
		_ = body.Close()
		return nil, &PolicyError{Status: http.StatusBadGateway, Reason: "secret_unavailable", AuthMode: "sigv4"}
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if req.URL != nil {
		req.URL.Opaque = "//" + req.URL.Host + req.URL.EscapedPath()
	}
	now := proxyNow
	if t.proxy != nil && t.proxy.now != nil {
		now = t.proxy.now
	}
	if err := awsv4.NewSigner().SignHTTP(req.Context(), creds, req, payloadHash, t.stanza.Service, t.stanza.Region, now().UTC(), func(o *awsv4.SignerOptions) { o.DisableURIPathEscaping = true }); err != nil {
		_ = body.Close()
		return nil, &PolicyError{Status: http.StatusBadGateway, Reason: "secret_unavailable", AuthMode: "sigv4"}
	}
	// URL.Opaque is needed only for the signer. net/http must send origin-form
	// requests, particularly over HTTP/2, so restore the normal request URL.
	req.URL.Opaque = ""
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		_ = body.Close()
		return nil, err
	}
	resp.Body = &spoolClosingReadCloser{ReadCloser: resp.Body, spool: body}
	return resp, nil
}

type spoolClosingReadCloser struct {
	io.ReadCloser
	spool io.Closer
}

func (r *spoolClosingReadCloser) Close() error {
	err := r.ReadCloser.Close()
	serr := r.spool.Close()
	if err != nil {
		return err
	}
	return serr
}

var errBodyTooLarge = errors.New("body too large")

func (t *sigV4RoundTripper) spoolDir() string {
	state := ""
	if t.proxy != nil {
		state = t.proxy.stateDir
	}
	if state == "" {
		state = config.StateDir()
	}
	return filepath.Join(state, "spool")
}

// spoolAndHashBody never keeps the payload in memory. The returned file has
// already been unlinked and its Close releases it on every caller path.
func spoolAndHashBody(body io.ReadCloser, dir string, max int64) (io.ReadCloser, string, int64, error) {
	if max < 0 {
		return nil, "", 0, fmt.Errorf("invalid body cap")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, "", 0, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, "", 0, err
	}
	f, err := os.CreateTemp(dir, "sigv4-")
	if err != nil {
		return nil, "", 0, err
	}
	if err = f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nil, "", 0, err
	}
	name := f.Name()
	if err = os.Remove(name); err != nil {
		_ = f.Close()
		return nil, "", 0, err
	}
	if body == nil {
		body = http.NoBody
	}
	defer body.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(body, max+1))
	if err != nil {
		_ = f.Close()
		return nil, "", 0, err
	}
	if n > max {
		_ = f.Close()
		return nil, "", 0, errBodyTooLarge
	}
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		_ = f.Close()
		return nil, "", 0, err
	}
	return f, fmt.Sprintf("%x", h.Sum(nil)), n, nil
}

func resolveAWSCredentials(cache *secret.Cache, stanza *config.SigV4Stanza) (aws.Credentials, error) {
	if cache == nil || stanza == nil {
		return aws.Credentials{}, errors.New("credentials unavailable")
	}
	akid, err := cache.Resolve(stanza.AccessKeyID)
	if err != nil || akid == "" {
		return aws.Credentials{}, errors.New("access key unavailable")
	}
	secretKey, err := cache.Resolve(stanza.SecretAccessKey)
	if err != nil || secretKey == "" {
		return aws.Credentials{}, errors.New("secret key unavailable")
	}
	creds := aws.Credentials{AccessKeyID: akid, SecretAccessKey: secretKey}
	if stanza.SessionToken != "" {
		token, err := cache.Resolve(stanza.SessionToken)
		if err != nil || token == "" {
			return aws.Credentials{}, errors.New("session token unavailable")
		}
		creds.SessionToken = token
	}
	return creds, nil
}
