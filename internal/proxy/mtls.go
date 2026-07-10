package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"cove/internal/config"
	"cove/internal/secret"
)

// mtlsAuthorizer performs the credential-free portion of an mTLS policy.
// Keeping it ahead of the transport is important: rejected requests must not
// resolve secrets or open an upstream connection.
type mtlsAuthorizer struct {
	stanza *config.MTLSStanza
}

func (a mtlsAuthorizer) Mode() string { return "mtls" }

func (a mtlsAuthorizer) Authorize(req *http.Request) (*AuthDecision, error) {
	if a.stanza == nil {
		return nil, &PolicyError{Status: http.StatusBadGateway, Reason: "secret_unavailable", AuthMode: a.Mode()}
	}
	hasMethod := false
	for _, rule := range a.stanza.Rules {
		if req.Method != rule.Method {
			continue
		}
		hasMethod = true
		if matchPathPrefix(req, rule.PathPrefix) {
			return &AuthDecision{Applied: true}, nil
		}
	}
	if !hasMethod {
		return nil, &PolicyError{Status: http.StatusForbidden, Reason: "policy_method", AuthMode: a.Mode()}
	}
	return nil, &PolicyError{Status: http.StatusForbidden, Reason: "policy_resource", AuthMode: a.Mode()}
}

// matchPathPrefix matches a request path by decoded, segment boundaries.
// It rejects unsafe spellings rather than cleaning them, since cleaning could
// turn a request outside the policy into an allowed path.
func matchPathPrefix(req *http.Request, prefix string) bool {
	if req == nil || req.URL == nil {
		return false
	}
	path, ok := safeHTTPPathSegments(req.URL.EscapedPath())
	if !ok {
		return false
	}
	segments, ok := safeHTTPPathSegments(prefix)
	if !ok || len(segments) > len(path) {
		return false
	}
	for i := range segments {
		if segments[i] != path[i] {
			return false
		}
	}
	return true
}

func safeHTTPPathSegments(escaped string) ([]string, bool) {
	if escaped == "" || !strings.HasPrefix(escaped, "/") || strings.Contains(escaped, "\\") || strings.ContainsRune(escaped, '\x00') {
		return nil, false
	}
	trimmed := strings.TrimPrefix(escaped, "/")
	if trimmed == "" {
		return nil, true
	}
	// A trailing slash is a spelling detail for a prefix, but empty interior
	// segments are never normalized into an allowed request.
	trimmed = strings.TrimSuffix(trimmed, "/")
	if trimmed == "" {
		return nil, true
	}
	parts := strings.Split(trimmed, "/")
	decoded := make([]string, len(parts))
	for i, part := range parts {
		if part == "" || strings.Contains(part, "\\") || strings.ContainsRune(part, '\x00') {
			return nil, false
		}
		value, err := url.PathUnescape(part)
		if err != nil || value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\%") || strings.ContainsRune(value, '\x00') {
			return nil, false
		}
		decoded[i] = value
	}
	return decoded, true
}

// mtlsClientCertificate resolves material only after the upstream requests a
// client certificate. Errors deliberately omit resolver and parser details.
func mtlsClientCertificate(secrets *secret.Cache, stanza *config.MTLSStanza) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		if stanza == nil {
			return nil, errors.New("mTLS client certificate unavailable")
		}
		certPEM, err := secrets.Resolve(stanza.ClientCert)
		if err != nil || strings.TrimSpace(certPEM) == "" {
			return nil, errors.New("mTLS client certificate unavailable")
		}
		keyPEM, err := secrets.Resolve(stanza.ClientKey)
		if err != nil || strings.TrimSpace(keyPEM) == "" {
			return nil, errors.New("mTLS client certificate unavailable")
		}
		pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return nil, errors.New("mTLS client certificate unavailable")
		}
		return &pair, nil
	}
}

// newMTLSRoundTripper creates one transport for one accepted CONNECT. Its TLS
// config is freshly allocated by newBaseTransport, so stanza callbacks cannot
// mutate another policy's configuration.
func newMTLSRoundTripper(target Target, p *Proxyd, secrets *secret.Cache, stanza *config.MTLSStanza) (http.RoundTripper, error) {
	if p == nil {
		return nil, errors.New("mTLS transport unavailable")
	}
	base, err := newBaseTransport(target, func(cfg *tls.Config) error {
		cfg.MinVersion = tls.VersionTLS12
		cfg.NextProtos = []string{"h2", "http/1.1"}
		if stanza != nil && stanza.ALPN == "http/1.1" {
			cfg.NextProtos = []string{"http/1.1"}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Perform TLS explicitly so a server that never requests a client
	// certificate cannot receive an authorized HTTP request. The template is
	// cloned for every upstream connection; callback state belongs to exactly
	// one handshake and is never shared across stanzas or pooled connections.
	dialResolved := p.dialResolved(target)
	tlsTemplate := base.TLSClientConfig.Clone()
	base.DialContext = dialResolved
	base.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		raw, err := dialResolved(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		requested, presented := false, false
		tlsConfig := tlsTemplate.Clone()
		resolveCertificate := mtlsClientCertificate(secrets, stanza)
		tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			requested = true
			pair, err := resolveCertificate(info)
			if err == nil && pair != nil && len(pair.Certificate) != 0 && pair.PrivateKey != nil {
				presented = true
			}
			return pair, err
		}

		tlsConn := tls.Client(raw, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		if !requested || !presented {
			_ = tlsConn.Close()
			return nil, &PolicyError{Status: http.StatusBadGateway, Reason: "mtls_not_requested", AuthMode: "mtls"}
		}
		return tlsConn, nil
	}
	return base, nil
}

func (c *Conn) serveMTLS(raw net.Conn, br *bufio.Reader, target Target, stanza *config.MTLSStanza) error {
	transport, err := newMTLSRoundTripper(target, c.proxy, c.secrets, stanza)
	if err != nil {
		return err
	}
	return c.serveMITM(raw, br, target, stanza.ALPN, transport, mtlsAuthorizer{stanza: stanza})
}
