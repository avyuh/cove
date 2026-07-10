package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"cove/internal/config"
	"cove/internal/secret"
)

const reloginWarning = "cove: Anthropic OAuth token rejected (401) - run 'claude' once on the host to re-login"

func (c *Conn) serveInject(raw net.Conn, br *bufio.Reader, t Target, st *config.InjectStanza) error {
	if c.secrets == nil {
		return fmt.Errorf("secret cache not loaded")
	}
	return c.serveMITM(raw, br, t, st.ALPN, nil, newHeaderAuthorizer(st, t, c, c.secrets))
}

func newHeaderAuthorizer(stanza *config.InjectStanza, target Target, conn *Conn, secrets *secret.Cache) *headerAuthorizer {
	return &headerAuthorizer{
		conn:    conn,
		stanza:  stanza,
		target:  target,
		secrets: secrets,
	}
}

type headerAuthorizer struct {
	conn    *Conn
	stanza  *config.InjectStanza
	target  Target
	secrets *secret.Cache
}

type headerSecretKey struct{}

func (a *headerAuthorizer) Authorize(req *http.Request) (*AuthDecision, error) {
	if a.stanza.Transform == "github-basic" {
		if err := matchGitHubGitRequest(req, a.stanza.GitHubRepositories); err != nil {
			return nil, &PolicyError{Status: http.StatusForbidden, Reason: "policy_resource", AuthMode: a.Mode()}
		}
		if !githubMethodAllowed(req.Method, a.stanza.AllowedMethods) {
			return nil, &PolicyError{Status: http.StatusForbidden, Reason: "policy_method", AuthMode: a.Mode()}
		}
	}
	secretVal, err := a.secrets.Resolve(a.stanza.Secret)
	if err != nil {
		return nil, &PolicyError{Status: http.StatusBadGateway, Reason: "secret_unavailable", AuthMode: a.Mode()}
	}
	*req = *req.WithContext(context.WithValue(req.Context(), headerSecretKey{}, secretVal))
	for _, h := range a.stanza.StripHeaders {
		req.Header.Del(h)
	}
	if secretVal != "" {
		value := strings.ReplaceAll(a.stanza.HeaderTemplate, "{secret}", secretVal)
		if a.stanza.Transform == "github-basic" {
			value = githubBasicValue(a.stanza.BasicUsername, secretVal)
		}
		req.Header.Set(a.stanza.HeaderName, value)
	}
	return &AuthDecision{Applied: secretVal != ""}, nil
}

func (a *headerAuthorizer) Mode() string {
	if a.stanza != nil && a.stanza.Transform == "github-basic" {
		return "github-basic"
	}
	return "header"
}

// githubBasicValue composes the GitHub smart-HTTP credential only after the
// real token has been resolved on the host.
func githubBasicValue(username, token string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+token))
}

var (
	errGitHubResource = errors.New("github request is outside configured repository scope")
)

// matchGitHubGitRequest accepts only Git smart-HTTP endpoints and LFS paths
// below a configured repository. It deliberately operates on EscapedPath and
// never cleans a path: cleaning could turn an unsafe spelling into an allowed
// repository path.
func matchGitHubGitRequest(req *http.Request, repositories []string) error {
	if req == nil || req.URL == nil {
		return errGitHubResource
	}
	escaped := req.URL.EscapedPath()
	if escaped == "" || !strings.HasPrefix(escaped, "/") || strings.Contains(escaped, "\\") || strings.ContainsRune(escaped, '\x00') {
		return errGitHubResource
	}
	parts := strings.Split(strings.TrimPrefix(escaped, "/"), "/")
	if len(parts) < 3 || anyUnsafeGitHubPathSegment(parts) {
		return errGitHubResource
	}
	owner, repoGit := parts[0], parts[1]
	if !strings.HasSuffix(strings.ToLower(repoGit), ".git") {
		return errGitHubResource
	}
	repo := repoGit[:len(repoGit)-len(".git")]
	if repo == "" || !githubRepositoryAllowed(owner, repo, repositories) {
		return errGitHubResource
	}

	if len(parts) == 4 && parts[2] == "info" && parts[3] == "refs" {
		return nil
	}
	if len(parts) == 3 && (parts[2] == "git-upload-pack" || parts[2] == "git-receive-pack") {
		return nil
	}
	if len(parts) >= 5 && parts[2] == "info" && parts[3] == "lfs" {
		return nil
	}
	return errGitHubResource
}

func anyUnsafeGitHubPathSegment(parts []string) bool {
	for _, part := range parts {
		if part == "" || strings.Contains(part, "\\") || strings.ContainsRune(part, '\x00') {
			return true
		}
		decoded, err := url.PathUnescape(part)
		if err != nil || decoded == "" || decoded == "." || decoded == ".." ||
			strings.ContainsAny(decoded, "/\\%") || strings.ContainsRune(decoded, '\x00') {
			return true
		}
	}
	return false
}

func githubRepositoryAllowed(owner, repo string, repositories []string) bool {
	for _, configured := range repositories {
		parts := strings.Split(configured, "/")
		if len(parts) == 2 && strings.EqualFold(parts[0], owner) &&
			(parts[1] == "*" || strings.EqualFold(parts[1], repo)) {
			return true
		}
	}
	return false
}

func githubMethodAllowed(method string, allowed []string) bool {
	for _, candidate := range allowed {
		if method == candidate {
			return true
		}
	}
	return false
}

func (a *headerAuthorizer) HandleResponse(resp *http.Response) {
	if resp.StatusCode == http.StatusUnauthorized && a.stanza.Mode == "oauth-refresh" {
		secretVal, _ := resp.Request.Context().Value(headerSecretKey{}).(string)
		a.conn.warnReloginRateLimited(secretVal, a.target)
	}
}

func (c *Conn) warnReloginRateLimited(secretVal string, t Target) {
	if c == nil || c.proxy == nil || !c.proxy.warnReloginRateLimited(secretVal) {
		return
	}
	c.emit(&AuditRecord{
		TS:      time.Now().UTC(),
		Session: c.sess.ID,
		Policy:  "warn",
		Level:   "warn",
		Host:    t.Host,
		Port:    t.Port,
		Status:  http.StatusUnauthorized,
		Message: reloginWarning,
		Agent:   c.sess.Agent,
	})
}

func (p *Proxyd) warnReloginRateLimited(secretVal string) bool {
	if p == nil {
		return false
	}
	sum := sha256.Sum256([]byte(secretVal))
	p.warnMu.Lock()
	defer p.warnMu.Unlock()
	if p.warnedRelogin == nil {
		p.warnedRelogin = map[[32]byte]struct{}{}
	}
	if _, ok := p.warnedRelogin[sum]; ok {
		return false
	}
	p.warnedRelogin[sum] = struct{}{}
	if p.log != nil {
		fmt.Fprintln(p.log, reloginWarning)
	}
	return true
}
