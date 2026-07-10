package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type requestAuthorizer interface {
	Mode() string
	Authorize(*http.Request) (*AuthDecision, error)
}

type AuthDecision struct {
	Applied   bool
	Operation string
	Resource  string
	Account   string
	Region    string
	Service   string
}

// PolicyError is deliberately safe to expose to the in-box client and audit.
// Reason is a stable policy code, never an underlying error string.
type PolicyError struct {
	Status   int
	Reason   string
	AuthMode string
	Decision *AuthDecision
}

func (e *PolicyError) Error() string { return "cove policy rejected request" }

type responseAuthorizer interface {
	HandleResponse(*http.Response)
}

type authorizingRoundTripper struct {
	transport http.RoundTripper
	auth      requestAuthorizer
}

func (t authorizingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.auth == nil {
		return t.transport.RoundTrip(req)
	}
	decision, err := t.auth.Authorize(req)
	if err != nil {
		var pe *PolicyError
		if !errors.As(err, &pe) {
			pe = &PolicyError{Status: http.StatusBadGateway, Reason: "secret_unavailable", AuthMode: t.auth.Mode()}
		}
		if pe.AuthMode == "" {
			pe.AuthMode = t.auth.Mode()
		}
		return nil, pe
	}
	if state := requestAuditFrom(req); state != nil {
		state.decision = decision
		state.authMode = t.auth.Mode()
	}
	return t.transport.RoundTrip(req)
}

type requestAuditState struct {
	once     sync.Once
	decision *AuthDecision
	authMode string
}

type requestAuditKey struct{}

func requestAuditFrom(req *http.Request) *requestAuditState {
	state, _ := req.Context().Value(requestAuditKey{}).(*requestAuditState)
	return state
}

func (s *requestAuditState) emit(c *Conn, rec *AuditRecord) {
	if s == nil {
		c.emit(rec)
		return
	}
	s.once.Do(func() { c.emit(rec) })
}

func newBaseTransport(t Target, tlsMutator func(*tls.Config) error) (*http.Transport, error) {
	tlsConfig := (&tls.Config{ServerName: t.Host}).Clone()
	if tlsMutator != nil {
		if err := tlsMutator(tlsConfig); err != nil {
			return nil, err
		}
	}
	return &http.Transport{ForceAttemptHTTP2: true, TLSClientConfig: tlsConfig, IdleConnTimeout: 30 * time.Second}, nil
}

type bufConn struct {
	r io.Reader
	net.Conn
}

func (b bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func newBufConn(br *bufio.Reader, c net.Conn) net.Conn {
	return bufConn{r: io.MultiReader(io.LimitReader(br, int64(br.Buffered())), c), Conn: c}
}

func (c *Conn) serveMITM(raw net.Conn, br *bufio.Reader, t Target, alpn string, transport http.RoundTripper, auth requestAuthorizer) error {
	if c.ca == nil {
		return fmt.Errorf("CA not loaded")
	}
	leaf, err := c.ca.LeafFor(t.Host)
	if err != nil {
		return err
	}

	nextProtos := []string{"h2", "http/1.1"}
	if alpn == "http/1.1" {
		nextProtos = []string{"http/1.1"}
	}
	srvTLS := &tls.Config{Certificates: []tls.Certificate{*leaf}, NextProtos: nextProtos, MinVersion: tls.VersionTLS12}

	if transport == nil {
		base, err := newBaseTransport(t, nil)
		if err != nil {
			return err
		}
		base.DialContext = c.proxy.dialResolved(t)
		transport = base
	}
	if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
		defer closer.CloseIdleConnections()
	}

	var bytesUp atomic.Int64
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = upstreamURLHost(t)
			pr.Out.Host = t.Host
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			if pr.Out.Body != nil {
				pr.Out.Body = &atomicCountingReadCloser{rc: pr.Out.Body, n: &bytesUp}
			}
			pr.Out = pr.Out.WithContext(context.WithValue(pr.Out.Context(), requestAuditKey{}, &requestAuditState{}))
		},
		Transport:     authorizingRoundTripper{transport: transport, auth: auth},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			state := requestAuditFrom(resp.Request)
			rec := c.newInjectRecord(t, resp, bytesUp.Load(), state)
			if a, ok := auth.(responseAuthorizer); ok {
				a.HandleResponse(resp)
			}
			resp.Body = &countingReadCloser{rc: resp.Body, onClose: func(n int64) {
				rec.BytesDn = n
				rec.DurMS = time.Since(c.started).Milliseconds()
				state.emit(c, rec)
			}}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			state := requestAuditFrom(req)
			var pe *PolicyError
			if errors.As(err, &pe) {
				status := pe.Status
				if status == 0 {
					status = http.StatusForbidden
				}
				rec := c.newInjectRecord(t, nil, bytesUp.Load(), state)
				rec.Policy, rec.Status, rec.Reason, rec.AuthMode = "deny", status, pe.Reason, pe.AuthMode
				state.emit(c, rec)
				http.Error(w, "cove blocked this operation for "+t.Host+"; ask the human to run: cove explain last\n", status)
				return
			}
			rec := c.newInjectRecord(t, nil, bytesUp.Load(), state)
			rec.Status, rec.Reason = http.StatusBadGateway, "upstream_tls"
			state.emit(c, rec)
			http.Error(w, "cove: upstream unavailable\n", http.StatusBadGateway)
		},
	}

	if _, err := io.WriteString(raw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	tlsConn := tls.Server(newBufConn(br, raw), srvTLS)
	if err := tlsConn.Handshake(); err != nil {
		return err
	}
	switch tlsConn.ConnectionState().NegotiatedProtocol {
	case "h2":
		(&http2.Server{}).ServeConn(tlsConn, &http2.ServeConnOpts{Handler: rp})
		return nil
	default:
		rp.FlushInterval = -1
		return http.Serve(newBlockingOneShotListener(tlsConn), rp)
	}
}

func upstreamURLHost(t Target) string {
	if t.Port == 443 {
		return t.Host
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

func (c *Conn) newInjectRecord(t Target, resp *http.Response, bytesUp int64, states ...*requestAuditState) *AuditRecord {
	var state *requestAuditState
	if len(states) != 0 {
		state = states[0]
	}
	method, path, status := "-", "-", 0
	if resp != nil && resp.Request != nil {
		method = resp.Request.Method
		if resp.Request.URL != nil {
			path = resp.Request.URL.RequestURI()
			if path == "" {
				path = "/"
			}
		}
	}
	if resp != nil {
		status = resp.StatusCode
	}
	rec := &AuditRecord{TS: time.Now().UTC(), Session: c.sess.ID, Policy: "inject", Host: t.Host, Port: t.Port, Method: method, Path: path, Status: status, BytesUp: bytesUp, Agent: c.sess.Agent}
	if state != nil {
		rec.AuthMode = state.authMode
		if d := state.decision; d != nil {
			rec.Operation, rec.Resource, rec.Account, rec.Region, rec.Service = d.Operation, d.Resource, d.Account, d.Region, d.Service
		}
	}
	return rec
}

type blockingOneShotListener struct {
	ch   chan net.Conn
	done chan struct{}
}
type atomicCountingReadCloser struct {
	rc io.ReadCloser
	n  *atomic.Int64
}

func (c *atomicCountingReadCloser) Read(p []byte) (int, error) {
	m, err := c.rc.Read(p)
	if m > 0 && c.n != nil {
		c.n.Add(int64(m))
	}
	return m, err
}
func (c *atomicCountingReadCloser) Close() error { return c.rc.Close() }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "cove" }
func (dummyAddr) String() string  { return "cove-oneshot" }

type notifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (n *notifyConn) Close() error { n.once.Do(func() { close(n.done) }); return n.Conn.Close() }
func newBlockingOneShotListener(c net.Conn) *blockingOneShotListener {
	done := make(chan struct{})
	l := &blockingOneShotListener{ch: make(chan net.Conn, 1), done: done}
	l.ch <- &notifyConn{Conn: c, done: done}
	close(l.ch)
	return l
}
func (l *blockingOneShotListener) Accept() (net.Conn, error) {
	if c, ok := <-l.ch; ok {
		return c, nil
	}
	<-l.done
	return nil, io.EOF
}
func (l *blockingOneShotListener) Close() error   { return nil }
func (l *blockingOneShotListener) Addr() net.Addr { return dummyAddr{} }
