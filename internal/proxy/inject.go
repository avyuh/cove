package proxy

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"cove/internal/config"

	"golang.org/x/net/http2"
)

const reloginWarning = "cove: Anthropic OAuth token rejected (401) - run 'claude' once on the host to re-login"

type bufConn struct {
	r io.Reader
	net.Conn
}

func (b bufConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

func newBufConn(br *bufio.Reader, c net.Conn) net.Conn {
	return bufConn{r: io.MultiReader(io.LimitReader(br, int64(br.Buffered())), c), Conn: c}
}

func (c *Conn) serveInject(raw net.Conn, br *bufio.Reader, t Target, st *config.InjectStanza) error {
	if c.ca == nil {
		return fmt.Errorf("CA not loaded")
	}
	if c.secrets == nil {
		return fmt.Errorf("secret cache not loaded")
	}
	leaf, err := c.ca.LeafFor(t.Host)
	if err != nil {
		return err
	}

	alpn := []string{"h2", "http/1.1"}
	if st.ALPN == "http/1.1" {
		alpn = []string{"http/1.1"}
	}
	srvTLS := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   alpn,
		MinVersion:   tls.VersionTLS12,
	}

	secretVal, err := c.secrets.Resolve(st.Secret)
	if err != nil {
		return err
	}
	inject := secretVal != ""
	headerVal := strings.ReplaceAll(st.HeaderTemplate, "{secret}", secretVal)

	upstream := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{ServerName: t.Host},
		DialContext:       c.proxy.dialResolved(t),
		IdleConnTimeout:   30 * time.Second,
	}
	defer upstream.CloseIdleConnections()

	var bytesUp atomic.Int64
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "https"
			pr.Out.URL.Host = upstreamURLHost(t)
			pr.Out.Host = t.Host
			for _, h := range st.StripHeaders {
				pr.Out.Header.Del(h)
			}
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
			if inject {
				pr.Out.Header.Set(st.HeaderName, headerVal)
			}
			if pr.Out.Body != nil {
				pr.Out.Body = &atomicCountingReadCloser{rc: pr.Out.Body, n: &bytesUp}
			}
		},
		Transport:     upstream,
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			rec := c.newInjectRecord(t, resp, bytesUp.Load())
			if resp.StatusCode == http.StatusUnauthorized && st.Mode == "oauth-refresh" {
				c.warnReloginRateLimited(secretVal, t)
			}
			resp.Body = &countingReadCloser{rc: resp.Body, onClose: func(n int64) {
				rec.BytesDn = n
				rec.DurMS = time.Since(c.started).Milliseconds()
				c.emit(rec)
			}}
			return nil
		},
	}

	if _, err := io.WriteString(raw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	conn := newBufConn(br, raw)
	tlsConn := tls.Server(conn, srvTLS)
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

func (c *Conn) newInjectRecord(t Target, resp *http.Response, bytesUp int64) *AuditRecord {
	method := "-"
	path := "-"
	status := 0
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
	return &AuditRecord{
		TS:      time.Now().UTC(),
		Session: c.sess.ID,
		Policy:  "inject",
		Host:    t.Host,
		Port:    t.Port,
		Method:  method,
		Path:    path,
		Status:  status,
		BytesUp: bytesUp,
		Agent:   c.sess.Agent,
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

func (c *atomicCountingReadCloser) Close() error {
	return c.rc.Close()
}

type dummyAddr struct{}

func (dummyAddr) Network() string { return "cove" }
func (dummyAddr) String() string  { return "cove-oneshot" }

type notifyConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func (n *notifyConn) Close() error {
	n.once.Do(func() { close(n.done) })
	return n.Conn.Close()
}

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
