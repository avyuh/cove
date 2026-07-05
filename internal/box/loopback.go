package box

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const dynamicBaseURLLoopback = "http://127.0.0.1:0"

type baseURLLoopback struct {
	targetHost string
	targetPort int
	proxyPort  int
	rootCAs    *x509.CertPool
}

func startBaseURLLoopbacks(d *Directives) (func(), error) {
	need := false
	for _, st := range d.Inject {
		if st.BaseURLValue == dynamicBaseURLLoopback {
			need = true
			break
		}
	}
	if !need {
		return func() {}, nil
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(d.CAPEM) {
		return nil, fmt.Errorf("load cove CA trust")
	}
	var listeners []net.Listener
	closeAll := func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}
	for i := range d.Inject {
		st := &d.Inject[i]
		if st.BaseURLValue != dynamicBaseURLLoopback {
			continue
		}
		if st.BaseURLEnv == "" {
			closeAll()
			return nil, fmt.Errorf("loopback stanza for %q missing base_url_env", st.Host)
		}
		host, port, err := loopbackTarget(*st)
		if err != nil {
			closeAll()
			return nil, err
		}
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			closeAll()
			return nil, err
		}
		listeners = append(listeners, ln)
		tcpAddr, ok := ln.Addr().(*net.TCPAddr)
		if !ok {
			closeAll()
			return nil, fmt.Errorf("loopback listener has non-TCP address %s", ln.Addr())
		}
		st.BaseURLValue = "http://127.0.0.1:" + strconv.Itoa(tcpAddr.Port)
		go serveBaseURLLoopback(ln, baseURLLoopback{
			targetHost: host,
			targetPort: port,
			proxyPort:  d.ProxyPort,
			rootCAs:    pool,
		})
	}
	return closeAll, nil
}

func loopbackTarget(st InjectDirective) (string, int, error) {
	host := strings.Trim(st.Host, "[]")
	port := st.Port
	if h, p, err := net.SplitHostPort(st.Host); err == nil {
		host = strings.Trim(h, "[]")
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 && parsed <= 65535 {
			port = parsed
		}
	}
	if host == "" {
		return "", 0, fmt.Errorf("loopback stanza missing host")
	}
	if port == 0 {
		port = 443
	}
	return host, port, nil
}

func serveBaseURLLoopback(ln net.Listener, lb baseURLLoopback) {
	srv := &http.Server{
		Handler:           http.HandlerFunc(lb.handle),
		ReadHeaderTimeout: 30 * time.Second,
	}
	_ = srv.Serve(ln)
}

func (lb baseURLLoopback) handle(w http.ResponseWriter, r *http.Request) {
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL.Scheme = "https"
	out.URL.Host = upstreamLoopbackHost(lb.targetHost, lb.targetPort)
	out.Host = lb.targetHost
	tr := &http.Transport{
		DialTLSContext:     lb.dialTLS,
		DisableKeepAlives:  true,
		DisableCompression: true,
		ForceAttemptHTTP2:  false,
	}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(out)
	if err != nil {
		http.Error(w, "cove base-url loopback: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHTTPHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (lb baseURLLoopback) dialTLS(ctx context.Context, _, _ string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(lb.proxyPort)))
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(lb.targetHost, strconv.Itoa(lb.targetPort))
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = conn.Close()
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}
	tlsConn := tls.Client(bufConn{Reader: br, Conn: conn}, &tls.Config{
		ServerName: lb.targetHost,
		RootCAs:    lb.rootCAs,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.Handshake(); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

type bufConn struct {
	io.Reader
	net.Conn
}

func (c bufConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}

func copyHTTPHeader(dst, src http.Header) {
	for k, vals := range src {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}

func upstreamLoopbackHost(host string, port int) string {
	if port == 443 {
		return host
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}
