package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"cove/internal/secret"
)

type Conn struct {
	raw     net.Conn
	br      *bufio.Reader
	sess    Session
	proxy   *Proxyd
	matcher *Matcher
	ca      *CA
	secrets *secret.Cache
	audit   *AuditWriter
	started time.Time
}

type Target struct {
	Host string
	Port int
}

type Matcher struct {
	rules []compiledRule
}

func (c *Conn) handle() {
	defer c.raw.Close()
	line, err := c.br.ReadString('\n')
	if err != nil {
		c.deny(Target{}, 400, "malformed CONNECT")
		return
	}
	line = strings.TrimRight(line, "\r\n")
	parts := strings.Fields(line)
	if len(parts) < 3 {
		c.deny(Target{}, 400, "malformed CONNECT")
		return
	}
	if parts[0] != "CONNECT" {
		c.writeResponse(405, "Method Not Allowed", "plain HTTP proxying is not supported\n")
		c.auditDeny(Target{Host: parts[1], Port: 80}, 405)
		return
	}
	t, err := parseTarget(parts[1])
	if err != nil {
		c.deny(Target{}, 400, "bad CONNECT target")
		return
	}
	for {
		h, err := c.br.ReadString('\n')
		if err != nil {
			c.deny(t, 400, "malformed CONNECT headers")
			return
		}
		if h == "\r\n" || h == "\n" {
			break
		}
	}
	policy, stanza := c.matcher.Match(t.Host, t.Port)
	if policy == PolicyDeny {
		c.deny(t, 403, "denied by cove policy\n")
		return
	}
	if policy == PolicyInject {
		if stanza == nil {
			c.deny(t, 502, "inject policy unavailable\n")
			return
		}
		if err := c.serveInject(c.raw, c.br, t, stanza); err != nil && !isClosed(err) {
			fmt.Fprintf(c.proxy.log, "cove proxyd: inject %s:%d: %v\n", t.Host, t.Port, err)
		}
		return
	}
	if err := c.tunnel(t, policy); err != nil {
		fmt.Fprintf(c.proxy.log, "cove proxyd: tunnel %s:%d: %v\n", t.Host, t.Port, err)
	}
}

func parseTarget(s string) (Target, error) {
	host, portText, err := net.SplitHostPort(s)
	if err != nil {
		return Target{}, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 || port > 65535 {
		return Target{}, fmt.Errorf("bad port")
	}
	return Target{Host: strings.ToLower(strings.Trim(host, "[]")), Port: port}, nil
}

func (c *Conn) tunnel(t Target, policy Policy) error {
	upstream, err := c.proxy.dialAllowed(t)
	if err != nil {
		c.deny(t, 502, "upstream unavailable\n")
		return err
	}
	defer upstream.Close()
	if _, err := io.WriteString(c.raw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return err
	}
	start := time.Now()
	upDone := make(chan copyResult, 1)
	downDone := make(chan copyResult, 1)
	go func() {
		n, err := io.Copy(upstream, c.br)
		closeWrite(upstream)
		upDone <- copyResult{n: n, err: err}
	}()
	go func() {
		n, err := io.Copy(c.raw, upstream)
		closeWrite(c.raw)
		downDone <- copyResult{n: n, err: err}
	}()
	up := <-upDone
	down := <-downDone
	pol := "allow"
	c.emit(&AuditRecord{
		TS:      time.Now().UTC(),
		Session: c.sess.ID,
		Policy:  pol,
		Host:    t.Host,
		Port:    t.Port,
		Method:  "-",
		Path:    "-",
		BytesUp: up.n,
		BytesDn: down.n,
		DurMS:   time.Since(start).Milliseconds(),
		Agent:   c.sess.Agent,
	})
	if up.err != nil && !isClosed(up.err) {
		return up.err
	}
	if down.err != nil && !isClosed(down.err) {
		return down.err
	}
	return nil
}

type copyResult struct {
	n   int64
	err error
}

func closeWrite(c net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}

func isClosed(err error) bool {
	if err == nil {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "closed") || strings.Contains(s, "reset by peer") || err == io.EOF
}

func (c *Conn) deny(t Target, status int, body string) {
	text := "Forbidden"
	if status == 400 {
		text = "Bad Request"
	} else if status == 502 {
		text = "Bad Gateway"
	}
	c.writeResponse(status, text, body)
	c.auditDeny(t, status)
}

func (c *Conn) writeResponse(status int, text, body string) {
	_, _ = fmt.Fprintf(c.raw, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, text, len(body), body)
}

func (c *Conn) auditDeny(t Target, status int) {
	c.emit(&AuditRecord{
		TS:      time.Now().UTC(),
		Session: c.sess.ID,
		Policy:  "deny",
		Host:    t.Host,
		Port:    t.Port,
		Method:  "-",
		Path:    "-",
		Status:  status,
		Agent:   c.sess.Agent,
	})
}

func (c *Conn) emit(rec *AuditRecord) {
	if c.audit != nil {
		c.audit.Emit(rec)
	}
}

func (p *Proxyd) dialAllowed(t Target) (net.Conn, error) {
	return p.dialResolved(t)(context.Background(), "tcp", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)))
}

func (p *Proxyd) dialResolved(t Target) func(context.Context, string, string) (net.Conn, error) {
	var (
		once sync.Once
		ip   net.IP
		err  error
	)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		once.Do(func() {
			ip, err = p.resolveOnce(ctx, t.Host)
		})
		if err != nil {
			return nil, err
		}
		_, portText, splitErr := net.SplitHostPort(addr)
		if splitErr != nil || portText == "" {
			portText = strconv.Itoa(t.Port)
		}
		d := net.Dialer{Timeout: 10 * time.Second}
		dial := d.DialContext
		if p.dialTCP != nil {
			dial = p.dialTCP
		}
		return dial(ctx, network, net.JoinHostPort(ip.String(), portText))
	}
}

func (p *Proxyd) resolveOnce(ctx context.Context, host string) (net.IP, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ip := net.ParseIP(host)
	if ip == nil {
		lookup := net.DefaultResolver.LookupIPAddr
		if p.lookupIP != nil {
			lookup = p.lookupIP
		}
		addrs, err := lookup(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(addrs) == 0 {
			return nil, fmt.Errorf("no DNS addresses")
		}
		ip = addrs[0].IP
	}
	return ip, nil
}
