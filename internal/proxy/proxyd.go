package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"cove/internal/config"
	"cove/internal/secret"
	"cove/internal/version"
)

type Policy int

const (
	PolicyDeny Policy = iota
	PolicyAllow
	PolicyInject
)

type Session struct {
	ID         string
	Agent      string
	Audit      bool
	Events     *SessionEvents
	Matcher    *Matcher
	Diagnostic bool
}

type Proxyd struct {
	mu       sync.RWMutex
	cfg      *config.Config
	matcher  *Matcher
	audit    *AuditWriter
	ca       *CA
	secrets  *secret.Cache
	stateDir string
	sessDir  string
	log      io.Writer
	lookupIP lookupIPFunc
	dialTCP  dialTCPFunc
	now      func() time.Time

	warnMu        sync.Mutex
	warnedRelogin map[[32]byte]struct{}
	// claimAllows is the card-8 queue seam. It is intentionally a no-op until
	// that queue exists; diagnostic sessions must never consume claims.
	claimAllows func(Session) []config.AllowRule
}

type lookupIPFunc func(context.Context, string) ([]net.IPAddr, error)
type dialTCPFunc func(context.Context, string, string) (net.Conn, error)

func Serve(cfg *config.Config, sockPath string) error {
	state := config.StateDir()
	if sockPath == "" {
		sockPath = filepath.Join(state, "proxyd.sock")
	}
	if err := os.MkdirAll(filepath.Join(state, "sessions", "meta"), 0700); err != nil {
		return err
	}
	lock, held, err := acquireProxydLock(state)
	if err != nil {
		return err
	}
	if !held {
		return nil
	}
	defer lock.Close()
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = os.Remove(sockPath)
	sessions := filepath.Join(state, "sessions")
	// Session sockets live directly under sessions/ to keep the AF_UNIX path
	// short (sun_path is limited to ~108 bytes; a deeper sockets/ subdir
	// overflows it on long HOME/temp paths). Metadata gets its own sessions/meta/
	// namespace instead. Sweep here removes stale sockets from older daemons.
	if err := sweepSessionSockets(sessions); err != nil {
		return err
	}
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return err
	}
	defer ln.Close()
	_ = os.Chmod(sockPath, 0600)
	audit, err := NewAuditWriter(filepath.Join(state, "audit.log"))
	if err != nil {
		return err
	}
	defer audit.Close()
	ca, err := LoadCA(filepath.Join(config.ConfigDir(), "ca.pem"), filepath.Join(config.ConfigDir(), "ca-key.pem"))
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	p := &Proxyd{
		cfg:      cfg,
		matcher:  NewMatcher(cfg),
		audit:    audit,
		ca:       ca,
		secrets:  secret.NewCache(os.Stderr),
		stateDir: state,
		sessDir:  sessions,
		log:      os.Stderr,
		now:      proxyNow,
	}
	p.claimAllows = func(Session) []config.AllowRule {
		claimed, err := ClaimPendingAllows(p.stateDir, p.now())
		if err != nil {
			fmt.Fprintf(p.log, "cove proxyd: pending allows: %v\n", err)
			return nil
		}
		return claimed
	}
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			if err := p.reload(); err != nil {
				fmt.Fprintf(os.Stderr, "cove proxyd: reload: %v\n", err)
			}
		}
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go p.handleControl(c)
	}
}

func proxyNow() time.Time { return time.Now() }

var ErrDenied = errors.New("denied by policy")

func (p *Proxyd) reload() error {
	cfg, err := config.Load("")
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cfg = cfg
	p.matcher = NewMatcher(cfg)
	return nil
}

func (p *Proxyd) handleControl(c net.Conn) {
	defer c.Close()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	if line == "PING" {
		fmt.Fprintf(c, "PONG %s control=2\n", version.Version)
		return
	}
	if line == "RELOAD/2" {
		if err := p.reload(); err != nil {
			fmt.Fprintln(c, "ERR/2 reload failed")
			return
		}
		fmt.Fprintln(c, "OK/2 reload")
		return
	}
	if strings.HasPrefix(line, "REGISTER/2 ") {
		if len(line) > controlLineLimit {
			fmt.Fprintln(c, "ERR/2 control line too long")
			return
		}
		r, err := decodeRegister(strings.TrimPrefix(line, "REGISTER/2 "))
		if err != nil {
			fmt.Fprintln(c, "ERR/2 malformed REGISTER/2")
			return
		}
		_ = p.reload()
		sess := Session{ID: r.Session, Agent: r.Agent, Audit: *r.Audit, Events: NewSessionEvents(), Diagnostic: r.Diagnostic}
		p.register(c, sess)
		return
	}
	fmt.Fprintln(c, "ERR/2 unknown command")
}

func (p *Proxyd) register(control net.Conn, sess Session) {
	if sess.Events == nil {
		sess.Events = NewSessionEvents()
	}
	if sess.Matcher == nil {
		p.mu.RLock()
		sess.Matcher = p.matcher
		p.mu.RUnlock()
	}
	path := filepath.Join(p.sessDir, sess.ID+".sock")
	if unixSocketAccepts(path) {
		fmt.Fprintln(control, "ERR/2 session socket already live")
		return
	}
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintf(control, "ERR/2 %v\n", err)
		return
	}
	_ = os.Chmod(path, 0600)
	// A client cannot reach the session listener until it receives OK/2.  Claim
	// after that acknowledgement, which keeps failed registration from
	// consuming a one-shot grant.
	if _, err := fmt.Fprint(control, controlJSON("OK/2", controlOK{Socket: path, Session: sess.ID})); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return
	}
	if p.claimAllows != nil && !sess.Diagnostic {
		sess.Matcher = sess.Matcher.WithAllows(p.claimAllows(sess))
	}
	var handlers sync.WaitGroup
	var rawMu sync.Mutex
	raws := map[net.Conn]struct{}{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			rawMu.Lock()
			raws[c] = struct{}{}
			rawMu.Unlock()
			p.mu.RLock()
			audit := p.audit
			ca := p.ca
			secrets := p.secrets
			p.mu.RUnlock()
			conn := &Conn{
				raw:     c,
				br:      bufio.NewReader(c),
				sess:    sess,
				proxy:   p,
				matcher: sess.Matcher,
				ca:      ca,
				secrets: secrets,
				audit:   audit,
				started: timeNow(),
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { rawMu.Lock(); delete(raws, c); rawMu.Unlock() }()
				conn.handle()
			}()
		}
	}()
	// This goroutine is the sole writer after registration. Event streaming is
	// intentionally decoupled from proxy request handlers.
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for e := range sess.Events.ch {
			fmt.Fprint(control, controlJSON("EVENT/2", e.event))
		}
		if end := sess.Events.endMessage(); end != nil {
			fmt.Fprint(control, controlJSON("END/2", *end))
		}
	}()
	br := bufio.NewReader(control)
	line, err := br.ReadString('\n')
	clean := err == nil && strings.TrimSpace(line) == "DONE/2"
	_ = ln.Close()
	rawMu.Lock()
	closeRaw(raws)
	rawMu.Unlock()
	handlers.Wait()
	sess.Events.close(clean)
	<-writerDone
	<-done
	_ = os.Remove(path)
}

func acquireProxydLock(state string) (*os.File, bool, error) {
	lock, err := os.OpenFile(filepath.Join(state, "proxyd.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, false, nil
	}
	return lock, true, nil
}

func sweepSessionSockets(dir string) error {
	old, err := filepath.Glob(filepath.Join(dir, "*.sock"))
	if err != nil {
		return err
	}
	for _, p := range old {
		st, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if st.Mode()&os.ModeSocket == 0 {
			continue
		}
		if unixSocketAccepts(p) {
			continue
		}
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func unixSocketAccepts(path string) bool {
	c, err := net.DialTimeout("unix", path, 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func timeNow() time.Time {
	return time.Now()
}
