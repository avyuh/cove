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
	"cove/internal/version"
)

type Policy int

const (
	PolicyDeny Policy = iota
	PolicyAllow
	PolicyInject
)

type Session struct {
	ID    string
	Agent string
}

type Proxyd struct {
	mu       sync.RWMutex
	cfg      *config.Config
	matcher  *Matcher
	audit    *AuditWriter
	stateDir string
	sessDir  string
	log      io.Writer
	lookupIP lookupIPFunc
	dialTCP  dialTCPFunc
}

type lookupIPFunc func(context.Context, string) ([]net.IPAddr, error)
type dialTCPFunc func(context.Context, string, string) (net.Conn, error)

func Serve(cfg *config.Config, sockPath string) error {
	state := config.StateDir()
	if sockPath == "" {
		sockPath = filepath.Join(state, "proxyd.sock")
	}
	if err := os.MkdirAll(filepath.Join(state, "sessions"), 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(state, "proxyd.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	_ = os.Remove(sockPath)
	sessions := filepath.Join(state, "sessions")
	old, _ := filepath.Glob(filepath.Join(sessions, "*.sock"))
	for _, p := range old {
		_ = os.Remove(p)
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
	p := &Proxyd{
		cfg:      cfg,
		matcher:  NewMatcher(cfg),
		audit:    audit,
		stateDir: state,
		sessDir:  sessions,
		log:      os.Stderr,
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
		fmt.Fprintf(c, "PONG %s\n", version.Version)
		return
	}
	if strings.HasPrefix(line, "REGISTER ") {
		_ = p.reload()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			fmt.Fprintln(c, "ERR malformed REGISTER")
			return
		}
		p.register(c, Session{ID: parts[1], Agent: parts[2]})
		return
	}
	fmt.Fprintln(c, "ERR unknown command")
}

func (p *Proxyd) register(control net.Conn, sess Session) {
	path := filepath.Join(p.sessDir, sess.ID+".sock")
	_ = os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		fmt.Fprintf(control, "ERR %v\n", err)
		return
	}
	_ = os.Chmod(path, 0600)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			p.mu.RLock()
			matcher := p.matcher
			audit := p.audit
			p.mu.RUnlock()
			conn := &Conn{
				raw:     c,
				br:      bufio.NewReader(c),
				sess:    sess,
				proxy:   p,
				matcher: matcher,
				audit:   audit,
				started: timeNow(),
			}
			go conn.handle()
		}
	}()
	fmt.Fprintf(control, "OK %s\n", path)
	_, _ = io.Copy(io.Discard, control)
	_ = ln.Close()
	<-done
	_ = os.Remove(path)
}

func timeNow() time.Time {
	return time.Now()
}
