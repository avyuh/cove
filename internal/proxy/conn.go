package proxy

import (
	"bufio"
	"net"
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

type Proxyd struct{}
type Matcher struct{}
type CA struct{}
type AuditWriter struct{}
