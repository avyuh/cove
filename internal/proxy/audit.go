package proxy

import (
	"io"
	"sync"
	"time"
)

type AuditRecord struct {
	TS      time.Time `json:"ts"`
	Session string    `json:"session"`
	Policy  string    `json:"policy"`
	Host    string    `json:"host"`
	Port    int       `json:"port"`
	Method  string    `json:"method,omitempty"`
	Path    string    `json:"path,omitempty"`
	Status  int       `json:"status,omitempty"`
	BytesUp int64     `json:"bytes_up"`
	BytesDn int64     `json:"bytes_down"`
	DurMS   int64     `json:"dur_ms"`
	Agent   string    `json:"agent,omitempty"`
}

type countingReadCloser struct {
	rc      io.ReadCloser
	n       int64
	onClose func(n int64)
	once    sync.Once
}

func (c *countingReadCloser) Read(p []byte) (int, error) {
	m, err := c.rc.Read(p)
	c.n += int64(m)
	return m, err
}

func (c *countingReadCloser) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			c.onClose(c.n)
		}
	})
	return c.rc.Close()
}
