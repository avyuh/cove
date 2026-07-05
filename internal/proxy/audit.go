package proxy

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
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
	err     error
}

type AuditWriter struct {
	mu   sync.Mutex
	path string
	file *os.File
}

func NewAuditWriter(path string) (*AuditWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &AuditWriter{path: path, file: f}, nil
}

func (a *AuditWriter) Emit(rec *AuditRecord) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return
	}
	if st, err := a.file.Stat(); err == nil && st.Size() > 64<<20 {
		a.rotateLocked()
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	_, _ = a.file.Write(append(b, '\n'))
}

func (a *AuditWriter) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	return err
}

func (a *AuditWriter) rotateLocked() {
	_ = a.file.Close()
	for i := 4; i >= 1; i-- {
		_ = os.Rename(a.path+"."+itoaAudit(i), a.path+"."+itoaAudit(i+1))
	}
	_ = os.Rename(a.path, a.path+".1")
	f, err := os.OpenFile(a.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		a.file = f
	}
}

func itoaAudit(n int) string {
	return string(rune('0' + n))
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
		c.err = c.rc.Close()
	})
	return c.err
}
