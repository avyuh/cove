package secret

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var ErrNotImplemented = errors.New("secret backend not implemented")

type Cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	env     map[string]string
	log     io.Writer
}

type cacheEntry struct {
	mtime int64
	size  int64
	value string
}

func NewCache(log io.Writer) *Cache {
	if log == nil {
		log = io.Discard
	}
	return &Cache{entries: map[string]cacheEntry{}, env: map[string]string{}, log: log}
}

var defaultCache = NewCache(io.Discard)

func Resolve(ref string) (string, error) {
	return defaultCache.Resolve(ref)
}

func (c *Cache) Resolve(ref string) (string, error) {
	if c == nil {
		c = defaultCache
	}
	c.ensure()
	switch {
	case strings.HasPrefix(ref, "file:"):
		return c.resolveFile(ref, strings.TrimPrefix(ref, "file:"))
	case strings.HasPrefix(ref, "json:"):
		body := strings.TrimPrefix(ref, "json:")
		path, dotted, ok := strings.Cut(body, "#")
		if !ok || path == "" || dotted == "" {
			return "", fmt.Errorf("json secret ref must be json:<path>#<dotted>")
		}
		return c.resolveJSON(ref, path, dotted)
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		if name == "" {
			return "", fmt.Errorf("env secret ref missing name")
		}
		return c.resolveEnv(name), nil
	case strings.HasPrefix(ref, "keyring:"):
		return "", fmt.Errorf("%w: keyring", ErrNotImplemented)
	default:
		return "", fmt.Errorf("unsupported secret ref %q", redactedRef(ref))
	}
}

func (c *Cache) ensure() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]cacheEntry{}
	}
	if c.env == nil {
		c.env = map[string]string{}
	}
	if c.log == nil {
		c.log = io.Discard
	}
}

func (c *Cache) resolveFile(ref, path string) (string, error) {
	return c.readCached(ref, path, func(data []byte) (string, error) {
		return strings.TrimRight(string(data), "\r\n"), nil
	})
}

func (c *Cache) resolveJSON(ref, path, dotted string) (string, error) {
	return c.readCached(ref, path, func(data []byte) (string, error) {
		var root any
		if err := json.Unmarshal(data, &root); err != nil {
			return "", err
		}
		v, ok := lookupDotted(root, dotted)
		if !ok {
			c.warn("json secret field %s missing in %s; injection inert", dotted, displayPath(path))
			return "", nil
		}
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("json secret field %s is not a string", dotted)
		}
		return s, nil
	})
}

func (c *Cache) resolveEnv(name string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.env[name]; ok {
		return v
	}
	v := os.Getenv(name)
	c.env[name] = v
	return v
}

func (c *Cache) readCached(ref, path string, parse func([]byte) (string, error)) (string, error) {
	expanded, err := expandPath(path)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(expanded)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.warn("secret file %s missing; injection inert", displayPath(path))
			return "", nil
		}
		return "", err
	}
	if st.Mode().Perm()&0007 != 0 {
		c.warn("secret file %s is world-readable", displayPath(path))
	}
	mtime := st.ModTime().UnixNano()
	size := st.Size()
	c.mu.Lock()
	if ent, ok := c.entries[ref]; ok && ent.mtime == mtime && ent.size == size {
		c.mu.Unlock()
		return ent.value, nil
	}
	c.mu.Unlock()
	data, err := os.ReadFile(expanded)
	if err != nil {
		return "", err
	}
	value, err := parse(data)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	c.entries[ref] = cacheEntry{mtime: mtime, size: size, value: value}
	c.mu.Unlock()
	return value, nil
}

func lookupDotted(root any, dotted string) (any, bool) {
	cur := root
	for _, part := range strings.Split(dotted, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func expandPath(path string) (string, error) {
	if path == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return home, nil
	}
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, strings.TrimPrefix(path, "~/")), nil
	}
	return path, nil
}

func (c *Cache) warn(format string, args ...any) {
	if c.log == nil {
		return
	}
	fmt.Fprintf(c.log, "cove: warning: "+format+"\n", args...)
}

func displayPath(path string) string {
	return filepath.Clean(path)
}

func redactedRef(ref string) string {
	if kind, _, ok := strings.Cut(ref, ":"); ok {
		return kind + ":<redacted>"
	}
	return "<redacted>"
}
