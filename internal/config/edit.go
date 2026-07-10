package config

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"cove/internal/clierr"
	"github.com/BurntSushi/toml"
)

const (
	managedBegin = "# BEGIN COVE MANAGED — written by cove commands"
	managedEnd   = "# END COVE MANAGED"
)

type managedRange struct{ start, end int }
type fileStamp struct {
	ino    uint64
	size   int64
	sum    [sha256.Size]byte
	exists bool
}

// EditManaged is the sole TOML-writing API. The callback sees only the
// cove-owned namespace; user bytes are neither decoded for rendering nor
// regenerated. The context is reserved for command cancellation seams.
func EditManaged(ctx context.Context, mutate func(*rawManaged) error) error {
	return EditManagedPath(ctx, DefaultPath(), mutate)
}

// AddManagedAllow adds one cove-owned exact allow rule. It is intentionally a
// narrow wrapper around EditManaged: command packages must not need access to
// the editor's internal raw TOML representation.
func AddManagedAllow(ctx context.Context, rule AllowRule) (bool, error) {
	return AddManagedAllowPath(ctx, DefaultPath(), rule)
}

// AddManagedAllowPath is the path-explicit form used by tests.
// It returns false when the effective managed entry already exists.
func AddManagedAllowPath(ctx context.Context, path string, rule AllowRule) (bool, error) {
	if rule.Wildcard {
		return false, errors.New("wildcards are not accepted for managed allows")
	}
	host := FormatExactRule(rule)
	added := false
	err := EditManagedPath(ctx, path, func(m *rawManaged) error {
		for _, allow := range m.Allow {
			existing, err := ParseExactRule(allow.Host)
			if err == nil && FormatExactRule(existing) == host {
				return nil
			}
		}
		name := "allow:" + host
		used := map[string]bool{}
		for _, allow := range m.Allow {
			used[allow.Name] = true
		}
		for _, st := range m.Inject {
			used[st.Name] = true
		}
		for _, st := range m.SigV4 {
			used[st.Name] = true
		}
		for _, st := range m.MTLS {
			used[st.Name] = true
		}
		if used[name] {
			for i := 2; ; i++ {
				candidate := fmt.Sprintf("%s-%d", name, i)
				if !used[candidate] {
					name = candidate
					break
				}
			}
		}
		m.Version = 1
		m.Allow = append(m.Allow, NamedAllow{Name: name, Host: host})
		added = true
		return nil
	})
	return added, err
}

// EditManagedPath exists for tests and for callers that already resolved a
// configuration path.
func EditManagedPath(ctx context.Context, path string, mutate func(*rawManaged) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(dir, "config.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)

	data, before, err := secureRead(path)
	if err != nil {
		return err
	}
	rng, err := findManagedRange(data)
	if err != nil {
		return configError(err)
	}
	if rng.start < 0 && hasManagedTableOutside(data) {
		return configError(errors.New("[managed] exists outside the managed markers; fix: move [managed] between the COVE MANAGED markers"))
	}
	var managed rawManaged
	if rng.start >= 0 {
		if _, err := DecodeDocument(path, data); err != nil {
			return err
		} // never replace undecodable data
		var holder struct {
			Managed rawManaged `toml:"managed"`
		}
		if _, err := toml.Decode(string(data[rng.start:rng.end]), &holder); err != nil {
			return configError(err)
		}
		managed = holder.Managed
	}
	if err := mutate(&managed); err != nil {
		return err
	}
	if managed.Version == 0 {
		managed.Version = 1
	}
	region, err := renderManaged(managed, newlineFor(data))
	if err != nil {
		return err
	}
	candidate := replaceManaged(data, rng, region)
	if _, err := DecodeDocument(path, candidate); err != nil {
		return err
	} // validate before temp creation

	tmp, err := os.OpenFile(filepath.Join(dir, ".config.toml.tmp-"+randomSuffix()), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(candidate); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	_, after, err := secureRead(path)
	if err != nil {
		return err
	}
	if before != after {
		return clierr.Wrap(clierr.EXTempFail, "configuration changed while it was being edited", nil, "cove config edit", nil)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return err
	}
	// TODO(card 5): issue RELOAD/2 and surface a non-rollback reload warning.
	return nil
}

func configError(err error) error {
	return clierr.Wrap(clierr.EXConfig, "could not edit the policy", nil, "cove config edit", err)
}

func secureRead(path string) ([]byte, fileStamp, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil, fileStamp{}, nil
		}
		return nil, fileStamp{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, fileStamp{}, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uint32(os.Getuid()) {
		return nil, fileStamp{}, fmt.Errorf("config must be a regular file owned by the invoking user")
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return nil, fileStamp{}, err
	}
	return b, fileStamp{ino: st.Ino, size: st.Size, sum: sha256.Sum256(b), exists: true}, nil
}

func (s fileStamp) equal(t fileStamp) bool {
	return s.exists == t.exists && s.ino == t.ino && s.size == t.size && s.sum == t.sum
}

func findManagedRange(data []byte) (managedRange, error) {
	begin, end := -1, -1
	multiline := ""
	for off := 0; off <= len(data); {
		n := len(data)
		if i := strings.IndexByte(string(data[off:]), '\n'); i >= 0 {
			n = off + i
		}
		line := strings.TrimSuffix(string(data[off:n]), "\r")
		if multiline == "" && line == managedBegin {
			if begin >= 0 || end >= 0 {
				return managedRange{}, errors.New("duplicate or nested COVE MANAGED markers")
			}
			begin = off
		}
		if multiline == "" && line == managedEnd {
			if end >= 0 || begin < 0 {
				return managedRange{}, errors.New("missing or reversed COVE MANAGED markers")
			}
			end = n
			if n < len(data) {
				end++
			}
		}
		if n == len(data) {
			break
		}
		// A marker-looking comment inside a TOML multiline string is data, not
		// a comment line. This deliberately small lexical guard is all the
		// managed strategy needs; TOML decoding remains authoritative.
		if multiline != "" {
			if strings.Contains(line, multiline) {
				multiline = ""
			}
		} else if strings.Count(line, `"""`)%2 == 1 {
			multiline = `"""`
		} else if strings.Count(line, `'''`)%2 == 1 {
			multiline = `'''`
		}
		off = n + 1
	}
	if (begin < 0) != (end < 0) {
		return managedRange{}, errors.New("missing COVE MANAGED marker")
	}
	if begin < 0 {
		return managedRange{start: -1, end: -1}, nil
	}
	return managedRange{start: begin, end: end}, nil
}

func hasManagedTableOutside(data []byte) bool {
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "[managed]" {
			return true
		}
	}
	return false
}

func newlineFor(data []byte) string {
	if strings.Contains(string(data), "\r\n") {
		return "\r\n"
	}
	return "\n"
}

func renderManaged(m rawManaged, nl string) ([]byte, error) {
	var b strings.Builder
	if err := toml.NewEncoder(&b).Encode(struct {
		Managed rawManaged `toml:"managed"`
	}{m}); err != nil {
		return nil, err
	}
	text := strings.ReplaceAll(b.String(), "\n", nl)
	return []byte(managedBegin + nl + text + managedEnd + nl), nil
}

func replaceManaged(data []byte, r managedRange, region []byte) []byte {
	if r.start >= 0 {
		return append(append(append([]byte(nil), data[:r.start]...), region...), data[r.end:]...)
	}
	if len(data) == 0 {
		return region
	}
	// Exactly one separator newline is appended, preserving every existing byte.
	sep := "\n"
	if strings.HasSuffix(string(data), "\r\n") {
		sep = "\r\n"
	}
	return append(append(append([]byte(nil), data...), []byte(sep)...), region...)
}

func randomSuffix() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d-%d", os.Getpid(), os.Getuid())
	}
	return fmt.Sprintf("%x", b[:])
}

// CreateIfAbsentAtomic stores host-side secret material without ever following
// a symlink. Callers must invoke it before adding a stanza that references it.
func CreateIfAbsentAtomic(path string, value []byte) error {
	if len(value) > 1<<20 {
		return fmt.Errorf("secret exceeds 1 MiB limit")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(value); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	return f.Chmod(0600)
}
