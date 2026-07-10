package proxy

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"cove/internal/config"
)

// PendingAllow is durable only until the next acknowledged ordinary session.
// Rule is stored in its canonical, display-safe form rather than accepting a
// second matching grammar here.
type PendingAllow struct {
	Rule      string    `json:"rule"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func pendingPaths(state string) (string, string) {
	return filepath.Join(state, "pending-allows.json"), filepath.Join(state, "pending-allows.lock")
}

func withPendingLock(state string, fn func(string) error) error {
	if err := os.MkdirAll(state, 0700); err != nil {
		return err
	}
	_, lockPath := pendingPaths(state)
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	path, _ := pendingPaths(state)
	return fn(path)
}

func readPending(path string) ([]PendingAllow, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []PendingAllow
	if err := json.Unmarshal(b, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func writePending(path string, entries []PendingAllow) error {
	b, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pending-allows-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// QueuePendingAllow coalesces duplicate grants and drops stale entries.
func QueuePendingAllow(state string, rule config.AllowRule, now time.Time) error {
	if rule.Wildcard {
		return errors.New("wildcards are not accepted for one-shot allows")
	}
	canonical := config.FormatExactRule(rule)
	return withPendingLock(state, func(path string) error {
		entries, err := readPending(path)
		if err != nil {
			return err
		}
		out := entries[:0]
		for _, e := range entries {
			if !e.ExpiresAt.After(now) {
				continue
			}
			if e.Rule == canonical {
				out = append(out, e)
				return writePending(path, out)
			}
			out = append(out, e)
		}
		out = append(out, PendingAllow{Rule: canonical, CreatedAt: now.UTC(), ExpiresAt: now.UTC().Add(24 * time.Hour)})
		return writePending(path, out)
	})
}

// ClaimPendingAllows atomically consumes every live entry. It is called only
// after REGISTER/2's OK has been acknowledged, so failed registrations leave
// the queue intact and concurrent sessions have one winner.
func ClaimPendingAllows(state string, now time.Time) ([]config.AllowRule, error) {
	var claimed []config.AllowRule
	err := withPendingLock(state, func(path string) error {
		entries, err := readPending(path)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !e.ExpiresAt.After(now) {
				continue
			}
			r, err := config.ParseExactRule(e.Rule)
			if err != nil {
				continue
			} // never turn corrupt queue text into policy
			claimed = append(claimed, r)
		}
		return writePending(path, nil)
	})
	return claimed, err
}
