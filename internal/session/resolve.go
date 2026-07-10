package session

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"cove/internal/clierr"
)

// Resolved is a session known from metadata or, for pre-metadata sessions,
// from the audit trail alone.
type Resolved struct {
	ID       string
	Metadata *Metadata
	Started  time.Time
}

// Resolve resolves a full ID or any unique prefix. "last" chooses the newest
// metadata start time, with audit timestamps providing the legacy fallback.
func (s Store) Resolve(selector string) (Resolved, error) {
	all := s.enumerate()
	if selector == "last" {
		if len(all) == 0 {
			return Resolved{}, clierr.Wrap(clierr.EXUsage, "no sessions found", nil, "cove status", nil)
		}
		sort.Slice(all, func(i, j int) bool { return all[i].Started.After(all[j].Started) })
		return all[0], nil
	}
	var matches []Resolved
	for _, r := range all {
		if strings.HasPrefix(r.ID, selector) {
			matches = append(matches, r)
		}
	}
	if len(matches) == 1 {
		return matches[0], nil
	}
	if len(matches) == 0 {
		return Resolved{}, clierr.Wrap(clierr.EXUsage, "session not found: "+selector, nil, "cove sessions", nil)
	}
	ids := make([]string, 0, len(matches))
	for _, r := range matches {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return Resolved{}, clierr.Wrap(clierr.EXUsage, "ambiguous session prefix "+selector+": "+strings.Join(ids, ", "), nil, "cove sessions", nil)
}

func (s Store) enumerate() []Resolved {
	byID := map[string]Resolved{}
	entries, err := os.ReadDir(s.MetaDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(s.MetaDir, entry.Name())
			data, err := os.ReadFile(path)
			var m Metadata
			if err != nil || json.Unmarshal(data, &m) != nil || m.Schema != Schema || m.ID == "" || m.StartedAt.IsZero() {
				s.warn("cove: warning: skipping corrupt session metadata " + path)
				continue
			}
			byID[m.ID] = Resolved{ID: m.ID, Metadata: &m, Started: m.StartedAt}
		}
	}
	for id, ts := range s.auditTimes() {
		if old, ok := byID[id]; !ok || old.Started.IsZero() {
			byID[id] = Resolved{ID: id, Started: ts}
		}
	}
	out := make([]Resolved, 0, len(byID))
	for _, r := range byID {
		out = append(out, r)
	}
	return out
}

func (s Store) auditTimes() map[string]time.Time {
	result := map[string]time.Time{}
	state := filepath.Dir(filepath.Dir(s.MetaDir))
	for _, suffix := range []string{".5", ".4", ".3", ".2", ".1", ""} {
		f, err := os.Open(filepath.Join(state, "audit.log") + suffix)
		if err != nil {
			continue
		}
		dec := json.NewDecoder(f)
		for {
			var rec struct {
				Session string    `json:"session"`
				TS      time.Time `json:"ts"`
			}
			if err := dec.Decode(&rec); err != nil {
				break
			}
			if rec.Session != "" && (result[rec.Session].IsZero() || rec.TS.After(result[rec.Session])) {
				result[rec.Session] = rec.TS
			}
		}
		_ = f.Close()
	}
	return result
}

func (s Store) warn(msg string) {
	if s.Stderr != nil {
		fmt.Fprintln(s.Stderr, msg)
	}
}

// Resolve is the convenient production entry point using the standard state
// directory. Callers that need an isolated state directory use Store.Resolve.
func Resolve(stateDir, selector string, stderr io.Writer) (Resolved, error) {
	return NewStore(stateDir, stderr).Resolve(selector)
}
