// Package sessioncmd renders the deliberately small local session index.
package sessioncmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"cove/internal/clierr"
	"cove/internal/config"
	"cove/internal/session"
)

type entry struct {
	id, path string
	meta     *session.Metadata
	started  time.Time
}

func Run(args []string) error { return run(args, config.StateDir(), os.Stdout, os.Stderr, time.Now()) }

func run(args []string, state string, out, stderr io.Writer, now time.Time) error {
	fs := flag.NewFlagSet("cove sessions", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	verbose := fs.Bool("verbose", false, "show full IDs and metadata paths")
	if err := fs.Parse(args); err != nil {
		return clierr.Wrap(clierr.EXUsage, "invalid sessions option", nil, "cove help sessions", err)
	}
	if fs.NArg() != 0 {
		return clierr.Wrap(clierr.EXUsage, "sessions accepts no positional arguments", nil, "cove help sessions", nil)
	}
	entries := enumerate(state, stderr)
	sort.Slice(entries, func(i, j int) bool { return entries[i].started.After(entries[j].started) })
	if len(entries) == 0 {
		return nil
	}
	prefixes := uniquePrefixes(entries)
	tw := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTART\tELAPSED\tAGENT\tPROJECT\tRESULT\tAUDIT")
	for i, e := range entries {
		id := prefixes[i]
		agent, project, result, audit := "legacy", "-", "unknown exit", "on"
		if e.meta != nil {
			agent, project = e.meta.Agent, e.meta.ProjectBasename
			if !e.meta.Complete {
				result = "interrupted"
			} else if e.meta.ExitCode != nil {
				result = fmt.Sprintf("exit %d", *e.meta.ExitCode)
			} else {
				result = "exit unknown"
			}
			if e.meta.Audit {
				audit = "on"
			} else {
				audit = "off"
			}
		}
		if *verbose {
			id = e.id
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", id, e.started.Local().Format("2006-01-02 15:04"), elapsed(now.Sub(e.started)), agent, project, result, audit)
		if *verbose && e.path != "" {
			fmt.Fprintf(tw, "\tmetadata: %s\n", e.path)
		}
	}
	return tw.Flush()
}

func enumerate(state string, stderr io.Writer) []entry {
	metaDir := filepath.Join(state, "sessions", "meta")
	byID := map[string]entry{}
	if files, err := os.ReadDir(metaDir); err == nil {
		for _, f := range files {
			if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
				continue
			}
			p := filepath.Join(metaDir, f.Name())
			b, err := os.ReadFile(p)
			var m session.Metadata
			if err != nil || json.Unmarshal(b, &m) != nil || m.Schema != session.Schema || m.ID == "" || m.StartedAt.IsZero() {
				fmt.Fprintln(stderr, "cove: warning: skipping corrupt session metadata "+p)
				continue
			}
			m2 := m
			byID[m.ID] = entry{id: m.ID, path: p, meta: &m2, started: m.StartedAt}
		}
	}
	for _, suffix := range []string{".5", ".4", ".3", ".2", ".1", ""} {
		f, err := os.Open(filepath.Join(state, "audit.log") + suffix)
		if err != nil {
			continue
		}
		dec := json.NewDecoder(f)
		for {
			var r struct {
				Session string    `json:"session"`
				TS      time.Time `json:"ts"`
			}
			if dec.Decode(&r) != nil {
				break
			}
			if r.Session != "" {
				if old, ok := byID[r.Session]; !ok || old.started.IsZero() {
					byID[r.Session] = entry{id: r.Session, started: r.TS}
				}
			}
		}
		_ = f.Close()
	}
	out := make([]entry, 0, len(byID))
	for _, e := range byID {
		out = append(out, e)
	}
	return out
}

func uniquePrefixes(entries []entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		n := 8
		if len(e.id) < n {
			n = len(e.id)
		}
		for {
			p := e.id[:n]
			unique := true
			for j, other := range entries {
				if i != j && strings.HasPrefix(other.id, p) {
					unique = false
					break
				}
			}
			if unique || n == len(e.id) {
				out[i] = p
				break
			}
			n++
		}
	}
	return out
}
func elapsed(d time.Duration) string {
	if d < time.Minute {
		return "<1m"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
