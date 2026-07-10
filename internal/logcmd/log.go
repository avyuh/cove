package logcmd

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"cove/internal/clierr"
	"cove/internal/config"
	"cove/internal/session"
	"golang.org/x/term"
)

type Opts struct {
	Follow    bool
	Session   string
	Host      string
	DenyOnly  bool
	JSON      bool
	Last      bool
	Blocked   bool
	Since     time.Time
	OutputTTY bool

	// resolvedSession is deliberately separate from the command-line selector:
	// all filtering always uses a complete, unambiguous ID.
	resolvedSession string
	auditOff        bool
}

func Run(args []string) error {
	fs := flag.NewFlagSet("cove log", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts Opts
	var since string
	fs.BoolVar(&opts.Follow, "follow", false, "keep reading new audit records")
	fs.StringVar(&opts.Session, "session", "", "show records for one session id")
	fs.StringVar(&opts.Host, "host", "", "show records for one host")
	fs.BoolVar(&opts.DenyOnly, "deny-only", false, `show records with policy "deny" only`)
	fs.BoolVar(&opts.Blocked, "blocked", false, `alias for --deny-only`)
	fs.BoolVar(&opts.JSON, "json", false, "write JSONL")
	fs.BoolVar(&opts.Last, "last", false, "show the latest session")
	fs.StringVar(&since, "since", "", "show records since a duration or RFC3339 time")
	help := fs.Bool("help", false, "show help")
	fs.BoolVar(help, "h", false, "show help")
	fs.Usage = func() { usage(fs.Output()) }
	if err := fs.Parse(args); err != nil {
		return clierr.Wrap(clierr.EXUsage, "invalid log option", nil, "cove help log", err)
	}
	if *help {
		usage(fs.Output())
		return nil
	}
	if fs.NArg() != 0 {
		return clierr.Wrap(clierr.EXUsage, "log accepts no positional arguments", nil, "cove help log", nil)
	}
	if opts.Last && opts.Session != "" {
		return clierr.Wrap(clierr.EXUsage, "--last conflicts with --session", nil, "cove help log", nil)
	}
	if opts.Blocked {
		opts.DenyOnly = true
	}
	if since != "" {
		v, err := parseSince(since, time.Now())
		if err != nil {
			return clierr.Wrap(clierr.EXUsage, "invalid --since value", nil, "cove help log", err)
		}
		opts.Since = v
	}
	opts.OutputTTY = term.IsTerminal(int(os.Stdout.Fd()))

	// A selector pins follow. Without one, following remains intentionally
	// unpinned so sessions that begin after cove log starts are visible.
	selector := opts.Session
	if opts.Last || (!opts.Follow && selector == "") {
		selector = "last"
	}
	if selector != "" {
		resolved, err := session.Resolve(config.StateDir(), selector, os.Stderr)
		if err != nil {
			// A fresh install has neither session metadata nor an audit file. It
			// is an empty log, not a usage error merely because there is no
			// "latest" session to select.
			if selector == "last" && freshLog(config.StateDir()) {
				return scanRotated(filepath.Join(config.StateDir(), "audit.log"), opts, os.Stdout)
			}
			return err
		}
		opts.resolvedSession = resolved.ID
		opts.Session = resolved.ID
		opts.auditOff = resolved.Metadata != nil && !resolved.Metadata.Audit
	}
	path := filepath.Join(config.StateDir(), "audit.log")
	if opts.Follow {
		return follow(path, opts)
	}
	return scanRotated(path, opts, os.Stdout)
}

func freshLog(stateDir string) bool {
	if _, err := os.Stat(filepath.Join(stateDir, "audit.log")); err == nil {
		return false
	}
	if entries, err := os.ReadDir(filepath.Join(stateDir, "sessions", "meta")); err == nil && len(entries) != 0 {
		return false
	}
	return true
}

func follow(path string, opts Opts) error {
	return followContext(context.Background(), path, opts, os.Stdout, 500*time.Millisecond)
}

type fileID struct{ dev, ino uint64 }

// followContext deliberately retains the established reopen/truncate/rewrite
// state machine. filterAndWrite is the only output seam added around it.
func followContext(ctx context.Context, path string, opts Opts, out io.Writer, interval time.Duration) error {
	var off int64
	var lastID fileID
	var haveID bool
	var prefix []byte
	// watch holds the previous inode between polls. On rotation it lets us
	// drain writes that landed in the renamed file before switching to the new
	// audit.log inode.
	var watch *os.File
	var watchID fileID
	defer func() {
		if watch != nil {
			_ = watch.Close()
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		f, err := os.Open(path)
		if err == nil {
			var currentID fileID
			var currentIDOK bool
			st, statErr := f.Stat()
			if statErr == nil {
				id, idOK := statFile(st)
				currentID, currentIDOK = id, idOK
				rotated := idOK && (!haveID || id != lastID)
				if rotated && haveID && watch != nil && watchID == lastID {
					off = drainFollowFile(watch, off, out, opts)
				}
				truncated := st.Size() < off
				currentPrefix := readPrefix(f, st.Size())
				rewritten := !rotated && !truncated && len(prefix) > 0 && !hasStoredPrefix(currentPrefix, prefix)
				if rotated || truncated || rewritten {
					off = 0
					prefix = nil
				}
				if idOK {
					lastID = id
					haveID = true
				}
				if len(currentPrefix) > len(prefix) && hasStoredPrefix(currentPrefix, prefix) {
					prefix = currentPrefix
				}
			}
			if _, err := f.Seek(off, io.SeekStart); err == nil {
				r := bufio.NewReader(f)
				for {
					line, err := r.ReadBytes('\n')
					if len(line) > 0 && bytes.HasSuffix(line, []byte{'\n'}) {
						off += int64(len(line))
						filterAndWrite(out, line, opts)
					}
					if err != nil {
						break
					}
				}
			}
			_ = f.Close()
			// Keep a descriptor to this inode until the next poll. Closing it
			// here would create a rotation gap for a writer that still has the
			// old audit file open.
			if currentIDOK {
				if next, openErr := os.Open(path); openErr == nil {
					if old := watch; old != nil {
						_ = old.Close()
					}
					watch, watchID = next, currentID
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func drainFollowFile(f *os.File, off int64, out io.Writer, opts Opts) int64 {
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return off
	}
	r := bufio.NewReader(f)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && bytes.HasSuffix(line, []byte{'\n'}) {
			off += int64(len(line))
			filterAndWrite(out, line, opts)
		}
		if err != nil {
			return off
		}
	}
}

func statFile(st os.FileInfo) (fileID, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return fileID{}, false
	}
	return fileID{dev: uint64(sys.Dev), ino: uint64(sys.Ino)}, true
}

func readPrefix(f *os.File, size int64) []byte {
	if size <= 0 {
		return nil
	}
	n := 256
	if size < int64(n) {
		n = int(size)
	}
	buf := make([]byte, n)
	m, err := f.ReadAt(buf, 0)
	if err != nil && err != io.EOF {
		return nil
	}
	return buf[:m]
}

func hasStoredPrefix(current, stored []byte) bool {
	return len(stored) == 0 || (len(current) >= len(stored) && bytes.Equal(current[:len(stored)], stored))
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: cove log [--follow] [--last | --session ID] [--host HOST] [--blocked | --deny-only] [--since 2h|RFC3339] [--json]

Read audit records. Non-terminal output and --json preserve matching JSONL bytes exactly.

Options:
      --follow       keep reading new audit records
      --last         show the latest session (the default without --follow)
      --session ID   show one full or unique-prefix session ID
      --host HOST    show records for one host
      --blocked      alias for --deny-only
      --deny-only    show records with policy "deny" only
      --since VALUE  positive duration or RFC3339 timestamp
      --json         write raw JSONL even to a terminal
  -h, --help         show help
`)
}
