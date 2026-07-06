package logcmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"cove/internal/config"
	"cove/internal/proxy"
)

type Opts struct {
	Follow   bool
	Session  string
	Host     string
	DenyOnly bool
}

func Run(args []string) error {
	fs := flag.NewFlagSet("cove log", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var opts Opts
	fs.BoolVar(&opts.Follow, "follow", false, "keep reading new audit records")
	fs.StringVar(&opts.Session, "session", "", "show records for one session id")
	fs.StringVar(&opts.Host, "host", "", "show records for one host")
	fs.BoolVar(&opts.DenyOnly, "deny-only", false, `show records with policy "deny" only`)
	help := fs.Bool("help", false, "show help")
	fs.BoolVar(help, "h", false, "show help")
	fs.Usage = func() { usage(fs.Output()) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *help {
		usage(fs.Output())
		return nil
	}
	path := filepath.Join(config.StateDir(), "audit.log")
	if opts.Follow {
		return follow(path, opts)
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return scan(f, opts)
}

func follow(path string, opts Opts) error {
	return followContext(context.Background(), path, opts, os.Stdout, 500*time.Millisecond)
}

type fileID struct {
	dev uint64
	ino uint64
}

func followContext(ctx context.Context, path string, opts Opts, out io.Writer, interval time.Duration) error {
	var off int64
	var lastID fileID
	var haveID bool
	var prefix []byte
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		f, err := os.Open(path)
		if err == nil {
			st, statErr := f.Stat()
			if statErr == nil {
				id, idOK := statFile(st)
				rotated := idOK && (!haveID || id != lastID)
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
						printIfMatchTo(out, line, opts)
					}
					if err != nil {
						break
					}
				}
			}
			_ = f.Close()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func scan(r io.Reader, opts Opts) error {
	return scanTo(r, opts, os.Stdout)
}

func scanTo(r io.Reader, opts Opts, out io.Writer) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		printIfMatchTo(out, append([]byte{}, append(sc.Bytes(), '\n')...), opts)
	}
	return sc.Err()
}

func printIfMatch(line []byte, opts Opts) {
	printIfMatchTo(os.Stdout, line, opts)
}

func printIfMatchTo(out io.Writer, line []byte, opts Opts) bool {
	var rec proxy.AuditRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return false
	}
	if opts.DenyOnly && rec.Policy != "deny" {
		return false
	}
	if opts.Session != "" && rec.Session != opts.Session {
		return false
	}
	if opts.Host != "" && rec.Host != opts.Host {
		return false
	}
	fmt.Fprint(out, string(line))
	return true
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
	const maxPrefix = 256
	n := maxPrefix
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
	if len(stored) == 0 {
		return true
	}
	if len(current) < len(stored) {
		return false
	}
	return bytes.Equal(current[:len(stored)], stored)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: cove log [--follow] [--session ID] [--host HOST] [--deny-only]

Read the JSONL audit trail for cove's credential firewall.

By default, cove log prints existing records from:
  $XDG_STATE_HOME/cove/audit.log
  ~/.local/state/cove/audit.log when XDG_STATE_HOME is unset

Options compose: for example, --deny-only --host evil.example.com prints only
denied records for that host. Malformed records and half-written trailing lines
are skipped. With --follow, cove keeps reading new records and reopens the log
when it is rotated or truncated.

Options:
      --follow       keep reading new audit records
      --session ID   show records for one session id
      --host HOST    show records for one host
      --deny-only    show records with policy "deny" only
  -h, --help         show help

Examples:
  cove log --deny-only
  cove log --follow --deny-only
  cove log --session 1a2b3c4d --host api.anthropic.com
`)
}
