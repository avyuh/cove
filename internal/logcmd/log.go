package logcmd

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	fs.BoolVar(&opts.Follow, "follow", false, "follow audit log")
	fs.StringVar(&opts.Session, "session", "", "filter by session id")
	fs.StringVar(&opts.Host, "host", "", "filter by host")
	fs.BoolVar(&opts.DenyOnly, "deny-only", false, "show deny records only")
	if err := fs.Parse(args); err != nil {
		return err
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
	var off int64
	for {
		f, err := os.Open(path)
		if err == nil {
			if _, err := f.Seek(off, io.SeekStart); err == nil {
				r := bufio.NewReader(f)
				for {
					line, err := r.ReadBytes('\n')
					if len(line) > 0 {
						off += int64(len(line))
						printIfMatch(line, opts)
					}
					if err != nil {
						break
					}
				}
			}
			_ = f.Close()
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func scan(r io.Reader, opts Opts) error {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		printIfMatch(append([]byte{}, append(sc.Bytes(), '\n')...), opts)
	}
	return sc.Err()
}

func printIfMatch(line []byte, opts Opts) {
	var rec proxy.AuditRecord
	if err := json.Unmarshal(line, &rec); err != nil {
		return
	}
	if opts.DenyOnly && rec.Policy != "deny" {
		return
	}
	if opts.Session != "" && rec.Session != opts.Session {
		return
	}
	if opts.Host != "" && rec.Host != opts.Host {
		return
	}
	fmt.Print(string(line))
}
