package logcmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"cove/internal/proxy"
)

func parseSince(value string, now time.Time) (time.Time, error) {
	if d, err := time.ParseDuration(value); err == nil {
		if d <= 0 {
			return time.Time{}, fmt.Errorf("duration must be positive")
		}
		return now.Add(-d), nil
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil || t.After(now) {
		return time.Time{}, fmt.Errorf("must be a past duration or RFC3339 timestamp")
	}
	return t, nil
}

func accepts(line []byte, opts Opts) (proxy.AuditRecord, bool) {
	var rec proxy.AuditRecord
	if json.Unmarshal(line, &rec) != nil {
		return rec, false
	}
	if opts.DenyOnly && rec.Policy != "deny" {
		return rec, false
	}
	if opts.Session != "" && rec.Session != opts.Session {
		return rec, false
	}
	if opts.Host != "" && rec.Host != opts.Host {
		return rec, false
	}
	if !opts.Since.IsZero() && rec.TS.Before(opts.Since) {
		return rec, false
	}
	return rec, true
}

func rawMode(opts Opts) bool { return opts.JSON || !opts.OutputTTY }

func filterAndWrite(out io.Writer, line []byte, opts Opts) bool {
	rec, ok := accepts(line, opts)
	if !ok {
		return false
	}
	if rawMode(opts) {
		_, _ = out.Write(line)
		return true
	}
	renderRecord(out, rec, terminalWidth(out), colorEnabled(opts))
	return true
}

// Compatibility seams used by the baseline contract tests.
func scan(r io.Reader, opts Opts) error { return scanTo(r, opts, os.Stdout) }
func scanTo(r io.Reader, opts Opts, out io.Writer) error {
	lines, err := readLines(r)
	if err != nil {
		return err
	}
	if rawMode(opts) {
		for _, line := range lines {
			filterAndWrite(out, line, opts)
		}
		return nil
	}
	var records []proxy.AuditRecord
	for _, line := range lines {
		if rec, ok := accepts(line, opts); ok {
			records = append(records, rec)
		}
	}
	renderTable(out, records, terminalWidth(out), colorEnabled(opts))
	return nil
}
func printIfMatch(line []byte, opts Opts) { filterAndWrite(io.Discard, line, opts) }
func printIfMatchTo(out io.Writer, line []byte, opts Opts) bool {
	return filterAndWrite(out, line, opts)
}

func readLines(r io.Reader) ([][]byte, error) {
	var out [][]byte
	buf := make([]byte, 0, 64*1024)
	tmp := make([]byte, 32*1024)
	for {
		n, err := r.Read(tmp)
		buf = append(buf, tmp[:n]...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			out = append(out, append([]byte(nil), buf[:i+1]...))
			buf = buf[i+1:]
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func reasonLabel(reason string) string {
	if s, ok := map[string]string{"host_policy": "host policy", "policy_method": "method policy", "policy_resource": "resource policy", "policy_operation": "operation policy", "body_too_large": "body too large", "secret_unavailable": "secret unavailable", "upstream_tls": "upstream TLS", "presigned_url": "presigned URL", "sigv4a": "SigV4a", "streaming_signature": "streaming signature", "malformed_request": "malformed request", "spool_failure": "spool failure", "mtls_not_requested": "mTLS not requested"}[reason]; ok {
		return s
	}
	return strings.TrimSpace(reason)
}
