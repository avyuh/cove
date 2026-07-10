package logcmd

import (
	"io"
	"os"

	"cove/internal/proxy"
)

// scanRotated visits oldest files first. A source identity includes its byte
// offset: duplicate hard links are suppressed without ever comparing records.
func scanRotated(path string, opts Opts, out io.Writer) error {
	if opts.auditOff {
		if !rawMode(opts) {
			_, _ = io.WriteString(out, "session "+opts.Session+": audit was off; no records were stored\n")
		}
		return nil
	}
	seen := map[sourceOffset]bool{}
	var records []proxy.AuditRecord
	for i := 5; i >= 0; i-- {
		name := path
		if i > 0 {
			name += "." + string(rune('0'+i))
		}
		f, err := os.Open(name)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		st, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return err
		}
		id, ok := statFile(st)
		lines, err := readLines(f)
		_ = f.Close()
		if err != nil {
			return err
		}
		var offset int64
		for _, line := range lines {
			key := sourceOffset{id: id, off: offset}
			offset += int64(len(line))
			if ok && seen[key] {
				continue
			}
			if ok {
				seen[key] = true
			}
			if rawMode(opts) {
				filterAndWrite(out, line, opts)
				continue
			}
			if rec, accepted := accepts(line, opts); accepted {
				records = append(records, rec)
			}
		}
	}
	if !rawMode(opts) {
		renderTable(out, records, terminalWidth(out), colorEnabled(opts))
	}
	return nil
}

type sourceOffset struct {
	id  fileID
	off int64
}
