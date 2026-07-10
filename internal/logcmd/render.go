package logcmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"cove/internal/proxy"
	"golang.org/x/term"
)

const ansiReset = "\x1b[0m"

func colorEnabled(opts Opts) bool {
	return opts.OutputTTY && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}
func terminalWidth(io.Writer) int {
	if w, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && w > 0 {
		return w
	}
	return 80
}

func renderTable(out io.Writer, records []proxy.AuditRecord, width int, color bool) {
	_, _ = io.WriteString(out, "TIME      VERDICT     HOST  METHOD PATH STATUS     UP   DOWN   TIME REASON\n")
	for _, rec := range records {
		renderRecordWidth(out, rec, width, color)
	}
}
func renderRecord(out io.Writer, rec proxy.AuditRecord, width int, color bool) {
	renderRecordWidth(out, rec, width, color)
}

func renderRecordWidth(out io.Writer, rec proxy.AuditRecord, width int, color bool) {
	if rec.Policy == "warn" || rec.Level == "warn" {
		fmt.Fprintf(out, "%s notice: %s\n", rec.TS.Local().Format("15:04:05"), rec.Message)
		return
	}
	verdict := map[string]string{"inject": "protected", "allow": "allowed", "deny": "blocked"}[rec.Policy]
	if verdict == "" {
		verdict = rec.Policy
	}
	if color {
		verdict = verdictColor(verdict) + verdict + ansiReset
	}
	method, path, status := dash(rec.Method), dash(rec.Path), dashInt(rec.Status)
	path = truncatePath(path, max(4, width-72-len(rec.Host)-len(reasonLabel(rec.Reason))))
	reason := dash(reasonLabel(rec.Reason))
	fmt.Fprintf(out, "%-8s %-19s %-*s %-6s %-*s %6s %6s %6s %6s %s\n", rec.TS.Local().Format("15:04:05"), verdict, len(rec.Host), rec.Host, method, len(path), path, status, size(rec.BytesUp), size(rec.BytesDn), duration(rec.DurMS), reason)
}
func verdictColor(v string) string {
	if v == "protected" {
		return "\x1b[32m"
	}
	if v == "allowed" {
		return "\x1b[36m"
	}
	if v == "blocked" {
		return "\x1b[31m"
	}
	return ""
}
func dash(v string) string {
	if v == "" {
		return "—"
	}
	return v
}
func dashInt(v int) string {
	if v == 0 {
		return "—"
	}
	return fmt.Sprint(v)
}
func size(n int64) string {
	if n == 0 {
		return "0B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%dB", n)
	}
	return fmt.Sprintf("%.1f%s", f, units[i])
}
func duration(ms int64) string {
	if ms == 0 {
		return "0ms"
	}
	return time.Duration(ms * int64(time.Millisecond)).String()
}
func truncatePath(s string, n int) string {
	if len(s) <= n || s == "—" {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return s[:n-1] + "…"
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
