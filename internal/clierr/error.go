// Package clierr contains the single human-facing error renderer used by cove.
package clierr

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// Sysexits used at cove's command boundary.
const (
	EXUsage       = 64
	EXNoInput     = 66
	EXUnavailable = 69
	EXCantCreate  = 73
	EXIOErr       = 74
	EXTempFail    = 75
	EXNoPerm      = 77
	EXConfig      = 78
)

// Location identifies a safe, user-editable source location.
type Location struct {
	Path   string
	Line   int
	Column int
	Detail string
}

// Error is a command-boundary error. Cause is deliberately not rendered.
type Error struct {
	Code  int
	What  string
	Where *Location
	Fix   string
	Cause error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Cause != nil {
		return e.Cause.Error()
	}
	if e.What != "" {
		return e.What
	}
	return "cove failed"
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}
func (e *Error) ExitCode() int {
	if e == nil || e.Code == 0 {
		return 1
	}
	return e.Code
}

// Wrap adds the common command-boundary fields while retaining the cause for
// callers that need to inspect it.
func Wrap(code int, what string, where *Location, fix string, cause error) *Error {
	return &Error{Code: code, What: what, Where: where, Fix: fix, Cause: cause}
}

// Print renders the three-beat error form and returns its process exit code.
func Print(w io.Writer, err error) int {
	if err == nil {
		return 0
	}
	var ce *Error
	if !errors.As(err, &ce) {
		ce = &Error{Code: 1, What: err.Error()}
	}
	what := safe(ce.What)
	if what == "" {
		what = "cove failed"
	}
	fmt.Fprintf(w, "cove: %s\n", what)
	if ce.Where != nil {
		fmt.Fprintf(w, "where: %s\n", formatLocation(*ce.Where))
	}
	if ce.Fix != "" {
		fmt.Fprintf(w, "fix: %s\n", safe(ce.Fix))
	}
	return ce.ExitCode()
}

func formatLocation(l Location) string {
	path := safe(l.Path)
	if l.Line > 0 {
		path += fmt.Sprintf(":%d", l.Line)
		if l.Column > 0 {
			path += fmt.Sprintf(":%d", l.Column)
		}
	}
	if d := safe(l.Detail); d != "" {
		path += " — " + d
	}
	return path
}

// safe keeps terminals and log captures one-line and unambiguous.
func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
