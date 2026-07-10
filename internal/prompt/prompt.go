// Package prompt contains command-side input only. It never touches the
// agent's PTY transport.
package prompt

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"

	"golang.org/x/term"
)

const maxSecret = 1 << 20

// Confirm reads only /dev/tty. A pipe is intentionally not a confirmation
// channel, because it is too easy for an agent or script to mutate policy.
func Confirm(message string, yes bool) error {
	if yes {
		return nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("confirmation requires a TTY; rerun with --yes")
	}
	defer tty.Close()
	if !term.IsTerminal(int(tty.Fd())) {
		return errors.New("confirmation requires a TTY; rerun with --yes")
	}
	if _, err := fmt.Fprintf(tty, "%s\nContinue? [y/N] ", message); err != nil {
		return err
	}
	var answer string
	if _, err := fmt.Fscanln(tty, &answer); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if strings.EqualFold(answer, "y") || strings.EqualFold(answer, "yes") {
		return nil
	}
	return errors.New("not confirmed")
}

// ReadPassword reads a secret without echo from /dev/tty. The returned bytes
// are never formatted by this package.
func ReadPassword(label string) ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, errors.New("could not open /dev/tty; use --secret-stdin --yes")
	}
	defer tty.Close()
	if !term.IsTerminal(int(tty.Fd())) {
		return nil, errors.New("could not use /dev/tty; use --secret-stdin --yes")
	}
	if _, err := fmt.Fprint(tty, label); err != nil {
		return nil, err
	}
	b, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(tty)
	if err != nil {
		return nil, err
	}
	return validateSecret(b)
}

// ReadSecretStdin is explicit opt-in for commands that support it.
func ReadSecretStdin(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSecret+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxSecret {
		return nil, errors.New("secret exceeds 1 MiB limit")
	}
	return validateSecret(b)
}

func validateSecret(b []byte) ([]byte, error) {
	s := strings.TrimFunc(string(b), unicode.IsSpace)
	if s == "" || strings.IndexByte(s, 0) >= 0 {
		return nil, errors.New("secret is empty or contains NUL")
	}
	return []byte(s), nil
}
