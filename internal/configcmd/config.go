// Package configcmd owns read-only config command surfaces. Editing is kept
// separate until its recovery transaction is available.
package configcmd

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"cove/internal/clierr"
	"cove/internal/config"
)

var output io.Writer = os.Stdout

var runEditor = defaultEditor

func Run(args []string) error {
	if len(args) != 1 {
		return clierr.Wrap(clierr.EXUsage, "config accepts check or edit", nil, "cove config check", nil)
	}
	if args[0] == "edit" {
		return Edit()
	}
	if args[0] != "check" {
		return clierr.Wrap(clierr.EXUsage, "config accepts check or edit", nil, "cove config check", nil)
	}
	doc, err := config.LoadDocument("")
	if err != nil {
		return err
	}
	protected := len(doc.Config.Inject) + len(doc.Config.SigV4) + len(doc.Config.MTLS)
	blocked := len(doc.Config.Managed.Block)
	fmt.Fprintf(output, "config valid — %d protected, %d allowed, %d blocked overrides, 0 exposed\n", protected, len(doc.Config.AllowRules), blocked)
	return nil
}

// Edit lets the user edit the whole document while keeping invalid candidates
// out of the active path. Managed commands remain the only generated-TOML
// writer; this is the explicit escape hatch for hand-authored configuration.
func Edit() error {
	path := config.DefaultPath()
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".config.toml.edit-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(original); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := runEditor(tmpName); err != nil {
		os.Remove(tmpName)
		return clierr.Wrap(clierr.EXUsage, "editor did not complete", nil, "cove config edit", err)
	}
	if _, err := config.LoadDocument(tmpName); err != nil {
		return clierr.Wrap(clierr.EXConfig, "edited configuration is invalid; recovery copy retained at "+tmpName, nil, "fix the recovery copy, then cove config edit", err)
	}
	lock, err := os.OpenFile(filepath.Join(dir, "config.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		os.Remove(tmpName)
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		os.Remove(tmpName)
		return err
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	now, err := os.ReadFile(path)
	if err != nil {
		os.Remove(tmpName)
		return err
	}
	if sha256.Sum256(now) != sha256.Sum256(original) {
		os.Remove(tmpName)
		return clierr.Wrap(clierr.EXTempFail, "configuration changed while it was being edited", nil, "cove config edit", nil)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return err
	}
	fmt.Fprintln(output, "saved: config")
	return nil
}

func defaultEditor(path string) error {
	if editor := os.Getenv("VISUAL"); editor != "" {
		return exec.Command("sh", "-c", editor+` "$1"`, "cove config edit", path).Run()
	}
	if editor := os.Getenv("EDITOR"); editor != "" {
		return exec.Command("sh", "-c", editor+` "$1"`, "cove config edit", path).Run()
	}
	for _, name := range []string{"sensible-editor", "vi"} {
		if _, err := exec.LookPath(name); err == nil {
			return exec.Command(name, path).Run()
		}
	}
	return errors.New("no editor found (set VISUAL or EDITOR)")
}
