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
	"strings"
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
	edited, err := config.LoadDocument(tmpName)
	if err != nil {
		return clierr.Wrap(clierr.EXConfig, "edited configuration is invalid; recovery copy retained at "+tmpName, nil, "fix the recovery copy, then cove config edit", err)
	}
	originalDoc, err := config.DecodeDocument(path, original)
	if err != nil {
		return err
	}
	if err := rejectProtectedDowngrade(originalDoc.Config, edited.Config); err != nil {
		return clierr.Wrap(clierr.EXConfig, "edited configuration would downgrade a protected host; recovery copy retained at "+tmpName, nil, "keep the protected policy, or use its explicit connection command", err)
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

func rejectProtectedDowngrade(before, after *config.Config) error {
	var protected []config.AllowRule
	for _, host := range protectedHosts(before) {
		rule, err := config.ParseRule(host)
		if err != nil {
			return err
		}
		protected = append(protected, rule)
	}
	for _, allow := range after.AllowRules {
		for _, rule := range protected {
			if policyRulesOverlap(rule, allow) {
				return fmt.Errorf("%s changes from protected to opaque allow", allow.Pattern)
			}
		}
	}
	return nil
}

func protectedHosts(cfg *config.Config) []string {
	hosts := make([]string, 0, len(cfg.Inject)+len(cfg.SigV4)+len(cfg.MTLS))
	for _, stanza := range cfg.Inject {
		hosts = append(hosts, stanza.Host)
	}
	for _, stanza := range cfg.SigV4 {
		hosts = append(hosts, stanza.Host)
	}
	for _, stanza := range cfg.MTLS {
		hosts = append(hosts, stanza.Host)
	}
	return hosts
}

func policyRulesOverlap(a, b config.AllowRule) bool {
	if a.Port != b.Port {
		return false
	}
	if !a.Wildcard && !b.Wildcard {
		return a.Host == b.Host
	}
	if a.Wildcard && b.Wildcard {
		return a.Host == b.Host
	}
	wild, exact := a, b
	if !wild.Wildcard {
		wild, exact = b, a
	}
	suffix := "." + wild.Host
	left := strings.TrimSuffix(exact.Host, suffix)
	return strings.HasSuffix(exact.Host, suffix) && left != "" && !strings.Contains(left, ".")
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
