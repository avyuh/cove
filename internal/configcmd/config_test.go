package configcmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cove/internal/clierr"
)

func TestCheckReportsValidatedCounts(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	path := filepath.Join(root, "config", "cove", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("allow = [\"example.com\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	old := output
	out := new(bytes.Buffer)
	output = out
	t.Cleanup(func() { output = old })
	if err := Run([]string{"check"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "config valid — 0 protected, 1 allowed") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestEditInvalidRetainsRecoveryAndOriginal(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	path := filepath.Join(root, "config", "cove", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte("allow = [\"example.com\"]\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	old := runEditor
	runEditor = func(p string) error { return os.WriteFile(p, []byte("[broken\n"), 0600) }
	t.Cleanup(func() { runEditor = old })
	err := Edit()
	var ce *clierr.Error
	if !errors.As(err, &ce) || ce.Code != clierr.EXConfig {
		t.Fatalf("err=%v", err)
	}
	if !strings.Contains(ce.What, "recovery copy retained at ") {
		t.Fatalf("recovery not cited: %+v", ce)
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, original) {
		t.Fatalf("invalid config activated: %q", got)
	}
	recovery := strings.TrimPrefix(ce.What, "edited configuration is invalid; recovery copy retained at ")
	st, e := os.Stat(recovery)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("recovery mode: %v %v", st, e)
	}
}

func TestEditRefusesProtectedHostDowngradeToAllow(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	path := filepath.Join(root, "config", "cove", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	original := []byte(`[[inject]]
host = "api.example.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "env:TOKEN"
`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	old := runEditor
	runEditor = func(p string) error {
		return os.WriteFile(p, []byte(`allow = ["api.example.com"]
`), 0600)
	}
	t.Cleanup(func() { runEditor = old })
	err := Edit()
	var ce *clierr.Error
	if !errors.As(err, &ce) || ce.Code != clierr.EXConfig || !strings.Contains(ce.What, "downgrade a protected host") {
		t.Fatalf("err=%#v, want protected-downgrade EX_CONFIG", err)
	}
	if got, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(got, original) {
		t.Fatalf("downgrade activated: %q, %v", got, readErr)
	}
}
