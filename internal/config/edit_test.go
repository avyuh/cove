package config

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cove/internal/clierr"
)

func addManagedAllow(m *rawManaged) error {
	m.Version = 1
	m.Allow = append(m.Allow, NamedAllow{Name: "managed-example", Host: "managed.example.com"})
	return nil
}

func TestManagedCorpusPreservesUserBytes(t *testing.T) {
	for _, name := range []string{"crlf.toml", "no-final-newline.toml", "multiline-marker.toml", "quoted-table.toml", "legacy-options-allow.toml"} {
		t.Run(name, func(t *testing.T) {
			in, err := os.ReadFile(filepath.Join("testdata", "managed", name))
			if err != nil {
				t.Fatal(err)
			}
			// The corpus exercises physical CRLF and an EOF without newline;
			// repository patch tools normalize fixture line endings on checkout.
			if name == "crlf.toml" {
				in = bytes.ReplaceAll(in, []byte("\n"), []byte("\r\n"))
			}
			if name == "no-final-newline.toml" {
				in = bytes.TrimSuffix(in, []byte("\n"))
			}
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, in, 0600); err != nil {
				t.Fatal(err)
			}
			if err := EditManagedPath(context.Background(), path, addManagedAllow); err != nil {
				t.Fatal(err)
			}
			out, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			a, _ := findManagedRange(in)
			b, _ := findManagedRange(out)
			if a.start < 0 {
				if !bytes.HasPrefix(out, in) {
					t.Fatal("user bytes changed")
				}
			} else if !bytes.Equal(in[:a.start], out[:b.start]) || !bytes.Equal(in[a.end:], out[b.end:]) {
				t.Fatal("bytes outside markers changed")
			}
		})
	}
}

func TestManagedMarkersIgnoreTripleQuotesInComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	original := []byte("value = '' # comment with '''")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := EditManagedPath(context.Background(), path, addManagedAllow); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	rng, err := findManagedRange(first)
	if err != nil || rng.start < 0 || !bytes.Equal(first[:len(original)], original) {
		t.Fatalf("appended block was hidden by comment quotes: range=%+v err=%v\n%s", rng, err, first)
	}
	if err := EditManagedPath(context.Background(), path, func(m *rawManaged) error {
		m.Allow = append(m.Allow, NamedAllow{Name: "second", Host: "second.example.com"})
		return nil
	}); err != nil {
		t.Fatalf("second edit could not find managed block: %v", err)
	}
}

func TestManagedFailuresAndExternalWriter(t *testing.T) {
	bad := []string{managedBegin + "\n[managed]\nversion=1\n", managedEnd + "\n", "[managed]\nversion=1\n", managedBegin + "\n[managed]\nversion=99\n" + managedEnd + "\n", managedBegin + "\n[managed]\nversion=1\nunknown=true\n" + managedEnd + "\n"}
	for _, body := range bad {
		path := filepath.Join(t.TempDir(), "config.toml")
		os.WriteFile(path, []byte(body), 0600)
		err := EditManagedPath(context.Background(), path, addManagedAllow)
		var ce *clierr.Error
		if !errors.As(err, &ce) || ce.Code != clierr.EXConfig {
			t.Fatalf("expected config error, got %v", err)
		}
		got, _ := os.ReadFile(path)
		if string(got) != body {
			t.Fatal("bad input changed")
		}
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	initial := []byte("allow = [\"old.example.com\"]\n")
	os.WriteFile(path, initial, 0600)
	err := EditManagedPath(context.Background(), path, func(*rawManaged) error { return os.WriteFile(path, []byte("allow = [\"user.example.com\"]\n"), 0600) })
	var ce *clierr.Error
	if !errors.As(err, &ce) || ce.Code != clierr.EXTempFail {
		t.Fatalf("expected tempfail, got %v", err)
	}
	got, _ := os.ReadFile(path)
	if !strings.Contains(string(got), "user.example.com") {
		t.Fatal("user edit lost")
	}
}

func TestInvalidCandidateNeverCommits(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	initial := []byte("allow = [\"old.example.com\"]\n")
	os.WriteFile(path, initial, 0600)
	err := EditManagedPath(context.Background(), path, func(m *rawManaged) error { m.Version = 1; m.Allow = []NamedAllow{{Name: "bad", Host: "*"}}; return nil })
	if err == nil {
		t.Fatal("invalid candidate committed")
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, initial) {
		t.Fatal("destination changed")
	}
}

func TestExportedManagedMutationIsAtomicAndValidated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	initial := []byte("allow = [\"old.example.com\"]\n")
	if err := os.WriteFile(path, initial, 0600); err != nil {
		t.Fatal(err)
	}
	err := EditManagedConfigPath(context.Background(), path, func(m *ManagedConfig) error {
		m.Version = 1
		m.Inject = append(m.Inject, InjectStanza{Name: "bad", Host: "api.example.com", Secret: "file:/tmp/key"})
		return nil
	})
	if err == nil {
		t.Fatal("invalid exported mutation committed")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, initial) {
		t.Fatalf("invalid mutation changed destination: %s", got)
	}

	if err := EditManagedConfigPath(context.Background(), path, func(m *ManagedConfig) error {
		m.Version = 1
		m.Inject = append(m.Inject, InjectStanza{Name: "openai", Host: "api.example.com", HeaderName: "Authorization", HeaderTemplate: "Bearer {secret}", Secret: "file:/tmp/key"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := RemoveManagedByNamePath(context.Background(), path, "openai"); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Managed.Inject) != 0 {
		t.Fatalf("managed inject remained: %+v", loaded.Managed.Inject)
	}
}

func TestCompileRawManagedBlockReplacesBasePolicy(t *testing.T) {
	cfg, err := LoadBytes([]byte(`
allow = ["api.example.com"]
# BEGIN COVE MANAGED — written by cove commands
[managed]
version = 1
[[managed.block]]
kind = "allow"
host = "api.example.com"
[[managed.inject]]
name = "api"
host = "api.example.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "env:TOKEN"
# END COVE MANAGED
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Allow) != 0 || len(cfg.Inject) != 1 || cfg.Inject[0].Host != "api.example.com" {
		t.Fatalf("managed compilation lost one-policy shape: %+v", cfg)
	}
	if _, err := LoadBytes([]byte(`[managed]
version=1
[[managed.block]]
kind="allow"
host="missing.example.com"`)); err == nil {
		t.Fatal("block must not grant or remove a missing base policy")
	}
}
