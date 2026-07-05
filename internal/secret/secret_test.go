package secret

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileSecretMTimeCacheInvalidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := NewCache(nil)
	got, err := c.Resolve("file:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "first" {
		t.Fatalf("got %q, want first", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime().Add(time.Second), info.ModTime().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err = c.Resolve("file:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Fatalf("got %q, want second", got)
	}
}

func TestJSONSecretDottedExtraction(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	if err := os.WriteFile(path, []byte(`{"claudeAiOauth":{"accessToken":"tok_123"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := NewCache(nil).Resolve("json:" + path + "#claudeAiOauth.accessToken")
	if err != nil {
		t.Fatal(err)
	}
	if got != "tok_123" {
		t.Fatalf("got %q, want tok_123", got)
	}
}

func TestJSONSecretMTimeCacheInvalidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".credentials.json")
	if err := os.WriteFile(path, []byte(`{"claudeAiOauth":{"accessToken":"first"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c := NewCache(nil)
	ref := "json:" + path + "#claudeAiOauth.accessToken"
	got, err := c.Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got != "first" {
		t.Fatalf("got %q, want first", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"claudeAiOauth":{"accessToken":"second"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	next := info.ModTime().Add(time.Second)
	if err := os.Chtimes(path, next, next); err != nil {
		t.Fatal(err)
	}
	got, err = c.Resolve(ref)
	if err != nil {
		t.Fatal(err)
	}
	if got != "second" {
		t.Fatalf("got %q, want second", got)
	}
}

func TestEnvSecretCaptureOnce(t *testing.T) {
	t.Setenv("COVE_SECRET_TEST", "first")
	c := NewCache(nil)
	got, err := c.Resolve("env:COVE_SECRET_TEST")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("COVE_SECRET_TEST", "second")
	again, err := c.Resolve("env:COVE_SECRET_TEST")
	if err != nil {
		t.Fatal(err)
	}
	if got != "first" || again != "first" {
		t.Fatalf("env capture = %q then %q, want first then first", got, again)
	}
}

func TestKeyringSecretNotImplemented(t *testing.T) {
	_, err := NewCache(nil).Resolve("keyring:svc/acct")
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("err = %v, want ErrNotImplemented", err)
	}
}

func TestMissingFileWarnsAndIsInert(t *testing.T) {
	var log bytes.Buffer
	got, err := NewCache(&log).Resolve("file:" + filepath.Join(t.TempDir(), "missing"))
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Fatalf("got %q, want empty inert secret", got)
	}
	if !strings.Contains(log.String(), "missing") || !strings.Contains(log.String(), "injection inert") {
		t.Fatalf("missing-file warning not found: %q", log.String())
	}
}

func TestSecretValuesNeverLogged(t *testing.T) {
	var log bytes.Buffer
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("SUPER-SECRET-VALUE"), 0606); err != nil {
		t.Fatal(err)
	}
	got, err := NewCache(&log).Resolve("file:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if got != "SUPER-SECRET-VALUE" {
		t.Fatalf("secret read failed")
	}
	if strings.Contains(log.String(), "SUPER-SECRET-VALUE") {
		t.Fatalf("secret value leaked to logs: %q", log.String())
	}
}
