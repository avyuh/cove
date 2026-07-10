package connection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cove/internal/clierr"
	"cove/internal/config"
	"cove/internal/prompt"
	"cove/internal/proxy"
)

func setupAllowTest(t *testing.T, policy []byte) (string, string, *bytes.Buffer) {
	t.Helper()
	root := t.TempDir()
	configHome := filepath.Join(root, "config")
	stateHome := filepath.Join(root, "state")
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("XDG_STATE_HOME", stateHome)
	path := filepath.Join(configHome, "cove", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, policy, 0600); err != nil {
		t.Fatal(err)
	}

	oldLoad, oldAdd := loadPolicy, addManagedAllow
	oldQueue, oldConfirm := queuePending, confirmAllow
	oldReload, oldNow, oldOutput := reloadPolicy, allowNow, allowOutput
	loadPolicy = config.Load
	addManagedAllow = config.AddManagedAllow
	queuePending = proxy.QueuePendingAllow
	confirmAllow = func(_ string, yes bool) error {
		if yes {
			return nil
		}
		return errors.New("confirmation requires a TTY; rerun with --yes")
	}
	reloadPolicy = func() error { return nil }
	allowNow = func() time.Time { return time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC) }
	out := new(bytes.Buffer)
	allowOutput = out
	t.Cleanup(func() {
		loadPolicy, addManagedAllow = oldLoad, oldAdd
		queuePending, confirmAllow = oldQueue, oldConfirm
		reloadPolicy, allowNow, allowOutput = oldReload, oldNow, oldOutput
	})
	return path, stateHome, out
}

func allowCLIError(t *testing.T, err error) *clierr.Error {
	t.Helper()
	var got *clierr.Error
	if !errors.As(err, &got) {
		t.Fatalf("expected cli error, got %T: %v", err, err)
	}
	if got.Code != clierr.EXUsage {
		t.Fatalf("error code = %d, want EX_USAGE (%d)", got.Code, clierr.EXUsage)
	}
	return got
}

func TestAllowRejectsWildcard(t *testing.T) {
	setupAllowTest(t, []byte("# policy\n"))
	err := Allow([]string{"--yes", "*.example.com"})
	got := allowCLIError(t, err)
	if got.What != "invalid host for allow" || got.Fix != "cove help allow" {
		t.Fatalf("unexpected three-beat error: %+v", got)
	}
}

func TestAllowRefusesProtectedHost(t *testing.T) {
	path, _, _ := setupAllowTest(t, []byte("# policy\n"))
	loadPolicy = func(string) (*config.Config, error) {
		return &config.Config{Inject: []config.InjectStanza{{Host: "api.example.com"}}}, nil
	}
	err := Allow([]string{"--yes", "api.example.com"})
	got := allowCLIError(t, err)
	if !strings.Contains(got.What, "already protected by inject policy") || got.Fix != "cove list; then cove config edit" {
		t.Fatalf("protected-policy refusal did not name the safe fix: %+v", got)
	}
	if body, readErr := os.ReadFile(path); readErr != nil || string(body) != "# policy\n" {
		t.Fatalf("protected-host refusal mutated config: %q, %v", body, readErr)
	}
}

func TestAllowOnceQueuesWithoutConfigMutation(t *testing.T) {
	path, state, _ := setupAllowTest(t, []byte("# policy\n"))
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := Allow([]string{"--yes", "--once", "uploads.example:8443"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("--once changed config.toml:\n%s", after)
	}
	pending, err := os.ReadFile(filepath.Join(state, "cove", "pending-allows.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []proxy.PendingAllow
	if err := json.Unmarshal(pending, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Rule != "uploads.example:8443" {
		t.Fatalf("pending queue = %+v, want uploads.example:8443", entries)
	}
}

func TestAllowPersistentWritesManagedAllow(t *testing.T) {
	path, _, _ := setupAllowTest(t, []byte("# policy\n"))
	if err := Allow([]string{"--yes", "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "# BEGIN COVE MANAGED") || !strings.Contains(string(body), "host = \"api.example.com\"") {
		t.Fatalf("managed allow was not written:\n%s", body)
	}
}

func TestAllowRequiresYesWithoutTTY(t *testing.T) {
	path, _, _ := setupAllowTest(t, []byte("# policy\n"))
	err := Allow([]string{"api.example.com"})
	got := allowCLIError(t, err)
	if got.What != "confirmation requires a TTY" || got.Fix != "rerun with --yes" {
		t.Fatalf("unexpected non-TTY error: %+v", got)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil || string(body) != "# policy\n" {
		t.Fatalf("non-TTY allow mutated config: %q, %v", body, readErr)
	}
}

func TestAllowDuplicatePersistentIsNoOp(t *testing.T) {
	path, _, _ := setupAllowTest(t, []byte("# policy\n"))
	if err := Allow([]string{"--yes", "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	addManagedAllow = func(_ context.Context, _ config.AllowRule) (bool, error) {
		t.Fatal("duplicate allow attempted to edit managed config")
		return false, nil
	}
	if err := Allow([]string{"--yes", "api.example.com"}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("duplicate persistent allow changed config")
	}
}

func setupAddTest(t *testing.T) (*bytes.Buffer, string) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	path := config.DefaultPath()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`[[inject]]
host = "api.openai.com"
header_name = "Authorization"
header_template = "Bearer {secret}"
secret = "file:/tmp/old"
`), 0600); err != nil {
		t.Fatal(err)
	}
	oldOut, oldIn, oldConfirm, oldRead := commandOutput, commandInput, confirmMutation, readSecretStdin
	out := new(bytes.Buffer)
	commandOutput, commandInput = out, strings.NewReader("  synthetic-secret  \n")
	confirmMutation = func(_ string, yes bool) error {
		if !yes {
			return errors.New("confirmation requires a TTY")
		}
		return nil
	}
	readSecretStdin = prompt.ReadSecretStdin
	t.Cleanup(func() {
		commandOutput, commandInput, confirmMutation, readSecretStdin = oldOut, oldIn, oldConfirm, oldRead
	})
	return out, path
}

func TestAddServiceSecretNeverAppearsInOutputAndBlocksSeed(t *testing.T) {
	out, path := setupAddTest(t)
	if err := Add([]string{"openai", "--secret-stdin", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "synthetic-secret") {
		t.Fatalf("secret leaked to output: %q", out.String())
	}
	secret, err := os.ReadFile(filepath.Join(config.ConfigDir(), "secrets", "openai-api-key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(secret) != "synthetic-secret" {
		t.Fatalf("secret write = %q", secret)
	}
	info, err := os.Stat(filepath.Join(config.ConfigDir(), "secrets", "openai-api-key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("secret mode = %o", info.Mode().Perm())
	}
	loaded, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Inject) != 1 || loaded.Inject[0].Name != "openai" {
		t.Fatalf("effective inject = %+v", loaded.Inject)
	}
	if len(loaded.Managed.Block) != 1 || loaded.Managed.Block[0].Kind != "inject" {
		t.Fatalf("seed inject was not blocked: %+v", loaded.Managed.Block)
	}
}

func TestAddRejectsLiteralSecretWithoutEcho(t *testing.T) {
	out, _ := setupAddTest(t)
	err := Add([]string{"openai", "--token", "very-secret"})
	var ce *clierr.Error
	if !errors.As(err, &ce) || ce.Code != clierr.EXUsage {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(ce.What+ce.Fix+out.String(), "very-secret") {
		t.Fatal("literal secret echoed")
	}
}

func TestAddRequiresYesWithoutTTY(t *testing.T) {
	_, path := setupAddTest(t)
	err := Add([]string{"openai", "--secret-stdin"})
	var ce *clierr.Error
	if !errors.As(err, &ce) || ce.Code != clierr.EXUsage {
		t.Fatalf("error = %v", err)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if strings.Contains(string(body), "BEGIN COVE MANAGED") {
		t.Fatal("non-TTY add mutated config")
	}
}

func TestListIsTabSeparatedAndDoesNotResolveSecret(t *testing.T) {
	out, _ := setupAddTest(t)
	if err := List(nil); err != nil {
		t.Fatal(err)
	}
	line := out.String()
	if !strings.Contains(line, "manual:inject:api.openai.com\tprotected\tapi.openai.com\tneeds a key") {
		t.Fatalf("list = %q", line)
	}
	if strings.Contains(line, "/tmp/old") {
		t.Fatal("list printed secret reference")
	}
}

func TestAddTokenValidatesAndNeverLeaksSecret(t *testing.T) {
	out, _ := setupAddTest(t)
	if err := Add([]string{"token", "ci-token", "--host", "token.example", "--header", "Authorization: Bearer {secret}", "--secret-stdin", "--yes"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "synthetic-secret") {
		t.Fatal("token secret leaked to output")
	}
	if _, err := os.Stat(filepath.Join(config.ConfigDir(), "secrets", "token-ci-token")); err != nil {
		t.Fatal(err)
	}
	if err := Add([]string{"token", "BAD", "--host", "token.example", "--secret-stdin", "--yes"}); err == nil {
		t.Fatal("unsafe slug accepted")
	}
	if err := Add([]string{"token", "other", "--host", "api.openai.com", "--secret-stdin", "--yes"}); err == nil {
		t.Fatal("token took over differently named policy")
	}
}

func TestGitHubPATAndOAuthAreSingleSafeTransitions(t *testing.T) {
	out, path := setupAddTest(t)
	if err := os.WriteFile(path, []byte("allow = [\"github.com\", \"api.github.com\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := Add([]string{"github", "--repo", "owner/repo", "--secret-stdin", "--yes"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inject) != 2 || len(cfg.AllowRules) != 0 {
		t.Fatalf("PAT transition unsafe: inject=%+v allow=%+v", cfg.Inject, cfg.AllowRules)
	}
	if !strings.Contains(out.String(), "undo: cove add github --oauth") {
		t.Fatalf("missing undo: %q", out.String())
	}
	if err := Add([]string{"github", "--oauth", "--yes"}); err != nil {
		t.Fatal(err)
	}
	cfg, err = config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Inject) != 0 || len(cfg.AllowRules) != 2 {
		t.Fatalf("OAuth reversal wrong: inject=%+v allow=%+v", cfg.Inject, cfg.AllowRules)
	}
	if _, err := os.Stat(filepath.Join(config.ConfigDir(), "secrets", "github-pat")); err != nil {
		t.Fatalf("PAT was deleted: %v", err)
	}
}

func TestRemoveBlocksSeedAndRetainsSecret(t *testing.T) {
	_, path := setupAddTest(t)
	if err := Add([]string{"openai", "--secret-stdin", "--yes"}); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(config.ConfigDir(), "secrets", "openai-api-key")
	if err := Remove([]string{"openai", "--yes"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range cfg.Inject {
		if st.Host == "api.openai.com" {
			t.Fatal("removed policy fell back to seed")
		}
	}
	if _, err := os.Stat(secret); err != nil {
		t.Fatalf("remove deleted secret: %v", err)
	}
}
