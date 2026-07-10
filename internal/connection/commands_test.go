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
