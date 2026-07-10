package session

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestStoreCreateWritesPrivacyMinimalMetadata(t *testing.T) {
	t.Parallel()

	store := Store{MetaDir: t.TempDir()}
	started := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	ended := started.Add(time.Minute)
	exitCode := 7
	metadata := Metadata{
		ID:              "deadbeef",
		Agent:           "claude",
		StartedAt:       started,
		EndedAt:         &ended,
		ProjectBasename: "cove",
		ExitCode:        &exitCode,
		Audit:           true,
		Complete:        true,
	}
	if err := store.Create(metadata); err != nil {
		t.Fatalf("Create: %v", err)
	}

	data, err := os.ReadFile(store.Path(metadata.ID))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("metadata JSON: %v", err)
	}
	wantFields := map[string]bool{
		"schema": true, "id": true, "agent": true, "started_at": true,
		"ended_at": true, "project_basename": true, "exit_code": true,
		"audit": true, "complete": true,
	}
	for field := range fields {
		if !wantFields[field] {
			t.Errorf("metadata contains request fact %q", field)
		}
	}
	for _, forbidden := range []string{"argv", "env", "environment", "secret", "path", "denied", "host"} {
		if _, ok := fields[forbidden]; ok {
			t.Errorf("metadata contains forbidden field %q", forbidden)
		}
	}
	if info, err := os.Stat(store.Path(metadata.ID)); err != nil {
		t.Fatalf("Stat: %v", err)
	} else if info.Mode().Perm() != 0600 {
		t.Errorf("metadata permissions = %o, want 0600", info.Mode().Perm())
	}
}

func TestStoreCreateReportsIDCollision(t *testing.T) {
	t.Parallel()

	store := Store{MetaDir: t.TempDir()}
	metadata := Metadata{
		ID:              "deadbeef",
		Agent:           "claude",
		StartedAt:       time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC),
		ProjectBasename: "cove",
		Audit:           true,
	}
	if err := store.Create(metadata); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := store.Create(metadata); !errors.Is(err, os.ErrExist) {
		t.Fatalf("second Create error = %v, want os.ErrExist", err)
	}
	// Store has no ID generator: launcher owns retrying after this collision signal.
}
