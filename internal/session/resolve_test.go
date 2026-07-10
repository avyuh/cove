package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cove/internal/clierr"
)

func TestResolveFixtureMatrix(t *testing.T) {
	t.Parallel()

	store, state := testStore(t)
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	complete := testMetadata("complete01", base, true, true)
	interrupted := testMetadata("interrupt02", base.Add(time.Minute), false, true)
	noAudit := testMetadata("noaudit003", base.Add(2*time.Minute), true, false)
	for _, metadata := range []Metadata{complete, interrupted, noAudit} {
		if err := store.Create(metadata); err != nil {
			t.Fatalf("Create(%s): %v", metadata.ID, err)
		}
	}
	writeAudit(t, state, "legacy004", base.Add(3*time.Minute))

	for _, tc := range []struct {
		selector string
		id       string
		metadata bool
		complete bool
	}{
		{"complete01", "complete01", true, true},
		{"inter", "interrupt02", true, false},
		{"noaudit003", "noaudit003", true, true},
		{"legacy", "legacy004", false, false},
	} {
		t.Run(tc.selector, func(t *testing.T) {
			got, err := store.Resolve(tc.selector)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.selector, err)
			}
			if got.ID != tc.id || (got.Metadata != nil) != tc.metadata {
				t.Fatalf("Resolve(%q) = %+v, want id=%q metadata=%t", tc.selector, got, tc.id, tc.metadata)
			}
			if got.Metadata != nil && got.Metadata.Complete != tc.complete {
				t.Errorf("Complete = %t, want %t", got.Metadata.Complete, tc.complete)
			}
		})
	}
}

func TestResolveLastUsesNewestMetadataAndAuditFallback(t *testing.T) {
	t.Parallel()

	store, state := testStore(t)
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if err := store.Create(testMetadata("oldermeta", base, true, true)); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(testMetadata("newermeta", base.Add(time.Minute), true, true)); err != nil {
		t.Fatal(err)
	}
	got, err := store.Resolve("last")
	if err != nil || got.ID != "newermeta" {
		t.Fatalf("metadata Resolve(last) = %+v, %v; want newermeta", got, err)
	}

	// With no metadata, old audit-only sessions provide the latest-session fallback.
	emptyMeta := filepath.Join(state, "other", "sessions", "meta")
	auditOnly := Store{MetaDir: emptyMeta}
	writeAudit(t, filepath.Join(state, "other"), "oldaudit", base.Add(2*time.Minute))
	writeAudit(t, filepath.Join(state, "other"), "newaudit", base.Add(3*time.Minute))
	got, err = auditOnly.Resolve("last")
	if err != nil || got.ID != "newaudit" || got.Metadata != nil {
		t.Fatalf("audit fallback Resolve(last) = %+v, %v; want newaudit without metadata", got, err)
	}
}

func TestResolveAmbiguousPrefixAndLegacyEightCharacterID(t *testing.T) {
	t.Parallel()

	store, _ := testStore(t)
	started := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	for i, id := range []string{"deadbeef", "deadfeed"} {
		if err := store.Create(testMetadata(id, started.Add(time.Duration(i)*time.Minute), true, true)); err != nil {
			t.Fatalf("Create(%s): %v", id, err)
		}
	}
	got, err := store.Resolve("deadbeef")
	if err != nil || got.ID != "deadbeef" {
		t.Fatalf("exact legacy ID Resolve = %+v, %v", got, err)
	}
	_, err = store.Resolve("dead")
	var cliError *clierr.Error
	if !errors.As(err, &cliError) || cliError.Code != clierr.EXUsage {
		t.Fatalf("ambiguous prefix error = %#v, want EX_USAGE", err)
	}
	for _, id := range []string{"deadbeef", "deadfeed"} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("ambiguous prefix error %q does not list %q", err, id)
		}
	}
}

func TestResolveUsesMetadataWhenAuditHasRotatedAway(t *testing.T) {
	t.Parallel()

	store, _ := testStore(t)
	metadata := testMetadata("rotated01", time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC), true, true)
	if err := store.Create(metadata); err != nil {
		t.Fatal(err)
	}
	got, err := store.Resolve("last")
	if err != nil || got.ID != metadata.ID || got.Metadata == nil {
		t.Fatalf("Resolve(last) = %+v, %v; want metadata-backed %q", got, err, metadata.ID)
	}
}

func TestResolveSkipsCorruptMetadataWithOneWarning(t *testing.T) {
	t.Parallel()

	store, _ := testStore(t)
	valid := testMetadata("valid001", time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC), true, true)
	if err := store.Create(valid); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.MetaDir, "corrupt.json"), []byte("not JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	store.Stderr = &stderr
	got, err := store.Resolve("last")
	if err != nil || got.ID != valid.ID {
		t.Fatalf("Resolve(last) = %+v, %v; corrupt metadata blocked resolution", got, err)
	}
	if warnings := strings.Count(stderr.String(), "skipping corrupt session metadata"); warnings != 1 {
		t.Errorf("warnings = %d, want 1: %q", warnings, stderr.String())
	}
}

func testStore(t *testing.T) (Store, string) {
	t.Helper()
	state := t.TempDir()
	return Store{MetaDir: filepath.Join(state, "sessions", "meta")}, state
}

func testMetadata(id string, started time.Time, complete, audit bool) Metadata {
	return Metadata{ID: id, Agent: "claude", StartedAt: started, ProjectBasename: "cove", Complete: complete, Audit: audit}
}

func writeAudit(t *testing.T, state, id string, timestamp time.Time) {
	t.Helper()
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(struct {
		Session string    `json:"session"`
		TS      time.Time `json:"ts"`
	}{Session: id, TS: timestamp})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(state, "audit.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(record, '\n')); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
