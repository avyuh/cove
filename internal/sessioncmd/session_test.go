package sessioncmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cove/internal/session"
)

func TestSessionsExpandsOnlyAmbiguousPrefixesAndWarnsForCorruptMetadata(t *testing.T) {
	state := t.TempDir()
	store := session.NewStore(state, nil)
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	for i, id := range []string{"deadbeef1111", "deadbeef2222", "cafebabe3333"} {
		m := session.Metadata{ID: id, Agent: "claude", StartedAt: base.Add(time.Duration(i) * time.Minute), ProjectBasename: "cove", Audit: true, Complete: true}
		if err := store.Create(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(store.MetaDir, "broken.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	if err := run(nil, state, &out, &stderr, base.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{"deadbeef1", "deadbeef2", "cafebabe"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing unique display prefix %q:\n%s", want, got)
		}
	}
	if strings.Count(stderr.String(), "skipping corrupt session metadata") != 1 {
		t.Errorf("stderr = %q", stderr.String())
	}
}
