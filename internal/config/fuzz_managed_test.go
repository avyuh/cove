package config

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func FuzzEditManaged(f *testing.F) {
	f.Add([]byte("# user comment\nallow = [\"example.com\"]\n"))
	f.Add([]byte(managedBegin + "\n[managed]\nversion = 1\n" + managedEnd + "\n# tail\n"))
	f.Add([]byte("note = '''\n" + managedBegin + "\n" + managedEnd + "\n'''\n"))
	f.Add([]byte(managedEnd + "\n" + managedBegin + "\n"))
	f.Fuzz(func(t *testing.T, original []byte) {
		if len(original) > 1<<20 {
			t.Skip()
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		beforeRange, beforeRangeErr := findManagedRange(original)
		err := EditManagedPath(context.Background(), path, func(m *rawManaged) error {
			m.Version = 1
			return nil
		})
		after, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err != nil {
			if !bytes.Equal(after, original) {
				t.Fatalf("failed edit changed destination: err=%v", err)
			}
			return
		}
		doc, decodeErr := DecodeDocument(path, after)
		if decodeErr != nil || doc == nil || doc.Config == nil {
			t.Fatalf("committed candidate is not valid: %v", decodeErr)
		}
		if validateErr := doc.Config.Validate(); validateErr != nil {
			t.Fatalf("committed candidate bypassed Validate: %v", validateErr)
		}
		afterRange, afterRangeErr := findManagedRange(after)
		if beforeRangeErr != nil || afterRangeErr != nil || afterRange.start < 0 {
			t.Fatalf("successful edit has invalid marker ranges: before=%v after=%v", beforeRangeErr, afterRangeErr)
		}
		if beforeRange.start >= 0 {
			if !bytes.Equal(original[:beforeRange.start], after[:afterRange.start]) ||
				!bytes.Equal(original[beforeRange.end:], after[afterRange.end:]) {
				t.Fatal("managed edit changed bytes outside existing markers")
			}
			return
		}
		if afterRange.start < len(original) || !bytes.Equal(after[:len(original)], original) {
			t.Fatal("managed edit changed pre-existing bytes while appending markers")
		}
	})
}
