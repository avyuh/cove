// Package session stores the deliberately small, local session index.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const Schema = 1

// Metadata is intentionally not an execution record. In particular it must
// never grow request, environment, argv, or credential fields.
type Metadata struct {
	Schema          int        `json:"schema"`
	ID              string     `json:"id"`
	Agent           string     `json:"agent"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	ProjectBasename string     `json:"project_basename"`
	ExitCode        *int       `json:"exit_code,omitempty"`
	Audit           bool       `json:"audit"`
	Complete        bool       `json:"complete"`
}

type Store struct {
	MetaDir string
	Stderr  io.Writer
}

func NewStore(stateDir string, stderr io.Writer) Store {
	return Store{MetaDir: filepath.Join(stateDir, "sessions", "meta"), Stderr: stderr}
}

func (s Store) Path(id string) string { return filepath.Join(s.MetaDir, id+".json") }

func (s Store) Exists(id string) bool {
	_, err := os.Lstat(s.Path(id))
	return err == nil
}

// Create publishes a complete JSON file without replacing an existing ID.
// A hard link gives us atomic create-if-absent semantics after the temp file
// has been fsynced.
func (s Store) Create(m Metadata) error {
	if err := os.MkdirAll(s.MetaDir, 0700); err != nil {
		return err
	}
	data, err := marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.MetaDir, ".session-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Link(tmpName, s.Path(m.ID)); err != nil {
		if errors.Is(err, os.ErrExist) {
			return os.ErrExist
		}
		return err
	}
	return syncDir(s.MetaDir)
}

// Replace atomically updates an already-created metadata record.
func (s Store) Replace(m Metadata) error {
	if err := os.MkdirAll(s.MetaDir, 0700); err != nil {
		return err
	}
	data, err := marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.MetaDir, ".session-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.Path(m.ID)); err != nil {
		return err
	}
	return syncDir(s.MetaDir)
}

func marshal(m Metadata) ([]byte, error) {
	if m.Schema == 0 {
		m.Schema = Schema
	}
	if m.Schema != Schema || m.ID == "" || m.Agent == "" || m.StartedAt.IsZero() || m.ProjectBasename == "" {
		return nil, fmt.Errorf("invalid session metadata")
	}
	return json.Marshal(m)
}

func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}
