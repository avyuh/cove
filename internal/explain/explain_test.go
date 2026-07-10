package explain

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"cove/internal/config"
	"cove/internal/proxy"
)

func writeDeny(t *testing.T, state, suffix string, r proxy.AuditRecord) {
	t.Helper()
	if err := os.MkdirAll(state, 0700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(state, "audit.log")+suffix, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(r); err != nil {
		t.Fatal(err)
	}
}

func TestExplainLastUsesNewestRotatedDenial(t *testing.T) {
	state := t.TempDir()
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	writeDeny(t, state, ".1", proxy.AuditRecord{TS: base, Policy: "deny", Session: "old", Host: "old.example", Reason: "host_policy"})
	writeDeny(t, state, "", proxy.AuditRecord{TS: base.Add(time.Minute), Policy: "deny", Session: "new", Host: "new.example", Method: "GET", Path: "/v1", Reason: "host_policy"})
	var out bytes.Buffer
	if err := run([]string{"last"}, state, &config.Config{}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "new.example/v1 (session new)") {
		t.Fatalf("got %q", out.String())
	}
}

func TestExplainReasonFixGoldens(t *testing.T) {
	base := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name string
		rec  proxy.AuditRecord
		cfg  *config.Config
		want string
	}{
		{"host", proxy.AuditRecord{TS: base, Policy: "deny", Session: "s", Host: "blocked.example", Reason: "host_policy"}, &config.Config{}, "because: this host is not allowed\nfix: cove allow blocked.example\n"},
		{"protected host", proxy.AuditRecord{TS: base, Policy: "deny", Session: "s", Host: "api.openai.com", Reason: "host_policy"}, &config.Config{Inject: []config.InjectStanza{{Host: "api.openai.com"}}}, "fix: cove config edit\n"},
		{"method github", proxy.AuditRecord{TS: base, Policy: "deny", Session: "s", Host: "api.github.com", Reason: "policy_method", Resource: "acme/app"}, &config.Config{}, "fix: cove add github --repo acme/app\n"},
		{"resource service", proxy.AuditRecord{TS: base, Policy: "deny", Session: "s", Host: "api.openai.com", Reason: "policy_resource", Service: "openai"}, &config.Config{}, "fix: cove add openai\n"},
		{"operation unknown", proxy.AuditRecord{TS: base, Policy: "deny", Session: "s", Host: "x.example", Reason: "policy_operation"}, &config.Config{}, "fix: cove config edit\n"},
		{"secret", proxy.AuditRecord{TS: base, Policy: "deny", Session: "s", Host: "x.example", Reason: "missing_secret", Service: "gemini"}, &config.Config{}, "fix: cove add gemini\n"},
		{"transport", proxy.AuditRecord{TS: base, Policy: "deny", Session: "s", Host: "x.example", Reason: "upstream_transport"}, &config.Config{}, "fix: cove status --verbose\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := t.TempDir()
			writeDeny(t, state, "", tc.rec)
			var out bytes.Buffer
			if err := run([]string{"last"}, state, tc.cfg, &out); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tc.want) {
				t.Fatalf("got:\n%s\nwant fragment:\n%s", out.String(), tc.want)
			}
			if tc.name == "protected host" && strings.Contains(out.String(), "cove allow") {
				t.Fatalf("protected host received allow recommendation: %s", out.String())
			}
		})
	}
}

func TestExplainNoStoredRecordIsSuccessful(t *testing.T) {
	state := t.TempDir()
	if err := os.MkdirAll(filepath.Join(state, "sessions", "meta"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "sessions", "meta", "noaudit.json"), []byte(`{"schema":1,"id":"noaudit","agent":"claude","started_at":"2026-07-10T12:00:00Z","project_basename":"cove","audit":false,"complete":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"last"}, state, &config.Config{}, &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "nothing stored to explain\ntry: cove log --last\n" {
		t.Fatalf("got %q", out.String())
	}
}
