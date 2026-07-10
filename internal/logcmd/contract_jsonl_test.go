package logcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// contract_audit.jsonl was captured as raw AuditWriter output on the baseline.
// The log command must copy matching source bytes, not re-marshal records.
func TestContractAuditJSONLBytesAreStable(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("testdata", "contract_audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, opts := range []Opts{
		{},
		{DenyOnly: true},
		{Session: "1a2b3c4d"},
		{Host: "api.anthropic.com"},
	} {
		var got bytes.Buffer
		if err := scanTo(bytes.NewReader(fixture), opts, &got); err != nil {
			t.Fatal(err)
		}
		var want bytes.Buffer
		for _, line := range bytes.SplitAfter(fixture, []byte{'\n'}) {
			if len(line) != 0 {
				printIfMatchTo(&want, line, opts)
			}
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("raw JSONL changed for %+v:\n got %q\nwant %q", opts, got.Bytes(), want.Bytes())
		}
	}
}
