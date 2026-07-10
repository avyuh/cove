package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func FuzzParseInvocation(f *testing.F) {
	f.Add([]byte("cove\x00claude\x00-p\x00"))
	f.Add([]byte("cove\x00--\x00log\x00--literal"))
	f.Add([]byte("cove\x00-C\x00work\x00agent\x00--help"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 1<<16 {
			t.Skip()
		}
		var args []string
		if len(raw) != 0 {
			args = strings.Split(string(raw), "\x00")
		}
		before := append([]string(nil), args...)
		inv, err := parseInvocation(args)
		if !reflect.DeepEqual(args, before) {
			t.Fatalf("parseInvocation mutated argv: before=%q after=%q", before, args)
		}
		if err == nil && inv.Kind == invocationLauncher && len(inv.AgentArgv) != 0 {
			found := false
			for i := range args {
				if reflect.DeepEqual(inv.AgentArgv, args[i:]) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("agent argv was reconstructed: input=%q agent=%q", args, inv.AgentArgv)
			}
		}

		// The permanent collision escape gives a direct byte-for-byte property for
		// every possible string, including empty and non-UTF-8 byte sequences.
		agent := string(raw)
		escaped, err := parseInvocation([]string{"cove", "--", agent})
		if err != nil || len(escaped.AgentArgv) != 1 || !bytes.Equal([]byte(escaped.AgentArgv[0]), raw) {
			t.Fatalf("escaped argv changed bytes: invocation=%#v err=%v", escaped, err)
		}
	})
}
