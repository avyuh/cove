package proxy

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzDecodeRegister(f *testing.F) {
	f.Add([]byte(`{"session":"a1b2c3d4","agent":"claude","audit":false,"project":"work"}`))
	f.Add([]byte(`{"session":"deadbeef","agent":"agent","audit":true,"unknown":1}`))
	f.Add([]byte(`{"session":"BAD","agent":"agent","audit":false}`))
	f.Add([]byte(`{"session":"deadbeef","agent":"agent","audit":false} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		r, err := decodeRegister(string(data))
		if err != nil {
			return
		}
		if len(data) > controlLineLimit || !utf8.Valid(data) || r.Audit == nil ||
			!sessionIDRE.MatchString(r.Session) || r.Agent == "" || len([]byte(r.Agent)) > 128 {
			t.Fatalf("decoder accepted an out-of-contract REGISTER/2: %#v", r)
		}
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(data, &keys); err != nil {
			t.Fatalf("accepted line does not decode as one JSON object: %v", err)
		}
		known := map[string]bool{"session": true, "agent": true, "audit": true, "project": true, "diagnostic": true}
		for key := range keys {
			if !known[key] {
				t.Fatalf("unknown key %q was accepted", key)
			}
		}
	})
}

func TestDecodeRegisterEnforcesLineAndUTF8Bounds(t *testing.T) {
	overlong := `{"session":"deadbeef","agent":"agent","audit":false,"project":"` + strings.Repeat("x", controlLineLimit) + `"}`
	if _, err := decodeRegister(overlong); err == nil {
		t.Fatal("overlong REGISTER/2 accepted")
	}
	invalidUTF8 := append([]byte(`{"session":"deadbeef","agent":"`), 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`","audit":false}`)...)
	if _, err := decodeRegister(string(invalidUTF8)); err == nil {
		t.Fatal("invalid UTF-8 REGISTER/2 accepted")
	}
	caseVariant := `{"sessiOn":"deadbeef","agent":"agent","audit":false}`
	if _, err := decodeRegister(caseVariant); err == nil {
		t.Fatal("case-variant unknown REGISTER/2 key accepted")
	}
}
