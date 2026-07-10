package config

import "testing"

func FuzzDecodeDocument(f *testing.F) {
	f.Add([]byte("allow = [\"example.com\"]\n"))
	f.Add([]byte("[[inject]]\nhost=\"api.example.com\"\nheader_name=\"Authorization\"\nheader_template=\"Bearer {secret}\"\nsecret=\"env:TOKEN\"\n"))
	f.Add([]byte("[managed]\nversion=1\nunknown=true\n"))
	f.Add([]byte("[[mtls]]\nhost=\"m.example\"\nallowed_methods=[\"GET\"]\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			t.Skip()
		}
		doc, err := DecodeDocument("fuzz.toml", data)
		if err != nil {
			return
		}
		if doc == nil || doc.Config == nil {
			t.Fatal("successful decode returned no config")
		}
		if err := doc.Config.Validate(); err != nil {
			t.Fatalf("DecodeDocument returned an unvalidated config: %v", err)
		}
	})
}
