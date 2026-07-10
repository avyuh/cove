package launcher

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"cove/internal/config"
)

// This is the launcher-side half of the drop-in argv contract.  Keep this table
// deliberately unfriendly to serializers which join argv before entering the box.
func TestContractAgentArgvPreservedAtLauncherBoundary(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	if err := os.MkdirAll(filepath.Join(configHome, "cove"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configHome, "cove", "ca.pem"), []byte("contract-ca\n"), 0600); err != nil {
		t.Fatal(err)
	}

	for _, argv := range [][]string{
		{"/bin/true"},
		{"/bin/true", "", "plain", "two words"},
		{"/bin/true", "--leading-dash", "--", "-x", "--flag=value"},
		{"/bin/true", "こんにちは", "🐚", "café"},
	} {
		t.Run(argv[0], func(t *testing.T) {
			got, err := buildDirectives(&config.Config{}, Opts{AgentArgv: argv}, t.TempDir(), "/tmp/contract.sock")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.AgentArgv, argv) {
				t.Fatalf("AgentArgv = %#v, want %#v", got.AgentArgv, argv)
			}
		})
	}
}
