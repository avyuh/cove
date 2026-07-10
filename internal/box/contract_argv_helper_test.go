package box

import (
	"bytes"
	"os"
	"os/exec"
	"testing"
)

const contractArgvSentinel = "contract-argv-helper"

// TestContractArgvHelper is an in-box-shaped executable helper: it writes its
// received argv as NUL-delimited bytes, so empty and Unicode arguments are not
// ambiguous in the integration assertion below.
func TestContractArgvHelper(t *testing.T) {
	for i, arg := range os.Args {
		if arg != contractArgvSentinel {
			continue
		}
		for _, got := range os.Args[i+1:] {
			_, _ = os.Stdout.WriteString(got)
			_, _ = os.Stdout.Write([]byte{0})
		}
		os.Exit(0)
	}
}

func TestContractArgvHelperNULDelimited(t *testing.T) {
	want := []string{"", "plain", "two words", "--leading-dash", "--", "こんにちは", "🐚"}
	args := append([]string{"-test.run=^TestContractArgvHelper$", "--", contractArgvSentinel}, want...)
	cmd := exec.Command(os.Args[0], args...)
	got, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var encoded []byte
	for _, arg := range want {
		encoded = append(encoded, arg...)
		encoded = append(encoded, 0)
	}
	if !bytes.Equal(got, encoded) {
		t.Fatalf("NUL argv = %q, want %q", got, encoded)
	}
}
