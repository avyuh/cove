package setup

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"cove/internal/config"
	"cove/internal/proxy"
)

func TestEnsureUserArtifactsIdempotentAndModes(t *testing.T) {
	home := t.TempDir()
	u := invokingUser{UID: os.Getuid(), GID: os.Getgid(), Name: "test", Home: home}
	notes, err := ensureUserArtifacts(u)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) == 0 {
		t.Fatalf("first run produced no notes")
	}
	notes, err = ensureUserArtifacts(u)
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Fatalf("second run notes = %q, want no changes", notes)
	}
	assertModeAndOwner(t, filepath.Join(home, ".config", "cove", "ca.pem"), 0644, u)
	assertModeAndOwner(t, filepath.Join(home, ".config", "cove", "ca-key.pem"), 0600, u)
	assertModeAndOwner(t, filepath.Join(home, ".config", "cove", "config.toml"), 0600, u)
}

func TestCreateSeedConfigValidatesCandidateBeforeWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cove", "config.toml")
	original := config.DefaultConfig
	config.DefaultConfig = `allow = ["*"]`
	t.Cleanup(func() { config.DefaultConfig = original })
	if err := createSeedConfig(path); err == nil {
		t.Fatal("invalid embedded seed was written")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("invalid seed destination exists: %v", err)
	}
}

func TestGenerateCAProperties(t *testing.T) {
	home := t.TempDir()
	u := invokingUser{UID: os.Getuid(), GID: os.Getgid(), Name: "test", Home: home}
	certPath := filepath.Join(home, "ca.pem")
	keyPath := filepath.Join(home, "ca-key.pem")
	if err := generateCA(certPath, keyPath, u); err != nil {
		t.Fatal(err)
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		t.Fatalf("certificate PEM did not decode")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		t.Fatalf("key PEM did not decode")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if key.N.BitLen() != 2048 {
		t.Fatalf("key bits = %d, want 2048", key.N.BitLen())
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		t.Fatalf("public key = %T, want RSA", cert.PublicKey)
	}
	if !cert.IsCA || !cert.BasicConstraintsValid {
		t.Fatalf("certificate is not a valid CA")
	}
	if !cert.MaxPathLenZero || cert.MaxPathLen != 0 {
		t.Fatalf("pathlen = %d zero=%v, want pathlen 0", cert.MaxPathLen, cert.MaxPathLenZero)
	}
	wantUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage&wantUsage != wantUsage {
		t.Fatalf("key usage = %v, want certSign|crlSign", cert.KeyUsage)
	}
}

func TestEnsureUserArtifactsRecoversInterruptedCAPair(t *testing.T) {
	home := t.TempDir()
	u := invokingUser{UID: os.Getuid(), GID: os.Getgid(), Name: "test", Home: home}
	if _, err := ensureUserArtifacts(u); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(home, ".config", "cove", "ca-key.pem")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureUserArtifacts(u); err != nil {
		t.Fatal(err)
	}
	if _, err := proxy.LoadCA(filepath.Join(home, ".config", "cove", "ca.pem"), key); err != nil {
		t.Fatalf("recovered CA pair invalid: %v", err)
	}
}

func TestCurrentInvokingUserSudoEnvFlip(t *testing.T) {
	t.Setenv("SUDO_UID", "")
	t.Setenv("SUDO_GID", "")
	t.Setenv("SUDO_USER", "")
	u, err := currentInvokingUser()
	if err != nil {
		t.Fatal(err)
	}
	if u.viaSudo {
		t.Fatalf("viaSudo = true without sudo env")
	}
	t.Setenv("SUDO_UID", u.lookupID)
	t.Setenv("SUDO_GID", strconv.Itoa(os.Getgid()))
	t.Setenv("SUDO_USER", "cove-test")
	flipped, err := currentInvokingUser()
	if err != nil {
		t.Fatal(err)
	}
	if !flipped.viaSudo || flipped.Name != "cove-test" || flipped.UID != u.UID {
		t.Fatalf("sudo env did not flip invoking user: %+v", flipped)
	}
}

func assertModeAndOwner(t *testing.T, path string, mode os.FileMode, u invokingUser) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Mode().Perm(); got != mode {
		t.Fatalf("%s mode = %04o, want %04o", path, got, mode)
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("%s stat type = %T", path, st.Sys())
	}
	if int(sys.Uid) != u.UID || int(sys.Gid) != u.GID {
		t.Fatalf("%s owner = %d:%d, want %d:%d", path, sys.Uid, sys.Gid, u.UID, u.GID)
	}
}
