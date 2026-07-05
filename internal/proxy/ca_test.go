package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCALoadsAndSignsCachedRSA2048Leaf(t *testing.T) {
	ca, caPEM, caKeyPEM := newTestCA(t)
	leaf, err := ca.LeafFor("api.test")
	if err != nil {
		t.Fatal(err)
	}
	again, err := ca.LeafFor("api.test")
	if err != nil {
		t.Fatal(err)
	}
	if leaf != again {
		t.Fatalf("LeafFor returned different cert pointers for same host")
	}
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to append test CA")
	}
	if _, err := leafCert.Verify(x509.VerifyOptions{DNSName: "api.test", Roots: pool}); err != nil {
		t.Fatalf("leaf did not verify against CA: %v", err)
	}
	if got := ca.key.N.BitLen(); got != 2048 {
		t.Fatalf("CA key bits = %d, want 2048", got)
	}
	leafKey, ok := leaf.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("leaf key type = %T, want RSA", leaf.PrivateKey)
	}
	if got := leafKey.N.BitLen(); got != 2048 {
		t.Fatalf("leaf key bits = %d, want 2048", got)
	}
	if leafCert.DNSNames[0] != "api.test" {
		t.Fatalf("leaf DNSNames = %v, want api.test", leafCert.DNSNames)
	}
	certArtifact := bytes.Join(leaf.Certificate, nil)
	if bytes.Contains(certArtifact, caKeyPEM) || bytes.Contains(caPEM, caKeyPEM) {
		t.Fatal("CA private key material appeared in a cert artifact")
	}
	if leaf.PrivateKey == ca.key {
		t.Fatal("leaf is using the CA private key")
	}
}

func newTestCA(t *testing.T) (*CA, []byte, []byte) {
	t.Helper()
	certPEM, keyPEM := generateTestCAPEM(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return ca, certPEM, keyPEM
}

func generateTestCAPEM(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "cove test CA",
			Organization: []string{"cove-test"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(1, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func certPoolFromPEM(t *testing.T, pemBytes []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("failed to append cert PEM")
	}
	return pool
}

func tlsCertForHost(t *testing.T, ca *CA, host string) tls.Certificate {
	t.Helper()
	leaf, err := ca.LeafFor(host)
	if err != nil {
		t.Fatal(err)
	}
	return *leaf
}
