package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type CA struct {
	cert *x509.Certificate
	key  *rsa.PrivateKey

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func LoadCA(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("invalid CA certificate PEM at %s", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("invalid CA key PEM at %s", keyPath)
	}
	key, err := parseRSAPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	if key.N.BitLen() != 2048 {
		return nil, fmt.Errorf("CA key must be RSA-2048")
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("CA certificate is not a CA")
	}
	return &CA{cert: cert, key: key, leaves: map[string]*tls.Certificate{}}, nil
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key is not RSA")
	}
	return key, nil
}

func (ca *CA) LeafFor(host string) (*tls.Certificate, error) {
	if ca == nil {
		return nil, fmt.Errorf("CA not loaded")
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "" {
		return nil, fmt.Errorf("empty leaf host")
	}
	ca.mu.Lock()
	if leaf, ok := ca.leaves[host]; ok {
		ca.mu.Unlock()
		return leaf, nil
	}
	ca.mu.Unlock()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(0, 1, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, ca.cert.Raw},
		PrivateKey:  key,
		Leaf:        mustParseLeaf(der),
	}

	ca.mu.Lock()
	defer ca.mu.Unlock()
	if cached, ok := ca.leaves[host]; ok {
		return cached, nil
	}
	ca.leaves[host] = leaf
	return leaf, nil
}

func mustParseLeaf(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return cert
}
