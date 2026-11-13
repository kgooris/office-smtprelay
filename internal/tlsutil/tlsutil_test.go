package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAndReuse(t *testing.T) {
	dir := t.TempDir()
	cfg, err := Load(dir, "", "", []string{"relay.lan", "192.0.2.5"}, tls.VersionTLS12)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinVersion != tls.VersionTLS12 || len(cfg.Certificates) != 1 {
		t.Fatalf("cfg = %#v", cfg)
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "relay.lan" || len(leaf.IPAddresses) != 1 {
		t.Errorf("SANs = %v %v", leaf.DNSNames, leaf.IPAddresses)
	}
	if leaf.PublicKeyAlgorithm != x509.RSA {
		t.Errorf("key algorithm = %v, want RSA for old printers", leaf.PublicKeyAlgorithm)
	}
	// Second call reuses the same certificate.
	cfg2, err := Load(dir, "", "", nil, tls.VersionTLS12)
	if err != nil {
		t.Fatal(err)
	}
	if string(cfg2.Certificates[0].Certificate[0]) != string(cfg.Certificates[0].Certificate[0]) {
		t.Error("certificate was regenerated instead of reused")
	}
	if fi, err := os.Stat(filepath.Join(dir, "tls", "key.pem")); err != nil || fi.Size() == 0 {
		t.Errorf("key file missing: %v", err)
	}
}

func TestLoadFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(dir, "", "", nil, tls.VersionTLS12); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(dir, filepath.Join(dir, "tls", "cert.pem"), filepath.Join(dir, "tls", "key.pem"), nil, tls.VersionTLS10)
	if err != nil || cfg.MinVersion != tls.VersionTLS10 {
		t.Fatalf("cfg = %#v err = %v", cfg, err)
	}
	if _, err := Load(dir, filepath.Join(dir, "missing.pem"), filepath.Join(dir, "missing.key"), nil, tls.VersionTLS12); err == nil {
		t.Error("missing files must be an error")
	}
}
