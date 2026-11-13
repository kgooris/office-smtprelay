package tlsutil

import (
	"crypto/tls"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func serve(t *testing.T, m *Manager) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", m.Config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { _ = c.(*tls.Conn).Handshake(); _ = c.Close() }()
		}
	}()
	return ln.Addr().String()
}

func handshake(addr string, min, max uint16) (*tls.ConnectionState, error) {
	c, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: min, MaxVersion: max})
	if err != nil {
		return nil, err
	}
	defer c.Close()
	st := c.ConnectionState()
	return &st, nil
}

func newManager(t *testing.T, global uint16, client func(netip.Addr) uint16) *Manager {
	t.Helper()
	m, err := NewManager(t.TempDir(), "", "", []string{"relay.lan", "192.0.2.10"}, func() uint16 { return global }, client)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestManagerGeneratesAndDescribesCertificate(t *testing.T) {
	m := newManager(t, tls.VersionTLS12, nil)
	info := m.Info()
	if info.Source != SourceGenerated || !info.SelfSigned || info.Expired || info.ExpiresSoon {
		t.Errorf("info = %#v", info)
	}
	if strings.Join(info.Names, ",") != "relay.lan,192.0.2.10" || len(info.Fingerprint) != 64 {
		t.Errorf("names/fingerprint = %v %q", info.Names, info.Fingerprint)
	}
	if st, err := handshake(serve(t, m), tls.VersionTLS12, 0); err != nil || st.Version < tls.VersionTLS12 {
		t.Fatalf("handshake: %v", err)
	}
}

func TestMinimumVersionGlobalAndPerClient(t *testing.T) {
	m := newManager(t, tls.VersionTLS12, nil)
	if _, err := handshake(serve(t, m), tls.VersionTLS10, tls.VersionTLS11); err == nil {
		t.Fatal("an old client must be refused when the minimum is 1.2")
	}

	// A device with its own lower minimum (looked up by its address) is accepted.
	m2 := newManager(t, tls.VersionTLS12, func(ip netip.Addr) uint16 {
		if ip == netip.MustParseAddr("127.0.0.1") {
			return tls.VersionTLS10
		}
		return 0
	})
	st, err := handshake(serve(t, m2), tls.VersionTLS10, tls.VersionTLS10)
	if err != nil {
		t.Fatalf("a device with a TLS 1.0 exception must connect: %v", err)
	}
	if st.Version != tls.VersionTLS10 {
		t.Errorf("version = %x", st.Version)
	}

	// Other addresses keep the global minimum.
	m3 := newManager(t, tls.VersionTLS12, func(netip.Addr) uint16 { return 0 })
	if _, err := handshake(serve(t, m3), tls.VersionTLS10, tls.VersionTLS10); err == nil {
		t.Error("no exception, no old TLS")
	}
}

func TestUploadAndRegenerate(t *testing.T) {
	m := newManager(t, tls.VersionTLS12, nil)
	// Make a second certificate to upload.
	other := newManager(t, tls.VersionTLS12, nil)
	certPEM, _ := os.ReadFile(filepath.Join(other.dir(), "cert.pem"))
	keyPEM, _ := os.ReadFile(filepath.Join(other.dir(), "key.pem"))
	oldFP := m.Info().Fingerprint

	if err := m.Upload(certPEM, []byte("not a key")); err == nil {
		t.Fatal("a wrong key must be refused")
	}
	if m.Info().Fingerprint != oldFP {
		t.Fatal("a refused upload must not change anything")
	}
	if err := m.Upload(certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if info := m.Info(); info.Source != SourceUploaded || info.Fingerprint == oldFP || info.Fingerprint != other.Info().Fingerprint {
		t.Errorf("after upload: %#v", info)
	}
	addr := serve(t, m)
	if _, err := handshake(addr, tls.VersionTLS12, 0); err != nil {
		t.Fatalf("new certificate must be served at once: %v", err)
	}

	// It survives a restart (a new manager on the same directory).
	again, err := NewManager(m.dataDir, "", "", []string{"x"}, func() uint16 { return tls.VersionTLS12 }, nil)
	if err != nil || again.Info().Fingerprint != m.Info().Fingerprint || again.Info().Source != SourceUploaded {
		t.Errorf("reload: %v %#v", err, again.Info())
	}

	if err := m.Regenerate([]string{"new.lan", "bad name!"}); err == nil {
		t.Error("an invalid name must be refused")
	}
	if err := m.Regenerate([]string{"new.lan", "192.0.2.77"}); err != nil {
		t.Fatal(err)
	}
	if info := m.Info(); info.Source != SourceGenerated || strings.Join(info.Names, ",") != "new.lan,192.0.2.77" {
		t.Errorf("after regenerate: %#v", info)
	}
}

func TestEnvironmentCertificateIsReadOnly(t *testing.T) {
	src := newManager(t, tls.VersionTLS12, nil)
	m, err := NewManager(t.TempDir(), filepath.Join(src.dir(), "cert.pem"), filepath.Join(src.dir(), "key.pem"), nil, func() uint16 { return tls.VersionTLS12 }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if m.Info().Source != SourceEnvironment {
		t.Error("source")
	}
	if err := m.Regenerate([]string{"a.lan"}); err != ErrManagedByEnvironment {
		t.Errorf("regenerate: %v", err)
	}
	if err := m.Upload(nil, nil); err != ErrManagedByEnvironment {
		t.Errorf("upload: %v", err)
	}
	_ = net.IPv4zero
}

func TestParseVersion(t *testing.T) {
	if ParseVersion("1.0") != tls.VersionTLS10 || ParseVersion("1.3") != tls.VersionTLS13 || ParseVersion("") != 0 || ParseVersion("x") != 0 {
		t.Error("ParseVersion")
	}
}
