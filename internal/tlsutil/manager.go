package tlsutil

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Certificate sources.
const (
	SourceEnvironment = "environment" // SMTPRELAY_TLS_CERT / _KEY: managed outside the UI
	SourceUploaded    = "uploaded"
	SourceGenerated   = "generated" // self-signed, created by the relay
)

// Manager serves the TLS certificate and can replace it while the relay runs.
// It also picks the minimum TLS version per connection: a device with its own
// setting gets that, everything else the relay-wide minimum.
type Manager struct {
	dataDir         string
	envCert, envKey string
	names           []string
	globalMin       func() uint16
	clientMin       func(netip.Addr) uint16 // 0 = no override for this address

	mu   sync.RWMutex
	cert tls.Certificate
}

// NewManager loads (or creates) the certificate. names are added to a
// generated certificate as DNS names or IP addresses.
func NewManager(dataDir, envCert, envKey string, names []string, globalMin func() uint16, clientMin func(netip.Addr) uint16) (*Manager, error) {
	m := &Manager{dataDir: dataDir, envCert: envCert, envKey: envKey, names: names, globalMin: globalMin, clientMin: clientMin}
	var err error
	if envCert != "" {
		m.cert, err = tls.LoadX509KeyPair(envCert, envKey)
	} else {
		m.cert, err = loadOrGenerate(m.dir(), names)
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Manager) dir() string { return filepath.Join(m.dataDir, "tls") }

func (m *Manager) current() *tls.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := m.cert
	return &c
}

// Config returns the TLS configuration for the SMTP servers. It looks up the
// certificate and the minimum version for every connection, so changes take
// effect without a restart.
func (m *Manager) Config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			min := m.globalMin()
			if m.clientMin != nil && h.Conn != nil {
				if ap, err := netip.ParseAddrPort(h.Conn.RemoteAddr().String()); err == nil {
					if v := m.clientMin(ap.Addr().Unmap()); v != 0 {
						min = v
					}
				}
			}
			cfg := &tls.Config{
				MinVersion:     min,
				GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return m.current(), nil },
			}
			if min < tls.VersionTLS12 {
				// Very old devices need the older cipher suites as well. Only offered when
				// the minimum version was lowered on purpose.
				for _, s := range tls.CipherSuites() {
					cfg.CipherSuites = append(cfg.CipherSuites, s.ID)
				}
				for _, s := range tls.InsecureCipherSuites() {
					cfg.CipherSuites = append(cfg.CipherSuites, s.ID)
				}
			}
			return cfg, nil
		},
	}
}

// CertInfo describes the certificate in use.
type CertInfo struct {
	Source      string
	Subject     string
	Issuer      string
	Names       []string // DNS names and IP addresses
	NotBefore   time.Time
	NotAfter    time.Time
	Fingerprint string // SHA-256, hex
	Expired     bool
	ExpiresSoon bool // within 30 days
	SelfSigned  bool
}

// Info returns facts about the current certificate.
func (m *Manager) Info() CertInfo {
	cert := m.current()
	info := CertInfo{Source: m.source()}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return info
	}
	sum := sha256.Sum256(leaf.Raw)
	info.Subject, info.Issuer = leaf.Subject.String(), leaf.Issuer.String()
	info.SelfSigned = leaf.Subject.String() == leaf.Issuer.String()
	info.Names = append(info.Names, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		info.Names = append(info.Names, ip.String())
	}
	info.NotBefore, info.NotAfter = leaf.NotBefore, leaf.NotAfter
	info.Fingerprint = strings.ToUpper(hex.EncodeToString(sum[:]))
	info.Expired = time.Now().After(leaf.NotAfter)
	info.ExpiresSoon = !info.Expired && time.Until(leaf.NotAfter) < 30*24*time.Hour
	return info
}

func (m *Manager) source() string {
	if m.envCert != "" {
		return SourceEnvironment
	}
	if b, err := os.ReadFile(filepath.Join(m.dir(), "source")); err == nil && strings.TrimSpace(string(b)) == SourceUploaded {
		return SourceUploaded
	}
	return SourceGenerated
}

// ErrManagedByEnvironment is returned when the certificate comes from the container environment.
var ErrManagedByEnvironment = errors.New("tlsutil: the certificate is set with SMTPRELAY_TLS_CERT and cannot be changed here")

// Upload replaces the certificate by a PEM certificate (with optional chain)
// and its private key. Both are checked before anything changes.
func (m *Manager) Upload(certPEM, keyPEM []byte) error {
	if m.envCert != "" {
		return ErrManagedByEnvironment
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("the certificate and key do not form a valid pair (an encrypted key is not supported): %w", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return err
	}
	if time.Now().After(leaf.NotAfter) {
		return errors.New("the certificate has expired")
	}
	if err := os.MkdirAll(m.dir(), 0o700); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(m.dir(), "key.pem"), keyPEM, 0o600); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(m.dir(), "cert.pem"), certPEM, 0o644); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(m.dir(), "source"), []byte(SourceUploaded), 0o644); err != nil {
		return err
	}
	m.mu.Lock()
	m.cert = cert
	m.mu.Unlock()
	return nil
}

// Regenerate creates a new self-signed certificate for the given names (DNS
// names or IP addresses) and starts using it.
func (m *Manager) Regenerate(names []string) error {
	if m.envCert != "" {
		return ErrManagedByEnvironment
	}
	var clean []string
	for _, n := range names {
		if n = strings.TrimSpace(n); n != "" && (net.ParseIP(n) != nil || validDNSName(n)) {
			clean = append(clean, n)
		} else if n != "" {
			return fmt.Errorf("%q is not a valid name or IP address", n)
		}
	}
	if len(clean) == 0 {
		return errors.New("give at least one name or IP address")
	}
	_ = os.Remove(filepath.Join(m.dir(), "cert.pem"))
	_ = os.Remove(filepath.Join(m.dir(), "key.pem"))
	_ = os.Remove(filepath.Join(m.dir(), "source"))
	cert, err := loadOrGenerate(m.dir(), clean)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.cert = cert
	m.mu.Unlock()
	return nil
}

func validDNSName(s string) bool {
	if len(s) > 253 || strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '*') {
			return false
		}
	}
	return s != ""
}

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ParseVersion converts "1.0".."1.3" to a TLS version constant (0 for anything else).
func ParseVersion(v string) uint16 {
	switch v {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.2":
		return tls.VersionTLS12
	case "1.3":
		return tls.VersionTLS13
	}
	return 0
}
