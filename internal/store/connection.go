package store

import (
	"fmt"
	"net/netip"
	"strconv"

	"github.com/kgooris/office-smtprelay/internal/policy"
)

// Setting keys for how devices connect.
const (
	SettingTLSMin       = "tls.min"            // "1.0" .. "1.3"; empty = the container default
	SettingImplicitPort = "smtp.implicit_port" // port inside the container for SMTP over TLS (0 = off)
	SettingLegacyPort   = "smtp.legacy_port"   // port inside the container without encryption (0 = off)
)

// PolicyForIP returns the rules of the enabled client that covers ip. Unknown
// addresses and read errors give the empty policy.
func (s *Store) PolicyForIP(ip netip.Addr) policy.Policy {
	ip = ip.Unmap()
	clients, err := s.ListClients()
	if err != nil {
		return policy.Policy{}
	}
	for _, c := range clients {
		if c.Enabled && c.Contains(ip) {
			return c.Policy
		}
	}
	return policy.Policy{}
}

// TLSMin returns the relay-wide minimum TLS version override ("" if none).
func (s *Store) TLSMin() string {
	v, _, _ := s.Setting(SettingTLSMin)
	if !policy.ValidTLSVersion(v) {
		return ""
	}
	return v
}

// SetTLSMin stores the relay-wide minimum TLS version ("" clears the override).
func (s *Store) SetTLSMin(v string) error {
	if !policy.ValidTLSVersion(v) {
		return fmt.Errorf("%w: TLS version", ErrInvalid)
	}
	return s.SetSetting(SettingTLSMin, v, false)
}

// Ports holds the optional extra SMTP listeners (0 = off).
type Ports struct {
	Implicit int // SMTP over TLS from the first byte (port 465 style)
	Legacy   int // no encryption, only for devices that may (TLS.AllowPlain)
}

// ExtraPorts returns the stored listener ports.
func (s *Store) ExtraPorts() Ports {
	return Ports{Implicit: s.intSetting(SettingImplicitPort), Legacy: s.intSetting(SettingLegacyPort)}
}

// SetExtraPorts validates and stores the listener ports. mainPort is the
// port of the normal listener, which the others must not use.
func (s *Store) SetExtraPorts(p Ports, mainPort int) error {
	for _, n := range []int{p.Implicit, p.Legacy} {
		if n < 0 || n > 65535 {
			return fmt.Errorf("%w: port", ErrInvalid)
		}
	}
	if p.Implicit > 0 && (p.Implicit == p.Legacy || p.Implicit == mainPort) || p.Legacy > 0 && p.Legacy == mainPort {
		return fmt.Errorf("%w: ports must differ", ErrInvalid)
	}
	if err := s.SetSetting(SettingImplicitPort, portText(p.Implicit), false); err != nil {
		return err
	}
	return s.SetSetting(SettingLegacyPort, portText(p.Legacy), false)
}

func portText(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}
