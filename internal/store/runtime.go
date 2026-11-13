package store

import (
	"strings"

	"github.com/kgooris/office-smtprelay/internal/policy"
	"github.com/kgooris/office-smtprelay/internal/relay"
)

// Setting keys for the relay's runtime behaviour.
const (
	SettingPaused     = "relay.paused"       // "1" while all sending is paused
	SettingOwnDomains = "policy.own_domains" // comma separated internal domains
)

var _ relay.Runtime = (*Store)(nil)

// ClientPolicy returns the optional rules of a client. Unknown clients and
// read errors give the empty policy (all rules off): a database problem must
// not start blocking devices.
func (s *Store) ClientPolicy(name string) policy.Policy {
	var raw string
	if err := s.db.QueryRow(`SELECT policy FROM clients WHERE name = ?`, name).Scan(&raw); err != nil {
		return policy.Policy{}
	}
	return policy.Parse(raw)
}

// Paused reports whether all sending is paused (the "emergency stop").
func (s *Store) Paused() bool {
	v, ok, err := s.Setting(SettingPaused)
	return err == nil && ok && v == "1"
}

// SetPaused turns the emergency stop on or off.
func (s *Store) SetPaused(paused bool) error {
	v := "0"
	if paused {
		v = "1"
	}
	return s.SetSetting(SettingPaused, v, false)
}

// OwnDomains returns the relay's internal domains (lower case, no "@").
func (s *Store) OwnDomains() []string {
	v, ok, err := s.Setting(SettingOwnDomains)
	if err != nil || !ok {
		return nil
	}
	return SplitDomains(v)
}

// SetOwnDomains stores the internal domains.
func (s *Store) SetOwnDomains(domains []string) error {
	return s.SetSetting(SettingOwnDomains, strings.Join(domains, ","), false)
}

// SplitDomains parses a free-form list of domains ("contoso.com, @gbk.be").
func SplitDomains(v string) []string {
	var out []string
	for _, d := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' }) {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d != "" && strings.Contains(d, ".") && !strings.ContainsAny(d, "@<>/\\") {
			out = append(out, d)
		}
	}
	return out
}
