package store

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Setting keys for the security of the web UI.
const (
	SettingUIAllow        = "security.ui_allow"        // networks that may open the UI (empty = everyone)
	SettingSessionMinutes = "security.session_minutes" // idle time after which a sign-in ends
)

// Limits of the session time.
const (
	MinSessionMinutes = 5
	MaxSessionMinutes = 480
)

// UIAllow returns the networks that may open the web UI. An empty list means
// no restriction.
func (s *Store) UIAllow() []netip.Prefix {
	v, ok, err := s.Setting(SettingUIAllow)
	if err != nil || !ok || v == "" {
		return nil
	}
	out, _ := ParseAddrList(v)
	return out
}

// SetUIAllow stores the networks that may open the web UI (empty clears the restriction).
func (s *Store) SetUIAllow(text string) ([]netip.Prefix, error) {
	if strings.TrimSpace(text) == "" {
		return nil, s.SetSetting(SettingUIAllow, "", false)
	}
	list, err := ParseAddrList(text)
	if err != nil {
		return nil, err
	}
	return list, s.SetSetting(SettingUIAllow, joinPrefixes(list), false)
}

// SessionMinutes returns the configured idle time in minutes (0 = default).
func (s *Store) SessionMinutes() int { return s.intSetting(SettingSessionMinutes) }

// SetSessionMinutes stores the idle time; 0 restores the default.
func (s *Store) SetSessionMinutes(m int) error {
	if m != 0 && (m < MinSessionMinutes || m > MaxSessionMinutes) {
		return fmt.Errorf("%w: session time", ErrInvalid)
	}
	return s.SetSetting(SettingSessionMinutes, numOrEmpty(m), false)
}

// IdleTimeout returns the session idle time to use.
func (s *Store) IdleTimeout(def time.Duration) time.Duration {
	if m := s.SessionMinutes(); m > 0 {
		return time.Duration(m) * time.Minute
	}
	return def
}
