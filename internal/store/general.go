package store

import (
	"fmt"
	"strconv"
)

// Setting keys for the general settings. A missing value means "use the
// default from the container environment".
const (
	SettingLang          = "general.lang"
	SettingRetentionDays = "general.retention_days"
	SettingMaxMessageMB  = "general.max_message_mb"
	SettingMaxConnsPerIP = "general.max_conns_per_ip"
)

// General holds the administrator's overrides of the environment defaults.
// Zero values mean "not set": the environment default applies.
type General struct {
	Lang          string // "en", "nl" or empty
	RetentionDays int    // 1..3650
	MaxMessageMB  int    // 1..150
	MaxConnsPerIP int    // 1..1000; 0 = not set (unlimited by default)
}

// Limits of the general settings.
const (
	MaxRetentionDays = 3650
	MaxMessageMBCap  = 150
	MaxConnsCap      = 1000
)

func (s *Store) intSetting(key string) int {
	v, ok, err := s.Setting(key)
	if err != nil || !ok {
		return 0
	}
	n, _ := strconv.Atoi(v)
	return n
}

// General returns the stored overrides.
func (s *Store) General() General {
	g := General{
		RetentionDays: s.intSetting(SettingRetentionDays),
		MaxMessageMB:  s.intSetting(SettingMaxMessageMB),
		MaxConnsPerIP: s.intSetting(SettingMaxConnsPerIP),
	}
	g.Lang, _, _ = s.Setting(SettingLang)
	return g
}

// SetGeneral validates and stores the overrides. Zero values clear an override.
func (s *Store) SetGeneral(g General) error {
	if g.Lang != "" && g.Lang != "en" && g.Lang != "nl" {
		return fmt.Errorf("%w: language", ErrInvalid)
	}
	if g.RetentionDays < 0 || g.RetentionDays > MaxRetentionDays || g.MaxMessageMB < 0 || g.MaxMessageMB > MaxMessageMBCap ||
		g.MaxConnsPerIP < 0 || g.MaxConnsPerIP > MaxConnsCap {
		return fmt.Errorf("%w: value out of range", ErrInvalid)
	}
	for k, v := range map[string]string{
		SettingLang:          g.Lang,
		SettingRetentionDays: numOrEmpty(g.RetentionDays),
		SettingMaxMessageMB:  numOrEmpty(g.MaxMessageMB),
		SettingMaxConnsPerIP: numOrEmpty(g.MaxConnsPerIP),
	} {
		if err := s.SetSetting(k, v, false); err != nil {
			return err
		}
	}
	return nil
}

func numOrEmpty(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// EffectiveLang returns the default UI language: the override, else def.
func (s *Store) EffectiveLang(def string) string {
	if l := s.General().Lang; l != "" {
		return l
	}
	return def
}

// EffectiveRetentionDays returns the log retention in days.
func (s *Store) EffectiveRetentionDays(def int) int {
	if n := s.General().RetentionDays; n > 0 {
		return n
	}
	return def
}

// EffectiveMaxMessageBytes returns the maximum message size in bytes.
func (s *Store) EffectiveMaxMessageBytes(defMB int) int64 {
	mb := defMB
	if n := s.General().MaxMessageMB; n > 0 {
		mb = n
	}
	return int64(mb) << 20
}
