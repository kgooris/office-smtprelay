package config

import (
	"crypto/tls"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestDefaults(t *testing.T) {
	c, err := FromEnv(env(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.DataDir != "/data" || c.SMTPAddr != ":2525" || c.HTTPAddr != ":8080" || c.Lang != "en" ||
		c.TLSMinVersion != tls.VersionTLS12 || c.MaxMessageMB != 35 || c.EventRetentionDays != 30 || c.Hostname == "" {
		t.Errorf("defaults = %#v", c)
	}
}

func TestOverrides(t *testing.T) {
	c, err := FromEnv(env(map[string]string{
		"SMTPRELAY_LANG": "NL", "SMTPRELAY_TLS_MIN": "1.0", "SMTPRELAY_MAX_MESSAGE_MB": "20",
		"SMTPRELAY_TLS_NAMES": " relay.lan , 192.0.2.5 ,", "SMTPRELAY_EVENT_RETENTION_DAYS": "7",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.Lang != "nl" || c.TLSMinVersion != tls.VersionTLS10 || c.MaxMessageMB != 20 || c.EventRetentionDays != 7 ||
		len(c.TLSNames) != 2 || c.TLSNames[0] != "relay.lan" || c.TLSNames[1] != "192.0.2.5" {
		t.Errorf("config = %#v", c)
	}
}

func TestInvalid(t *testing.T) {
	for name, m := range map[string]map[string]string{
		"lang":      {"SMTPRELAY_LANG": "fr"},
		"tls min":   {"SMTPRELAY_TLS_MIN": "1.3"},
		"cert only": {"SMTPRELAY_TLS_CERT": "/x.pem"},
		"key only":  {"SMTPRELAY_TLS_KEY": "/x.key"},
		"size":      {"SMTPRELAY_MAX_MESSAGE_MB": "0"},
		"size text": {"SMTPRELAY_MAX_MESSAGE_MB": "big"},
		"retention": {"SMTPRELAY_EVENT_RETENTION_DAYS": "-1"},
	} {
		if _, err := FromEnv(env(m)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
