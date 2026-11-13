// Package config reads the container parameters from environment variables.
package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime settings.
type Config struct {
	DataDir            string   // SMTPRELAY_DATA_DIR            default /data
	SMTPAddr           string   // SMTPRELAY_SMTP_ADDR           default :2525 (map host 587 -> 2525)
	HTTPAddr           string   // SMTPRELAY_HTTP_ADDR           default :8080
	Hostname           string   // SMTPRELAY_HOSTNAME            default OS hostname
	Lang               string   // SMTPRELAY_LANG                en | nl, default en
	TLSCert            string   // SMTPRELAY_TLS_CERT            optional PEM file
	TLSKey             string   // SMTPRELAY_TLS_KEY             optional PEM file
	TLSNames           []string // SMTPRELAY_TLS_NAMES           extra DNS names / IPs for the generated certificate
	TLSMinVersion      uint16   // SMTPRELAY_TLS_MIN             1.2 (default), 1.1 or 1.0 for old devices
	MaxMessageMB       int      // SMTPRELAY_MAX_MESSAGE_MB      default 35
	EventRetentionDays int      // SMTPRELAY_EVENT_RETENTION_DAYS default 30
	AdminPassword      string   // SMTPRELAY_ADMIN_PASSWORD      optional: sets the UI password on first start (min 12 chars)
	TrustProxy         bool     // SMTPRELAY_TRUST_PROXY         use X-Forwarded-For / -Proto from a reverse proxy
	PublicSMTPPort     string   // SMTPRELAY_PUBLIC_SMTP_PORT    port devices use (shown in the UI), default 587
}

// FromEnv builds a Config from a getenv function (os.Getenv in production).
func FromEnv(getenv func(string) string) (Config, error) {
	c := Config{
		DataDir:            or(getenv("SMTPRELAY_DATA_DIR"), "/data"),
		SMTPAddr:           or(getenv("SMTPRELAY_SMTP_ADDR"), ":2525"),
		HTTPAddr:           or(getenv("SMTPRELAY_HTTP_ADDR"), ":8080"),
		Hostname:           getenv("SMTPRELAY_HOSTNAME"),
		Lang:               strings.ToLower(or(getenv("SMTPRELAY_LANG"), "en")),
		TLSCert:            getenv("SMTPRELAY_TLS_CERT"),
		TLSKey:             getenv("SMTPRELAY_TLS_KEY"),
		TLSMinVersion:      tls.VersionTLS12,
		MaxMessageMB:       35,
		EventRetentionDays: 30,
		AdminPassword:      getenv("SMTPRELAY_ADMIN_PASSWORD"),
		PublicSMTPPort:     or(getenv("SMTPRELAY_PUBLIC_SMTP_PORT"), "587"),
	}
	switch strings.ToLower(getenv("SMTPRELAY_TRUST_PROXY")) {
	case "", "0", "false", "no":
	case "1", "true", "yes":
		c.TrustProxy = true
	default:
		return c, fmt.Errorf("SMTPRELAY_TRUST_PROXY must be true or false")
	}
	if p, err := strconv.Atoi(c.PublicSMTPPort); err != nil || p < 1 || p > 65535 {
		return c, fmt.Errorf("SMTPRELAY_PUBLIC_SMTP_PORT must be a port number, got %q", c.PublicSMTPPort)
	}
	if c.AdminPassword != "" && len(c.AdminPassword) < 12 {
		return c, fmt.Errorf("SMTPRELAY_ADMIN_PASSWORD must be at least 12 characters")
	}
	if c.Hostname == "" {
		if h, err := os.Hostname(); err == nil {
			c.Hostname = h
		} else {
			c.Hostname = "office-smtprelay"
		}
	}
	if c.Lang != "en" && c.Lang != "nl" {
		return c, fmt.Errorf("SMTPRELAY_LANG must be en or nl, got %q", c.Lang)
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return c, fmt.Errorf("SMTPRELAY_TLS_CERT and SMTPRELAY_TLS_KEY must be set together")
	}
	for _, n := range strings.Split(getenv("SMTPRELAY_TLS_NAMES"), ",") {
		if n = strings.TrimSpace(n); n != "" {
			c.TLSNames = append(c.TLSNames, n)
		}
	}
	switch v := getenv("SMTPRELAY_TLS_MIN"); v {
	case "", "1.2":
	case "1.1":
		c.TLSMinVersion = tls.VersionTLS11
	case "1.0":
		c.TLSMinVersion = tls.VersionTLS10
	default:
		return c, fmt.Errorf("SMTPRELAY_TLS_MIN must be 1.2, 1.1 or 1.0, got %q", v)
	}
	var err error
	if c.MaxMessageMB, err = intVar(getenv, "SMTPRELAY_MAX_MESSAGE_MB", c.MaxMessageMB, 1, 150); err != nil {
		return c, err
	}
	if c.EventRetentionDays, err = intVar(getenv, "SMTPRELAY_EVENT_RETENTION_DAYS", c.EventRetentionDays, 1, 3650); err != nil {
		return c, err
	}
	return c, nil
}

func or(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func intVar(getenv func(string) string, name string, def, min, max int) (int, error) {
	v := getenv(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be a number between %d and %d, got %q", name, min, max, v)
	}
	return n, nil
}
