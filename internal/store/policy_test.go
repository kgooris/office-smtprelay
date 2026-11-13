package store

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/kgooris/office-smtprelay/internal/policy"
)

// A database created by version 1 (no policy column) must open, keep its
// clients and give them the empty policy, so nothing changes for devices.
func TestMigrationFromV1KeepsClientsWorking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := HashPassword("a-long-password-1")
	_, err = old.Exec(`
CREATE TABLE clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, addr TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL, last_seen INTEGER);
CREATE TABLE settings (key TEXT PRIMARY KEY, value BLOB NOT NULL, encrypted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, first_at INTEGER NOT NULL, last_at INTEGER NOT NULL,
  remote_ip TEXT NOT NULL, client TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL, smtp_code INTEGER NOT NULL,
  sender TEXT NOT NULL DEFAULT '', recipients INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT '', count INTEGER NOT NULL DEFAULT 1);
PRAGMA user_version = 1;`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO clients(name, addr, username, password_hash, enabled, created_at) VALUES('Printer','192.0.2.10/32','printer',?,1,1)`, hash); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()

	key, _ := LoadOrCreateKey(dir)
	for i := 0; i < 2; i++ { // opening twice must be harmless
		s, err := Open(path, key)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		list, err := s.ListClients()
		if err != nil || len(list) != 1 {
			t.Fatalf("clients = %v, %v", list, err)
		}
		if list[0].Policy.ActiveRules() != 0 {
			t.Error("a migrated client must have no rules")
		}
		if _, err := s.Authenticate(ip("192.0.2.10"), "printer", "a-long-password-1"); err != nil {
			t.Errorf("login after migration: %v", err)
		}
		var v int
		_ = s.db.QueryRow("PRAGMA user_version").Scan(&v)
		if v != schemaVersion {
			t.Errorf("user_version = %d, want %d", v, schemaVersion)
		}
		_ = s.Close()
	}
}

func TestClientPolicyRoundTrip(t *testing.T) {
	s := newStore(t)
	if _, err := s.AddClient("Printer", "192.0.2.10", "printer", "a-long-password-1"); err != nil {
		t.Fatal(err)
	}
	if s.ClientPolicy("Printer").ActiveRules() != 0 {
		t.Fatal("new clients start with no rules")
	}
	p := policy.FromPreset(policy.PresetStrict, "printer@gbk.be")
	if err := s.SetClientPolicy("Printer", p); err != nil {
		t.Fatal(err)
	}
	got := s.ClientPolicy("Printer")
	if got.JSON() != p.JSON() || got.Limits.PerHour != 30 {
		t.Errorf("policy = %s", got.JSON())
	}
	c, _ := s.ClientByName("printer")
	if c.Policy.Sender.Allowed[0] != "printer@gbk.be" {
		t.Errorf("ClientByName policy = %#v", c.Policy)
	}
	bad := policy.Policy{Rcpt: policy.RcptRule{Mode: policy.Enforce, Scope: policy.ScopeList}}
	if err := s.SetClientPolicy("Printer", bad); err == nil {
		t.Error("an invalid policy must be refused")
	}
	if s.ClientPolicy("Unknown").ActiveRules() != 0 {
		t.Error("unknown client: empty policy")
	}
}

func TestClientWithSeveralAddresses(t *testing.T) {
	s := newStore(t)
	c, err := s.AddClient("Copiers", "192.0.2.10, 192.0.2.64/28", "copiers", "a-long-password-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.More) != 1 || c.AddrString() != "192.0.2.10/32, 192.0.2.64/28" {
		t.Errorf("addresses = %q", c.AddrString())
	}
	for ipStr, want := range map[string]bool{"192.0.2.10": true, "192.0.2.70": true, "192.0.2.11": false, "192.0.2.80": false} {
		if got := s.IPKnown(ip(ipStr)); got != want {
			t.Errorf("IPKnown(%s) = %v, want %v", ipStr, got, want)
		}
	}
	if _, err := s.Authenticate(ip("192.0.2.70"), "copiers", "a-long-password-1"); err != nil {
		t.Errorf("login from the second range: %v", err)
	}
	if err := s.SetClientAddr("Copiers", "192.0.2.99"); err != nil {
		t.Fatal(err)
	}
	if s.IPKnown(ip("192.0.2.70")) || !s.IPKnown(ip("192.0.2.99")) {
		t.Error("SetClientAddr must replace all addresses")
	}
	if _, err := ParseAddrList(""); err == nil {
		t.Error("an empty list is invalid")
	}
}

func TestPausedAndOwnDomains(t *testing.T) {
	s := newStore(t)
	if s.Paused() {
		t.Fatal("not paused by default")
	}
	_ = s.SetPaused(true)
	if !s.Paused() {
		t.Error("paused")
	}
	_ = s.SetPaused(false)
	if s.Paused() {
		t.Error("resumed")
	}
	_ = s.SetOwnDomains(SplitDomains("GBK.be, @contoso.com; bad@x, nodot"))
	got := s.OwnDomains()
	if len(got) != 2 || got[0] != "gbk.be" || got[1] != "contoso.com" {
		t.Errorf("own domains = %v", got)
	}
}

func TestGeneralSettingsOverrideDefaults(t *testing.T) {
	s := newStore(t)
	if s.EffectiveLang("en") != "en" || s.EffectiveRetentionDays(30) != 30 || s.EffectiveMaxMessageBytes(35) != 35<<20 {
		t.Fatal("without overrides the environment defaults apply")
	}
	if err := s.SetGeneral(General{Lang: "nl", RetentionDays: 90, MaxMessageMB: 10, MaxConnsPerIP: 5}); err != nil {
		t.Fatal(err)
	}
	if s.EffectiveLang("en") != "nl" || s.EffectiveRetentionDays(30) != 90 || s.EffectiveMaxMessageBytes(35) != 10<<20 || s.General().MaxConnsPerIP != 5 {
		t.Errorf("overrides not applied: %#v", s.General())
	}
	if err := s.SetGeneral(General{}); err != nil {
		t.Fatal(err)
	}
	if s.EffectiveLang("en") != "en" || s.EffectiveRetentionDays(30) != 30 {
		t.Error("empty values clear the overrides")
	}
	for _, bad := range []General{{Lang: "fr"}, {RetentionDays: 99999}, {MaxMessageMB: 500}, {MaxConnsPerIP: -1}} {
		if err := s.SetGeneral(bad); err == nil {
			t.Errorf("%#v must be refused", bad)
		}
	}
}
