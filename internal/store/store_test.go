package store

import (
	"bytes"
	"database/sql"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/relay"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	key, err := LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(filepath.Join(dir, "relay.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func ip(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestPasswordHashing(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") || strings.Contains(h, "correct") {
		t.Fatalf("unexpected hash %q", h)
	}
	if !VerifyPassword("correct horse battery", h) || VerifyPassword("wrong", h) {
		t.Error("verify failed")
	}
	if VerifyPassword("x", "garbage") || VerifyPassword("x", "") {
		t.Error("garbage hash must not verify")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("salts must differ")
	}
}

func TestGeneratePassword(t *testing.T) {
	a, _ := GeneratePassword(20)
	b, _ := GeneratePassword(20)
	if len(a) != 20 || a == b {
		t.Errorf("bad passwords %q %q", a, b)
	}
	if _, err := GeneratePassword(5); err == nil {
		t.Error("short passwords must be refused")
	}
}

func TestClientLifecycle(t *testing.T) {
	s := newStore(t)
	c, err := s.AddClient("Printer", "192.0.2.50", "printer", "a-long-password-1")
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr.String() != "192.0.2.50/32" {
		t.Errorf("addr = %v", c.Addr)
	}
	if _, err := s.AddClient("printer", "192.0.2.51", "other", "a-long-password-2"); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate name (case-insensitive) err = %v", err)
	}
	if _, err := s.AddClient("x", "not-an-ip", "u", "a-long-password-3"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad address err = %v", err)
	}
	if _, err := s.AddClient("x", "192.0.2.1", "u", "short"); !errors.Is(err, ErrInvalid) {
		t.Errorf("short password err = %v", err)
	}
	if _, err := s.AddClient("x", "192.0.2.1", "bad user", "a-long-password-3"); !errors.Is(err, ErrInvalid) {
		t.Errorf("space in username err = %v", err)
	}
	list, _ := s.ListClients()
	if len(list) != 1 || list[0].Name != "Printer" {
		t.Fatalf("list = %#v", list)
	}
	if err := s.SetClientEnabled("printer", false); err != nil {
		t.Fatal(err)
	}
	if s.IPKnown(ip("192.0.2.50")) {
		t.Error("disabled client must not be known")
	}
	if err := s.DeleteClient("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("delete missing err = %v", err)
	}
	if err := s.DeleteClient("Printer"); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticate(t *testing.T) {
	s := newStore(t)
	if _, err := s.AddClient("Printer", "192.0.2.50", "printer", "a-long-password-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddClient("Net", "198.51.100.0/24", "scanner", "another-long-pw-2"); err != nil {
		t.Fatal(err)
	}

	if name, err := s.Authenticate(ip("192.0.2.50"), "printer", "a-long-password-1"); err != nil || name != "Printer" {
		t.Fatalf("good login: %q %v", name, err)
	}
	if name, err := s.Authenticate(ip("198.51.100.77"), "scanner", "another-long-pw-2"); err != nil || name != "Net" {
		t.Fatalf("CIDR login: %q %v", name, err)
	}
	if _, err := s.Authenticate(ip("192.0.2.50"), "printer", "wrong"); !errors.Is(err, relay.ErrBadPassword) {
		t.Errorf("bad password err = %v", err)
	}
	if _, err := s.Authenticate(ip("192.0.2.50"), "ghost", "x"); !errors.Is(err, relay.ErrUnknownUser) {
		t.Errorf("unknown user err = %v", err)
	}
	// Right credentials from another client's IP.
	if _, err := s.Authenticate(ip("198.51.100.5"), "printer", "a-long-password-1"); !errors.Is(err, relay.ErrWrongIP) {
		t.Errorf("wrong IP err = %v", err)
	}
	// IPv4-mapped IPv6 addresses are treated as IPv4.
	if !s.IPKnown(netip.MustParseAddr("::ffff:192.0.2.50")) {
		t.Error("mapped address must match")
	}
	if s.IPKnown(ip("203.0.113.9")) {
		t.Error("unregistered IP must be unknown")
	}
	// Usernames are case-insensitive; passwords are not.
	if _, err := s.Authenticate(ip("192.0.2.50"), "PRINTER", "a-long-password-1"); err != nil {
		t.Errorf("case-insensitive username: %v", err)
	}
	// Disabled clients look like unknown users.
	_ = s.SetClientEnabled("Printer", false)
	if _, err := s.Authenticate(ip("192.0.2.50"), "printer", "a-long-password-1"); !errors.Is(err, relay.ErrUnknownUser) {
		t.Errorf("disabled client err = %v", err)
	}
	// Password reset.
	_ = s.SetClientEnabled("Printer", true)
	if err := s.SetClientPassword("Printer", "brand-new-password-3"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ip("192.0.2.50"), "printer", "a-long-password-1"); err == nil {
		t.Error("old password must stop working")
	}
	if _, err := s.Authenticate(ip("192.0.2.50"), "printer", "brand-new-password-3"); err != nil {
		t.Errorf("new password: %v", err)
	}
	// last_seen is recorded.
	list, _ := s.ListClients()
	for _, c := range list {
		if c.Name == "Printer" && c.LastSeen.IsZero() {
			t.Error("last_seen not updated")
		}
	}
}

func TestSecretsEncryptedAtRest(t *testing.T) {
	dir := t.TempDir()
	key, _ := LoadOrCreateKey(dir)
	path := filepath.Join(dir, "relay.db")
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	creds := graph.Credentials{TenantID: "tenant-guid", ClientID: "client-guid", ClientSecret: "SUPER-SECRET-VALUE"}
	if err := s.SetGraphCredentials(creds, time.Date(2027, 11, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.GraphCredentials()
	if err != nil || !ok || got != creds {
		t.Fatalf("round trip: %#v %v %v", got, ok, err)
	}
	if exp, ok := s.SecretExpires(); !ok || exp.Format("2006-01-02") != "2027-11-01" {
		t.Errorf("expiry = %v %v", exp, ok)
	}
	// The raw database value must not contain the secret.
	var raw []byte
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, SettingClientSecret).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("SUPER-SECRET")) {
		t.Error("secret stored in clear text")
	}
	_ = s.Close()

	// A different key cannot read it.
	s2, err := Open(path, bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, _, err := s2.GraphCredentials(); err == nil {
		t.Error("decrypting with the wrong key must fail")
	}
}

func TestAdminPassword(t *testing.T) {
	s := newStore(t)
	if s.HasAdminPassword() || s.CheckAdminPassword("anything-at-all-12") {
		t.Fatal("no admin password must mean no access")
	}
	if err := s.SetAdminPassword("short"); !errors.Is(err, ErrInvalid) {
		t.Errorf("short password err = %v", err)
	}
	if err := s.SetAdminPassword("a-good-admin-password"); err != nil {
		t.Fatal(err)
	}
	if !s.HasAdminPassword() || !s.CheckAdminPassword("a-good-admin-password") || s.CheckAdminPassword("wrong-password-123") {
		t.Error("admin password check failed")
	}
}

func TestGraphCredentialsIncomplete(t *testing.T) {
	s := newStore(t)
	if _, ok, _ := s.GraphCredentials(); ok {
		t.Error("empty store must report not configured")
	}
	if err := s.SetGraphCredentials(graph.Credentials{TenantID: "t"}, time.Time{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("incomplete credentials err = %v", err)
	}
}

func TestEventsAggregateAndFilter(t *testing.T) {
	s := newStore(t)
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	bad := relay.Event{RemoteIP: ip("192.0.2.99"), Reason: relay.ReasonIPNotAllowed, SMTPCode: 554}
	for i := 0; i < 5; i++ {
		e := bad
		e.Time = base.Add(time.Duration(i) * time.Minute)
		s.Record(e)
	}
	// Outside the merge window: a new row.
	e := bad
	e.Time = base.Add(30 * time.Minute)
	s.Record(e)
	// Successful sends are never merged.
	for i := 0; i < 2; i++ {
		s.Record(relay.Event{Time: base, RemoteIP: ip("192.0.2.50"), Client: "Printer", Reason: relay.ReasonSent, SMTPCode: 250, Sender: "p@example.com"})
	}

	all, err := s.ListEvents(EventFilter{}, 100, 0)
	if err != nil || len(all) != 4 {
		t.Fatalf("events = %d (%v), want 4", len(all), err)
	}
	fails, _ := s.ListEvents(EventFilter{OnlyFail: true}, 100, 0)
	if len(fails) != 2 {
		t.Fatalf("failures = %d, want 2", len(fails))
	}
	var merged StoredEvent
	for _, f := range fails {
		if f.Count > 1 {
			merged = f
		}
	}
	if merged.Count != 5 || merged.RemoteIP != "192.0.2.99" || !merged.LastAt.After(merged.FirstAt) {
		t.Errorf("merged = %#v", merged)
	}
	byIP, _ := s.ListEvents(EventFilter{RemoteIP: "192.0.2.50"}, 100, 0)
	if len(byIP) != 2 {
		t.Errorf("by IP = %d", len(byIP))
	}
}

func TestDashboardQueries(t *testing.T) {
	s := newStore(t)
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return base }
	s.Record(relay.Event{Time: base.Add(-time.Hour), RemoteIP: ip("192.0.2.50"), Client: "Printer", Reason: relay.ReasonSent, SMTPCode: 250})
	s.Record(relay.Event{Time: base, RemoteIP: ip("192.0.2.50"), Client: "Printer", Reason: relay.ReasonSent, SMTPCode: 250})
	for i := 0; i < 3; i++ {
		s.Record(relay.Event{Time: base.Add(time.Duration(i) * time.Minute), RemoteIP: ip("192.0.2.77"), Reason: relay.ReasonIPNotAllowed, SMTPCode: 554})
	}
	s.Record(relay.Event{Time: base, RemoteIP: ip("192.0.2.88"), Reason: relay.ReasonIPNotAllowed, SMTPCode: 554})

	last, err := s.LastSentByClient()
	if err != nil || !last["Printer"].Equal(base) {
		t.Fatalf("last sent = %v (%v)", last, err)
	}
	if n, _ := s.CountEvents(EventFilter{OnlyFail: true}); n != 2 {
		t.Errorf("failure rows = %d, want 2", n)
	}
	dev, err := s.UnknownDevices(base.Add(-24*time.Hour), 10)
	if err != nil || len(dev) != 2 {
		t.Fatalf("unknown devices = %#v (%v)", dev, err)
	}
	var seen77 bool
	for _, d := range dev {
		if d.IP == "192.0.2.77" {
			seen77 = true
			if d.Count != 3 {
				t.Errorf("count for .77 = %d, want 3", d.Count)
			}
		}
	}
	if !seen77 {
		t.Error("192.0.2.77 missing")
	}
	if dev, _ := s.UnknownDevices(base.Add(time.Hour), 10); len(dev) != 0 {
		t.Error("the since filter must apply")
	}
}

func TestPruneEvents(t *testing.T) {
	s := newStore(t)
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	for i := 0; i < 10; i++ {
		s.Record(relay.Event{Time: now.Add(-time.Duration(i) * 24 * time.Hour), RemoteIP: ip("192.0.2.1"), Reason: relay.ReasonSent, SMTPCode: 250})
	}
	// Keep 3 days: removes events 4..9 days old.
	if n, err := s.PruneEvents(72*time.Hour+time.Minute, 0); err != nil || n != 6 {
		t.Fatalf("pruned %d (%v), want 6", n, err)
	}
	// Row cap.
	if n, err := s.PruneEvents(365*24*time.Hour, 2); err != nil || n != 2 {
		t.Fatalf("row cap pruned %d (%v), want 2", n, err)
	}
	left, _ := s.ListEvents(EventFilter{}, 100, 0)
	if len(left) != 2 {
		t.Errorf("left = %d", len(left))
	}
}

func TestRefuseNewerSchema(t *testing.T) {
	dir := t.TempDir()
	key, _ := LoadOrCreateKey(dir)
	path := filepath.Join(dir, "relay.db")
	db, _ := sql.Open("sqlite", "file:"+path)
	_, _ = db.Exec("PRAGMA user_version = 99")
	_ = db.Close()
	if _, err := Open(path, key); err == nil {
		t.Error("a database from a newer version must be refused")
	}
}
