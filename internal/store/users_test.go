package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/kgooris/office-smtprelay/internal/totp"
)

// A version 2 database has one shared password in the settings. After the
// upgrade it is the password of the user "admin", so nobody is locked out.
func TestMigrationKeepsTheOldAdminPassword(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "relay.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := HashPassword("the-old-admin-password")
	_, err = old.Exec(`
CREATE TABLE clients (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, addr TEXT NOT NULL,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL, last_seen INTEGER, policy TEXT NOT NULL DEFAULT '{}');
CREATE TABLE settings (key TEXT PRIMARY KEY, value BLOB NOT NULL, encrypted INTEGER NOT NULL DEFAULT 0);
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, first_at INTEGER NOT NULL, last_at INTEGER NOT NULL,
  remote_ip TEXT NOT NULL, client TEXT NOT NULL DEFAULT '', reason TEXT NOT NULL, smtp_code INTEGER NOT NULL,
  sender TEXT NOT NULL DEFAULT '', recipients INTEGER NOT NULL DEFAULT 0, bytes INTEGER NOT NULL DEFAULT 0,
  detail TEXT NOT NULL DEFAULT '', count INTEGER NOT NULL DEFAULT 1);
PRAGMA user_version = 2;`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(`INSERT INTO settings(key, value, encrypted) VALUES('admin.password_hash', ?, 0)`, hash); err != nil {
		t.Fatal(err)
	}
	_ = old.Close()

	key, _ := LoadOrCreateKey(dir)
	for i := 0; i < 2; i++ { // twice: the migration must not duplicate
		s, err := Open(path, key)
		if err != nil {
			t.Fatal(err)
		}
		if !s.HasAdminPassword() {
			t.Fatal("the admin must exist after the upgrade")
		}
		u, err := s.AuthUser("admin", "the-old-admin-password")
		if err != nil || !u.Admin() || u.TOTPEnabled {
			t.Fatalf("login after upgrade: %+v %v", u, err)
		}
		if list, _ := s.Users(); len(list) != 1 {
			t.Errorf("users = %v", list)
		}
		_ = s.Close()
	}
}

func TestUsersAndRoles(t *testing.T) {
	s := newStore(t)
	if s.HasAdminPassword() {
		t.Fatal("no admin yet")
	}
	if err := s.SetAdminPassword("a-good-admin-password"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetAdminPassword("a-second-admin-password"); err != nil { // replaces the password of "admin"
		t.Fatal(err)
	}
	if list, _ := s.Users(); len(list) != 1 || !s.CheckAdminPassword("a-second-admin-password") || s.CheckAdminPassword("a-good-admin-password") {
		t.Fatal("SetAdminPassword must replace, not add")
	}
	admin, _ := s.UserByName("ADMIN") // case-insensitive
	reader, err := s.AddUser("jan", "jan-reads-only-12", RoleReadOnly)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddUser("Jan", "another-password-12", RoleAdmin); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate name: %v", err)
	}
	for _, bad := range [][3]string{{"", "long-enough-pw-12", RoleAdmin}, {"x y", "long-enough-pw-12", RoleAdmin}, {"ok", "short", RoleAdmin}, {"ok", "long-enough-pw-12", "boss"}} {
		if _, err := s.AddUser(bad[0], bad[1], bad[2]); err == nil {
			t.Errorf("%v must be refused", bad)
		}
	}
	if u, err := s.AuthUser("jan", "jan-reads-only-12"); err != nil || u.Role != RoleReadOnly || u.Admin() {
		t.Errorf("reader login: %+v %v", u, err)
	}
	if _, err := s.AuthUser("jan", "wrong-password-12"); !errors.Is(err, ErrAuth) {
		t.Error("wrong password")
	}
	if _, err := s.AuthUser("nobody", "whatever-password-12"); !errors.Is(err, ErrAuth) {
		t.Error("unknown user")
	}

	// The last administrator is protected.
	if err := s.DeleteUser(admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("delete last admin: %v", err)
	}
	if err := s.SetUserRole(admin.ID, RoleReadOnly); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("demote last admin: %v", err)
	}
	if err := s.SetUserRole(reader.ID, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserRole(admin.ID, RoleReadOnly); err != nil {
		t.Errorf("with a second admin the first can be demoted: %v", err)
	}
	if err := s.SetUserPassword(reader.ID, "a-new-password-for-jan"); err != nil {
		t.Fatal(err)
	}
	if !s.CheckUserPassword(reader.ID, "a-new-password-for-jan") || s.CheckUserPassword(reader.ID, "jan-reads-only-12") {
		t.Error("password change")
	}
	if err := s.DeleteUser(admin.ID); err != nil {
		t.Errorf("deleting a non-last admin: %v", err)
	}
	if err := s.DeleteUser(9999); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user: %v", err)
	}
}

func TestTwoStepVerification(t *testing.T) {
	s := newStore(t)
	_ = s.SetAdminPassword("a-good-admin-password")
	u, _ := s.UserByName("admin")
	now := time.Unix(1_800_000_000, 0)

	secret, err := s.BeginTOTP(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := s.PendingTOTP(u.ID); !ok || p != secret {
		t.Error("the pending secret must be readable during setup")
	}
	if got, _ := s.UserByID(u.ID); got.TOTPEnabled {
		t.Fatal("not active before confirmation")
	}
	if _, err := s.ConfirmTOTP(u.ID, "000000", now); !errors.Is(err, ErrBadCode) {
		t.Errorf("a wrong code must not activate: %v", err)
	}
	code, _ := totp.Code(secret, now)
	codes, err := s.ConfirmTOTP(u.ID, code, now)
	if err != nil || len(codes) != 8 {
		t.Fatalf("confirm: %v %v", codes, err)
	}
	if got, _ := s.UserByID(u.ID); !got.TOTPEnabled || s.RecoveryCodesLeft(u.ID) != 8 {
		t.Error("active with 8 recovery codes")
	}

	// A code works once; the next step's code works.
	if s.CheckSecondFactor(u.ID, code, now) {
		t.Error("the code used to confirm must not work again")
	}
	next, _ := totp.Code(secret, now.Add(30*time.Second))
	if !s.CheckSecondFactor(u.ID, next, now.Add(30*time.Second)) {
		t.Error("the next code must work")
	}
	if s.CheckSecondFactor(u.ID, next, now.Add(31*time.Second)) {
		t.Error("replaying a code must fail")
	}
	if s.CheckSecondFactor(u.ID, "123456", now) {
		t.Error("a random code must fail")
	}

	// A recovery code works once.
	if !s.CheckSecondFactor(u.ID, codes[0], now) || s.CheckSecondFactor(u.ID, codes[0], now) {
		t.Error("a recovery code is single-use")
	}
	if s.RecoveryCodesLeft(u.ID) != 7 {
		t.Errorf("left = %d", s.RecoveryCodesLeft(u.ID))
	}
	if !s.CheckSecondFactor(u.ID, " "+codes[1][:4]+codes[1][5:]+" ", now) {
		t.Error("recovery codes are accepted without the dash")
	}

	if err := s.DisableTOTP(u.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.UserByID(u.ID); got.TOTPEnabled || s.CheckSecondFactor(u.ID, codes[2], now) {
		t.Error("disabled: no second factor, old recovery codes are void")
	}
}
