package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/kgooris/office-smtprelay/internal/totp"
)

// Roles of the people who use the web UI.
const (
	RoleAdmin    = "admin"    // can change everything
	RoleReadOnly = "readonly" // can look, cannot change anything
)

// MinAdminPasswordLength is the minimum length of a web UI password.
const MinAdminPasswordLength = 12

// ErrAuth is returned when a username or password is wrong.
var ErrAuth = errors.New("invalid credentials")

const legacyAdminHash = "admin.password_hash" // before version 3 there was one shared password

var userNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`)

// User is a person who can sign in to the web UI.
type User struct {
	ID          int64
	Username    string
	Role        string
	TOTPEnabled bool
	CreatedAt   time.Time
	LastLogin   time.Time // zero if never
}

// Admin reports whether the user may change settings.
func (u User) Admin() bool { return u.Role == RoleAdmin }

const userCols = `id, username, role, totp_enabled, created_at, last_login`

func scanUser(sc interface{ Scan(...any) error }) (User, error) {
	var (
		u       User
		enabled int
		created int64
		last    sql.NullInt64
	)
	if err := sc.Scan(&u.ID, &u.Username, &u.Role, &enabled, &created, &last); err != nil {
		return User{}, err
	}
	u.TOTPEnabled, u.CreatedAt = enabled == 1, time.Unix(created, 0)
	if last.Valid {
		u.LastLogin = time.Unix(last.Int64, 0)
	}
	return u, nil
}

// migrateUsers copies the single shared password of older versions into an
// "admin" user, once.
func (s *Store) migrateUsers() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil || n > 0 {
		return err
	}
	hash, ok, err := s.Setting(legacyAdminHash)
	if err != nil || !ok || hash == "" {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO users(username, password_hash, role, created_at) VALUES('admin', ?, ?, ?)`, hash, RoleAdmin, s.now().Unix())
	return err
}

func checkPassword(pw string) error {
	if len(pw) < MinAdminPasswordLength {
		return fmt.Errorf("%w: password must be at least %d characters", ErrInvalid, MinAdminPasswordLength)
	}
	return nil
}

// HasAdminPassword reports whether at least one administrator exists, that is
// whether the first-time setup has been done.
func (s *Store) HasAdminPassword() bool {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ?`, RoleAdmin).Scan(&n)
	return err == nil && n > 0
}

// SetAdminPassword creates the administrator "admin" or replaces its password.
// It is used by the first-time setup and by SMTPRELAY_ADMIN_PASSWORD.
func (s *Store) SetAdminPassword(password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	res, err := s.db.Exec(`UPDATE users SET password_hash = ? WHERE username = 'admin'`, hash)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = s.db.Exec(`INSERT INTO users(username, password_hash, role, created_at) VALUES('admin', ?, ?, ?)`, hash, RoleAdmin, s.now().Unix())
	return err
}

// AuthUser checks a username and password. The time taken does not reveal
// whether the username exists.
func (s *Store) AuthUser(username, password string) (User, error) {
	var hash string
	row := s.db.QueryRow(`SELECT `+userCols+`, password_hash FROM users WHERE username = ?`, strings.TrimSpace(username))
	var (
		u       User
		enabled int
		created int64
		last    sql.NullInt64
	)
	err := row.Scan(&u.ID, &u.Username, &u.Role, &enabled, &created, &last, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		VerifyPassword(password, dummyHash)
		return User{}, ErrAuth
	}
	if err != nil {
		return User{}, err
	}
	if !VerifyPassword(password, hash) {
		return User{}, ErrAuth
	}
	u.TOTPEnabled, u.CreatedAt = enabled == 1, time.Unix(created, 0)
	if last.Valid {
		u.LastLogin = time.Unix(last.Int64, 0)
	}
	return u, nil
}

// CheckUserPassword verifies the password of a known user (for "enter your current password").
func (s *Store) CheckUserPassword(id int64, password string) bool {
	var hash string
	if err := s.db.QueryRow(`SELECT password_hash FROM users WHERE id = ?`, id).Scan(&hash); err != nil {
		VerifyPassword(password, dummyHash)
		return false
	}
	return VerifyPassword(password, hash)
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(id int64) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, _ = s.db.Exec(`UPDATE users SET last_login = ? WHERE id = ?`, s.now().Unix(), id)
}

// UserByID returns one user.
func (s *Store) UserByID(id int64) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// UserByName returns one user by (case-insensitive) name.
func (s *Store) UserByName(name string) (User, error) {
	u, err := scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username = ?`, strings.TrimSpace(name)))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// Users lists all users by name.
func (s *Store) Users() ([]User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func validRole(r string) bool { return r == RoleAdmin || r == RoleReadOnly }

// AddUser creates a user.
func (s *Store) AddUser(username, password, role string) (User, error) {
	username = strings.TrimSpace(username)
	if !userNameRe.MatchString(username) || !validRole(role) {
		return User{}, fmt.Errorf("%w: username or role", ErrInvalid)
	}
	if err := checkPassword(password); err != nil {
		return User{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	res, err := s.db.Exec(`INSERT INTO users(username, password_hash, role, created_at) VALUES(?,?,?,?)`, username, hash, role, s.now().Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return User{}, fmt.Errorf("%w: username", ErrExists)
		}
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Username: username, Role: role, CreatedAt: s.now()}, nil
}

// admins counts the administrators other than id.
func (s *Store) otherAdmins(id int64) int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = ? AND id <> ?`, RoleAdmin, id).Scan(&n)
	return n
}

// ErrLastAdmin is returned when a change would leave no administrator.
var ErrLastAdmin = errors.New("there must be at least one administrator")

// DeleteUser removes a user. The last administrator cannot be removed.
func (s *Store) DeleteUser(id int64) error {
	u, err := s.UserByID(id)
	if err != nil {
		return err
	}
	if u.Admin() && s.otherAdmins(id) == 0 {
		return ErrLastAdmin
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.affect(s.db.Exec(`DELETE FROM users WHERE id = ?`, id))
}

// SetUserRole changes the role. The last administrator cannot be demoted.
func (s *Store) SetUserRole(id int64, role string) error {
	if !validRole(role) {
		return fmt.Errorf("%w: role", ErrInvalid)
	}
	u, err := s.UserByID(id)
	if err != nil {
		return err
	}
	if u.Admin() && role != RoleAdmin && s.otherAdmins(id) == 0 {
		return ErrLastAdmin
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.affect(s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, id))
}

// SetUserPassword replaces a user's password.
func (s *Store) SetUserPassword(id int64, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.affect(s.db.Exec(`UPDATE users SET password_hash = ? WHERE id = ?`, hash, id))
}

// ---- two-step verification -----------------------------------------------------

// BeginTOTP creates a new secret for the user that is not active yet. It
// becomes active when ConfirmTOTP receives a valid code from the app.
func (s *Store) BeginTOTP(id int64) (string, error) {
	secret, err := totp.NewSecret()
	if err != nil {
		return "", err
	}
	sealed, err := seal(s.key, []byte(secret))
	if err != nil {
		return "", err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.affect(s.db.Exec(`UPDATE users SET totp_pending = ? WHERE id = ?`, sealed, id)); err != nil {
		return "", err
	}
	return secret, nil
}

// PendingTOTP returns the secret that is waiting for confirmation, if any.
func (s *Store) PendingTOTP(id int64) (string, bool) {
	var sealed []byte
	if err := s.db.QueryRow(`SELECT totp_pending FROM users WHERE id = ?`, id).Scan(&sealed); err != nil || len(sealed) == 0 {
		return "", false
	}
	b, err := open(s.key, sealed)
	return string(b), err == nil
}

func recoveryHash(code string) string {
	code = strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func newRecoveryCodes(n int) []string {
	const alphabet = "abcdefghjkmnpqrstuvwxyz23456789" // no look-alikes
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		for j := range b {
			b[j] = alphabet[int(b[j])%len(alphabet)]
		}
		out[i] = string(b[:4]) + "-" + string(b[4:])
	}
	return out
}

// ErrBadCode is returned when a verification code is wrong.
var ErrBadCode = errors.New("invalid verification code")

// ConfirmTOTP activates the pending secret when code is valid. It returns the
// recovery codes, which are shown once; only their hashes are stored.
func (s *Store) ConfirmTOTP(id int64, code string, now time.Time) ([]string, error) {
	secret, ok := s.PendingTOTP(id)
	if !ok {
		return nil, ErrNotFound
	}
	step, valid := totp.Verify(secret, code, now, 0)
	if !valid {
		return nil, ErrBadCode
	}
	sealed, err := seal(s.key, []byte(secret))
	if err != nil {
		return nil, err
	}
	codes := newRecoveryCodes(8)
	hashes := make([]string, len(codes))
	for i, c := range codes {
		hashes[i] = recoveryHash(c)
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	err = s.affect(s.db.Exec(`UPDATE users SET totp_secret = ?, totp_pending = NULL, totp_enabled = 1, totp_last = ?, recovery = ? WHERE id = ?`,
		sealed, step, strings.Join(hashes, ","), id))
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// DisableTOTP turns two-step verification off for a user.
func (s *Store) DisableTOTP(id int64) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return s.affect(s.db.Exec(`UPDATE users SET totp_secret = NULL, totp_pending = NULL, totp_enabled = 0, totp_last = 0, recovery = '' WHERE id = ?`, id))
}

// CheckSecondFactor verifies a code from the app (each code works once) or a
// recovery code (consumed when used).
func (s *Store) CheckSecondFactor(id int64, input string, now time.Time) bool {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var (
		sealed   []byte
		last     int64
		recovery string
	)
	if err := s.db.QueryRow(`SELECT totp_secret, totp_last, recovery FROM users WHERE id = ? AND totp_enabled = 1`, id).Scan(&sealed, &last, &recovery); err != nil {
		return false
	}
	if secret, err := open(s.key, sealed); err == nil {
		if step, ok := totp.Verify(string(secret), input, now, last); ok {
			_, _ = s.db.Exec(`UPDATE users SET totp_last = ? WHERE id = ?`, step, id)
			return true
		}
	}
	h := recoveryHash(input)
	var kept []string
	used := false
	for _, r := range strings.Split(recovery, ",") {
		if r != "" && r == h && !used {
			used = true
			continue
		}
		if r != "" {
			kept = append(kept, r)
		}
	}
	if used {
		_, _ = s.db.Exec(`UPDATE users SET recovery = ? WHERE id = ?`, strings.Join(kept, ","), id)
	}
	return used
}

// RecoveryCodesLeft says how many recovery codes the user still has.
func (s *Store) RecoveryCodesLeft(id int64) int {
	var r string
	_ = s.db.QueryRow(`SELECT recovery FROM users WHERE id = ?`, id).Scan(&r)
	n := 0
	for _, c := range strings.Split(r, ",") {
		if c != "" {
			n++
		}
	}
	return n
}

// CheckAdminPassword verifies the password of the user "admin".
func (s *Store) CheckAdminPassword(password string) bool {
	u, err := s.AuthUser("admin", password)
	return err == nil && u.Admin()
}
