// Package store persists clients, settings and the event log in SQLite.
// It implements relay.Registry and relay.Recorder.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no cgo

	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/policy"
	"github.com/kgooris/office-smtprelay/internal/relay"
)

// Setting keys.
const (
	SettingTenantID      = "graph.tenant_id"
	SettingClientID      = "graph.client_id"
	SettingClientSecret  = "graph.client_secret" // stored encrypted
	SettingSecretExpires = "graph.secret_expires"
)

// Errors returned by client management.
var (
	ErrExists   = errors.New("already exists")
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid value")
)

// Store is the database handle.
type Store struct {
	db  *sql.DB
	key []byte
	now func() time.Time

	// writeMu serialises the "last seen" updates, which are best-effort.
	writeMu sync.Mutex
}

// Open opens (and migrates) the database at path. key encrypts secrets.
func Open(path string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("store: key must be 32 bytes")
	}
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer; the data volume is tiny
	s := &Store{db: db, key: key, now: time.Now}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Ping checks that the database answers (used by the health check).
func (s *Store) Ping() error { return s.db.Ping() }

const schema = `
CREATE TABLE IF NOT EXISTS clients (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  name          TEXT NOT NULL UNIQUE COLLATE NOCASE,
  addr          TEXT NOT NULL,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    INTEGER NOT NULL,
  last_seen     INTEGER
);
CREATE TABLE IF NOT EXISTS settings (
  key       TEXT PRIMARY KEY,
  value     BLOB NOT NULL,
  encrypted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'admin',
  totp_secret   BLOB,
  totp_pending  BLOB,
  totp_enabled  INTEGER NOT NULL DEFAULT 0,
  totp_last     INTEGER NOT NULL DEFAULT 0,
  recovery      TEXT NOT NULL DEFAULT '',
  created_at    INTEGER NOT NULL,
  last_login    INTEGER
);
CREATE TABLE IF NOT EXISTS events (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  first_at   INTEGER NOT NULL,
  last_at    INTEGER NOT NULL,
  remote_ip  TEXT NOT NULL,
  client     TEXT NOT NULL DEFAULT '',
  reason     TEXT NOT NULL,
  smtp_code  INTEGER NOT NULL,
  sender     TEXT NOT NULL DEFAULT '',
  recipients INTEGER NOT NULL DEFAULT 0,
  bytes      INTEGER NOT NULL DEFAULT 0,
  detail     TEXT NOT NULL DEFAULT '',
  count      INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS events_last_at ON events(last_at);
CREATE INDEX IF NOT EXISTS events_ip ON events(remote_ip);
`

func (s *Store) migrate() error {
	var v int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return err
	}
	if v > schemaVersion {
		return fmt.Errorf("store: database schema version %d is newer than this program supports", v)
	}
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}
	if v < 2 { // v2: optional per-client policy (JSON); an empty policy changes nothing
		if _, err := s.db.Exec(`ALTER TABLE clients ADD COLUMN policy TEXT NOT NULL DEFAULT '{}'`); err != nil {
			return err
		}
	}
	if v < 3 { // v3: several web UI users; the old single password becomes the user "admin"
		if err := s.migrateUsers(); err != nil {
			return err
		}
	}
	if v < schemaVersion {
		_, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion))
		return err
	}
	return nil
}

const schemaVersion = 3

// ---- clients ---------------------------------------------------------------

// Client is a registered device.
type Client struct {
	ID        int64
	Name      string
	Addr      netip.Prefix   // first address or network; single IP is stored as /32 or /128
	More      []netip.Prefix // further addresses or networks of the same device
	Policy    policy.Policy  // optional rules; the zero value changes nothing
	Username  string
	Enabled   bool
	CreatedAt time.Time
	LastSeen  time.Time // zero if never
}

// Contains reports whether ip is covered by one of the client's addresses.
func (c Client) Contains(ip netip.Addr) bool {
	if c.Addr.Contains(ip) {
		return true
	}
	for _, p := range c.More {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// AddrString lists all addresses of the client, comma separated.
func (c Client) AddrString() string {
	parts := []string{c.Addr.String()}
	for _, p := range c.More {
		parts = append(parts, p.String())
	}
	return strings.Join(parts, ", ")
}

// ParseAddrList accepts one or more addresses or networks separated by commas,
// spaces or semicolons ("192.0.2.10, 192.0.2.0/28").
func ParseAddrList(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' }) {
		p, err := ParseAddr(part)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if len(out) == 0 || len(out) > 20 {
		return nil, fmt.Errorf("%w: give between 1 and 20 addresses", ErrInvalid)
	}
	return out, nil
}

func joinPrefixes(ps []netip.Prefix) string {
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.String()
	}
	return strings.Join(parts, ",")
}

// ParseAddr accepts "192.0.2.10" or "192.0.2.0/24" (IPv4 or IPv6).
func ParseAddr(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%w: address %q", ErrInvalid, s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("%w: address %q", ErrInvalid, s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validUsername(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || r == ':' {
			return false
		}
	}
	return true
}

// AddClient registers a device. The password must be at least 12 characters
// (use GeneratePassword).
func (s *Store) AddClient(name, addr, username, password string) (Client, error) {
	if !validName(name) || !validUsername(username) {
		return Client{}, fmt.Errorf("%w: name or username", ErrInvalid)
	}
	if len(password) < 12 {
		return Client{}, fmt.Errorf("%w: password must be at least 12 characters", ErrInvalid)
	}
	prefixes, err := ParseAddrList(addr)
	if err != nil {
		return Client{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return Client{}, err
	}
	now := s.now()
	res, err := s.db.Exec(`INSERT INTO clients(name, addr, username, password_hash, enabled, created_at) VALUES(?,?,?,?,1,?)`,
		name, joinPrefixes(prefixes), username, hash, now.Unix())
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Client{}, fmt.Errorf("%w: name or username", ErrExists)
		}
		return Client{}, err
	}
	id, _ := res.LastInsertId()
	return Client{ID: id, Name: name, Addr: prefixes[0], More: prefixes[1:], Username: username, Enabled: true, CreatedAt: now}, nil
}

func scanClient(sc interface{ Scan(...any) error }) (Client, string, error) {
	var (
		c        Client
		addr     string
		hash     string
		enabled  int
		created  int64
		lastSeen sql.NullInt64
		pol      string
	)
	if err := sc.Scan(&c.ID, &c.Name, &addr, &c.Username, &hash, &enabled, &created, &lastSeen, &pol); err != nil {
		return Client{}, "", err
	}
	var ps []netip.Prefix
	for _, part := range strings.Split(addr, ",") {
		p, err := netip.ParsePrefix(strings.TrimSpace(part))
		if err != nil {
			return Client{}, "", fmt.Errorf("store: corrupt address %q for client %q", addr, c.Name)
		}
		ps = append(ps, p)
	}
	c.Addr, c.More, c.Enabled, c.CreatedAt = ps[0], ps[1:], enabled == 1, time.Unix(created, 0)
	c.Policy = policy.Parse(pol)
	if lastSeen.Valid {
		c.LastSeen = time.Unix(lastSeen.Int64, 0)
	}
	return c, hash, nil
}

const clientCols = `id, name, addr, username, password_hash, enabled, created_at, last_seen, policy`

// ListClients returns all clients ordered by name.
func (s *Store) ListClients() ([]Client, error) {
	rows, err := s.db.Query(`SELECT ` + clientCols + ` FROM clients ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Client
	for rows.Next() {
		c, _, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteClient removes a client by name.
func (s *Store) DeleteClient(name string) error {
	return s.affect(s.db.Exec(`DELETE FROM clients WHERE name = ?`, name))
}

// SetClientEnabled enables or disables a client.
func (s *Store) SetClientEnabled(name string, enabled bool) error {
	v := 0
	if enabled {
		v = 1
	}
	return s.affect(s.db.Exec(`UPDATE clients SET enabled = ? WHERE name = ?`, v, name))
}

// SetClientAddr changes the IP address (or network) of a client.
func (s *Store) SetClientAddr(name, addr string) error {
	ps, err := ParseAddrList(addr)
	if err != nil {
		return err
	}
	return s.affect(s.db.Exec(`UPDATE clients SET addr = ? WHERE name = ?`, joinPrefixes(ps), name))
}

// SetClientPolicy replaces the optional rules of a client.
func (s *Store) SetClientPolicy(name string, p policy.Policy) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return s.affect(s.db.Exec(`UPDATE clients SET policy = ? WHERE name = ?`, p.JSON(), name))
}

// ClientByName returns one client.
func (s *Store) ClientByName(name string) (Client, error) {
	c, _, err := scanClient(s.db.QueryRow(`SELECT `+clientCols+` FROM clients WHERE name = ?`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return Client{}, ErrNotFound
	}
	return c, err
}

// SetClientPassword replaces the password of a client.
func (s *Store) SetClientPassword(name, password string) error {
	if len(password) < 12 {
		return fmt.Errorf("%w: password must be at least 12 characters", ErrInvalid)
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.affect(s.db.Exec(`UPDATE clients SET password_hash = ? WHERE name = ?`, hash, name))
}

func (s *Store) affect(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- relay.Registry --------------------------------------------------------

var _ relay.Registry = (*Store)(nil)

// IPKnown reports whether an enabled client covers this address.
func (s *Store) IPKnown(ip netip.Addr) bool {
	ip = ip.Unmap()
	clients, err := s.ListClients()
	if err != nil {
		return false // fail closed
	}
	for _, c := range clients {
		if c.Enabled && c.Contains(ip) {
			return true
		}
	}
	return false
}

// Authenticate verifies username and password for a connection from ip.
func (s *Store) Authenticate(ip netip.Addr, username, password string) (string, error) {
	ip = ip.Unmap()
	c, hash, err := scanClient(s.db.QueryRow(`SELECT `+clientCols+` FROM clients WHERE username = ?`, username))
	if errors.Is(err, sql.ErrNoRows) || (err == nil && !c.Enabled) {
		VerifyPassword(password, dummyHash) // equalise timing
		return "", relay.ErrUnknownUser
	}
	if err != nil {
		return "", err
	}
	if !VerifyPassword(password, hash) {
		return c.Name, relay.ErrBadPassword
	}
	if !c.Contains(ip) {
		return c.Name, relay.ErrWrongIP
	}
	s.writeMu.Lock()
	_, _ = s.db.Exec(`UPDATE clients SET last_seen = ? WHERE id = ?`, s.now().Unix(), c.ID)
	s.writeMu.Unlock()
	return c.Name, nil
}

// ---- settings --------------------------------------------------------------

// SetSetting stores a value. Secrets are encrypted at rest.
func (s *Store) SetSetting(key, value string, secret bool) error {
	data, enc := []byte(value), 0
	if secret {
		sealed, err := seal(s.key, data)
		if err != nil {
			return err
		}
		data, enc = sealed, 1
	}
	_, err := s.db.Exec(`INSERT INTO settings(key, value, encrypted) VALUES(?,?,?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, encrypted = excluded.encrypted`, key, data, enc)
	return err
}

// Setting returns a value and whether it exists.
func (s *Store) Setting(key string) (string, bool, error) {
	var (
		data []byte
		enc  int
	)
	err := s.db.QueryRow(`SELECT value, encrypted FROM settings WHERE key = ?`, key).Scan(&data, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if enc == 1 {
		if data, err = open(s.key, data); err != nil {
			return "", false, fmt.Errorf("store: cannot decrypt %s (was secret.key replaced?): %w", key, err)
		}
	}
	return string(data), true, nil
}

// SetGraphCredentials saves the Microsoft connection. expires may be zero.
func (s *Store) SetGraphCredentials(c graph.Credentials, expires time.Time) error {
	if c.TenantID == "" || c.ClientID == "" || c.ClientSecret == "" {
		return fmt.Errorf("%w: tenant ID, client ID and client secret are required", ErrInvalid)
	}
	if err := s.SetSetting(SettingTenantID, c.TenantID, false); err != nil {
		return err
	}
	if err := s.SetSetting(SettingClientID, c.ClientID, false); err != nil {
		return err
	}
	if err := s.SetSetting(SettingClientSecret, c.ClientSecret, true); err != nil {
		return err
	}
	exp := ""
	if !expires.IsZero() {
		exp = expires.UTC().Format("2006-01-02")
	}
	return s.SetSetting(SettingSecretExpires, exp, false)
}

// GraphCredentials returns the saved Microsoft connection, if complete.
func (s *Store) GraphCredentials() (graph.Credentials, bool, error) {
	var c graph.Credentials
	for _, f := range []struct {
		key string
		dst *string
	}{{SettingTenantID, &c.TenantID}, {SettingClientID, &c.ClientID}, {SettingClientSecret, &c.ClientSecret}} {
		v, ok, err := s.Setting(f.key)
		if err != nil {
			return graph.Credentials{}, false, err
		}
		if !ok || v == "" {
			return graph.Credentials{}, false, nil
		}
		*f.dst = v
	}
	return c, true, nil
}

// SecretExpires returns the recorded expiry date of the client secret.
func (s *Store) SecretExpires() (time.Time, bool) {
	v, ok, err := s.Setting(SettingSecretExpires)
	if err != nil || !ok || v == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", v)
	return t, err == nil
}

// ---- events (relay.Recorder) ----------------------------------------------

var _ relay.Recorder = (*Store)(nil)

// repeatWindow is the period in which identical failures are merged into one row.
const repeatWindow = 10 * time.Minute

// Record stores an event. Identical failures within repeatWindow are merged
// (count is incremented) so a misconfigured device cannot flood the log.
func (s *Store) Record(e relay.Event) {
	if e.Time.IsZero() {
		e.Time = s.now()
	}
	ip := ""
	if e.RemoteIP.IsValid() {
		ip = e.RemoteIP.String()
	}
	ts := e.Time.Unix()
	if e.Reason != relay.ReasonSent {
		res, err := s.db.Exec(`UPDATE events SET last_at = ?, count = count + 1 WHERE id = (
			SELECT id FROM events WHERE remote_ip = ? AND client = ? AND reason = ? AND smtp_code = ?
			  AND sender = ? AND detail = ? AND last_at >= ? ORDER BY last_at DESC LIMIT 1)`,
			ts, ip, e.Client, string(e.Reason), e.SMTPCode, e.Sender, e.Detail, ts-int64(repeatWindow/time.Second))
		if err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				return
			}
		}
	}
	_, _ = s.db.Exec(`INSERT INTO events(first_at, last_at, remote_ip, client, reason, smtp_code, sender, recipients, bytes, detail)
		VALUES(?,?,?,?,?,?,?,?,?,?)`,
		ts, ts, ip, e.Client, string(e.Reason), e.SMTPCode, e.Sender, e.Recipients, e.Bytes, e.Detail)
}

// StoredEvent is an event row as shown in the UI.
type StoredEvent struct {
	ID         int64
	FirstAt    time.Time
	LastAt     time.Time
	RemoteIP   string
	Client     string
	Reason     relay.Reason
	SMTPCode   int
	Sender     string
	Recipients int
	Bytes      int
	Detail     string
	Count      int
}

// EventFilter narrows ListEvents. Empty fields match everything.
type EventFilter struct {
	RemoteIP string
	Client   string
	Reason   relay.Reason
	OnlyFail bool // exclude successful sends
	Since    time.Time
}

// eventWhere builds the WHERE fragment (starting with " AND ...") for a filter.
func eventWhere(f EventFilter) (string, []any) {
	var (
		q    string
		args []any
	)
	if f.RemoteIP != "" {
		q += ` AND remote_ip = ?`
		args = append(args, f.RemoteIP)
	}
	if f.Client != "" {
		q += ` AND client = ?`
		args = append(args, f.Client)
	}
	if f.Reason != "" {
		q += ` AND reason = ?`
		args = append(args, string(f.Reason))
	}
	if f.OnlyFail {
		q += ` AND reason <> ? AND reason <> ?`
		args = append(args, string(relay.ReasonSent), string(relay.ReasonPolicyTest))
	}
	if !f.Since.IsZero() {
		q += ` AND last_at >= ?`
		args = append(args, f.Since.Unix())
	}
	return q, args
}

// ListEvents returns the newest events first.
func (s *Store) ListEvents(f EventFilter, limit, offset int) ([]StoredEvent, error) {
	if limit <= 0 || limit > 5000 {
		limit = 100
	}
	where, args := eventWhere(f)
	q := `SELECT id, first_at, last_at, remote_ip, client, reason, smtp_code, sender, recipients, bytes, detail, count FROM events WHERE 1=1` + where
	q += ` ORDER BY last_at DESC, id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		var (
			e           StoredEvent
			first, last int64
			reason      string
		)
		if err := rows.Scan(&e.ID, &first, &last, &e.RemoteIP, &e.Client, &reason, &e.SMTPCode, &e.Sender, &e.Recipients, &e.Bytes, &e.Detail, &e.Count); err != nil {
			return nil, err
		}
		e.FirstAt, e.LastAt, e.Reason = time.Unix(first, 0), time.Unix(last, 0), relay.Reason(reason)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountEvents returns the number of event rows matching the filter
// (each merged failure row counts once).
func (s *Store) CountEvents(f EventFilter) (int, error) {
	q, args := eventWhere(f)
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE 1=1`+q, args...).Scan(&n)
	return n, err
}

// SumFailures returns the number of failed attempts since the given time,
// counting every merged repetition.
func (s *Store) SumFailures(since time.Time) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COALESCE(SUM(count), 0) FROM events WHERE reason <> ? AND reason <> ? AND last_at >= ?`,
		string(relay.ReasonSent), string(relay.ReasonPolicyTest), since.Unix()).Scan(&n)
	return n, err
}

// LastSentByClient returns, per client name, the time of the last successful send.
func (s *Store) LastSentByClient() (map[string]time.Time, error) {
	rows, err := s.db.Query(`SELECT client, MAX(last_at) FROM events WHERE reason = ? AND client <> '' GROUP BY client`, string(relay.ReasonSent))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var (
			name string
			ts   int64
		)
		if err := rows.Scan(&name, &ts); err != nil {
			return nil, err
		}
		out[name] = time.Unix(ts, 0)
	}
	return out, rows.Err()
}

// UnknownDevice is an IP address that tried to connect but is not registered.
type UnknownDevice struct {
	IP      string
	Count   int
	FirstAt time.Time
	LastAt  time.Time
}

// UnknownDevices lists IP addresses refused with ip_not_allowed since the given time.
func (s *Store) UnknownDevices(since time.Time, limit int) ([]UnknownDevice, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.Query(`SELECT remote_ip, SUM(count), MIN(first_at), MAX(last_at) FROM events
		WHERE reason = ? AND last_at >= ? AND remote_ip <> ''
		GROUP BY remote_ip ORDER BY MAX(last_at) DESC LIMIT ?`, string(relay.ReasonIPNotAllowed), since.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UnknownDevice
	for rows.Next() {
		var (
			d           UnknownDevice
			first, last int64
		)
		if err := rows.Scan(&d.IP, &d.Count, &first, &last); err != nil {
			return nil, err
		}
		d.FirstAt, d.LastAt = time.Unix(first, 0), time.Unix(last, 0)
		out = append(out, d)
	}
	return out, rows.Err()
}

// PruneEvents deletes events older than the given age and keeps at most
// maxRows of the newest ones. It returns the number of deleted rows.
func (s *Store) PruneEvents(maxAge time.Duration, maxRows int) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM events WHERE last_at < ?`, s.now().Add(-maxAge).Unix())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if maxRows > 0 {
		res, err = s.db.Exec(`DELETE FROM events WHERE id <= (SELECT id FROM events ORDER BY id DESC LIMIT 1 OFFSET ?)`, maxRows)
		if err != nil {
			return n, err
		}
		m, _ := res.RowsAffected()
		n += m
	}
	return n, nil
}
