package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/kgooris/office-smtprelay/internal/policy"
)

// BackupVersion is the format version of an exported backup.
const BackupVersion = 1

// Backup is the exportable part of the configuration: the devices (with their
// rules and password hashes) and the settings that are not secrets. It does
// NOT contain the Microsoft client secret, the administrator password, the
// encryption key, the certificate or the event log.
type Backup struct {
	Version   int               `json:"version"`
	CreatedAt time.Time         `json:"created_at"`
	Clients   []BackupClient    `json:"clients"`
	Settings  map[string]string `json:"settings"`
}

// BackupClient is one device in a backup.
type BackupClient struct {
	Name         string          `json:"name"`
	Addr         string          `json:"addr"`
	Username     string          `json:"username"`
	PasswordHash string          `json:"password_hash"`
	Enabled      bool            `json:"enabled"`
	Policy       json.RawMessage `json:"policy,omitempty"`
}

// backupSettingKeys are the settings a backup carries.
var backupSettingKeys = []string{
	SettingOwnDomains, SettingLang, SettingRetentionDays, SettingMaxMessageMB, SettingMaxConnsPerIP,
	SettingTLSMin, SettingImplicitPort, SettingLegacyPort,
	"notify.enabled", "notify.to", "notify.from", "notify.events",
}

// ExportBackup collects the configuration.
func (s *Store) ExportBackup() (Backup, error) {
	b := Backup{Version: BackupVersion, CreatedAt: s.now().UTC(), Settings: map[string]string{}}
	rows, err := s.db.Query(`SELECT ` + clientCols + ` FROM clients ORDER BY name`)
	if err != nil {
		return b, err
	}
	defer rows.Close()
	for rows.Next() {
		c, hash, err := scanClient(rows)
		if err != nil {
			return b, err
		}
		bc := BackupClient{Name: c.Name, Addr: c.AddrString(), Username: c.Username, PasswordHash: hash, Enabled: c.Enabled}
		if c.Policy.ActiveRules() > 0 || c.Policy.TLS.MinVersion != "" {
			bc.Policy = json.RawMessage(c.Policy.JSON())
		}
		b.Clients = append(b.Clients, bc)
	}
	if err := rows.Err(); err != nil {
		return b, err
	}
	for _, k := range backupSettingKeys {
		if v, ok, _ := s.Setting(k); ok && v != "" {
			b.Settings[k] = v
		}
	}
	return b, nil
}

// ImportResult says what an import did.
type ImportResult struct {
	Added, Updated int
}

// ImportBackup merges a backup into the configuration: devices are matched by
// name (updated when they exist, added otherwise); devices that are not in the
// backup are left alone. Everything is checked first; if anything is wrong,
// nothing is changed.
func (s *Store) ImportBackup(b Backup) (ImportResult, error) {
	var res ImportResult
	if b.Version != BackupVersion {
		return res, fmt.Errorf("%w: unsupported backup version %d", ErrInvalid, b.Version)
	}
	type prepared struct {
		c   BackupClient
		pol policy.Policy
	}
	var list []prepared
	seenName, seenUser := map[string]bool{}, map[string]bool{}
	for _, c := range b.Clients {
		if !validName(c.Name) || !validUsername(c.Username) {
			return res, fmt.Errorf("%w: device %q: name or username", ErrInvalid, c.Name)
		}
		if _, err := ParseAddrList(c.Addr); err != nil {
			return res, fmt.Errorf("device %q: %w", c.Name, err)
		}
		if !strings.HasPrefix(c.PasswordHash, "$argon2id$") {
			return res, fmt.Errorf("%w: device %q: not a password hash from this program", ErrInvalid, c.Name)
		}
		pol := policy.Parse(string(c.Policy))
		if err := pol.Validate(); err != nil {
			return res, fmt.Errorf("%w: device %q: %v", ErrInvalid, c.Name, err)
		}
		ln, lu := strings.ToLower(c.Name), strings.ToLower(c.Username)
		if seenName[ln] || seenUser[lu] {
			return res, fmt.Errorf("%w: device %q appears twice", ErrInvalid, c.Name)
		}
		seenName[ln], seenUser[lu] = true, true
		list = append(list, prepared{c, pol})
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	for _, p := range list {
		ps, _ := ParseAddrList(p.c.Addr)
		en := 0
		if p.c.Enabled {
			en = 1
		}
		var id int64
		err := tx.QueryRow(`SELECT id FROM clients WHERE name = ?`, p.c.Name).Scan(&id)
		if err == nil {
			if _, err := tx.Exec(`UPDATE clients SET addr = ?, username = ?, password_hash = ?, enabled = ?, policy = ? WHERE id = ?`,
				joinPrefixes(ps), p.c.Username, p.c.PasswordHash, en, p.pol.JSON(), id); err != nil {
				return res, fmt.Errorf("%w: device %q: %v", ErrExists, p.c.Name, err)
			}
			res.Updated++
			continue
		}
		if _, err := tx.Exec(`INSERT INTO clients(name, addr, username, password_hash, enabled, created_at, policy) VALUES(?,?,?,?,?,?,?)`,
			p.c.Name, joinPrefixes(ps), p.c.Username, p.c.PasswordHash, en, s.now().Unix(), p.pol.JSON()); err != nil {
			return res, fmt.Errorf("%w: device %q: %v", ErrExists, p.c.Name, err)
		}
		res.Added++
	}
	if err := tx.Commit(); err != nil {
		return res, err
	}

	// Settings go through their own validation; an invalid value is skipped.
	get := func(k string) string { return b.Settings[k] }
	if d := get(SettingOwnDomains); d != "" {
		_ = s.SetOwnDomains(SplitDomains(d))
	}
	g := General{Lang: get(SettingLang)}
	g.RetentionDays, _ = atoiSafe(get(SettingRetentionDays))
	g.MaxMessageMB, _ = atoiSafe(get(SettingMaxMessageMB))
	g.MaxConnsPerIP, _ = atoiSafe(get(SettingMaxConnsPerIP))
	_ = s.SetGeneral(g)
	_ = s.SetTLSMin(get(SettingTLSMin))
	imp, _ := atoiSafe(get(SettingImplicitPort))
	leg, _ := atoiSafe(get(SettingLegacyPort))
	_ = s.SetExtraPorts(Ports{Implicit: imp, Legacy: leg}, 0)
	for _, k := range []string{"notify.enabled", "notify.to", "notify.from", "notify.events"} {
		if v, ok := b.Settings[k]; ok && len(v) < 300 && !strings.ContainsAny(v, "\r\n") {
			_ = s.SetSetting(k, v, false)
		}
	}
	return res, nil
}

func atoiSafe(s string) (int, error) {
	var n int
	_, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &n)
	if err != nil || n < 0 {
		return 0, err
	}
	return n, nil
}
