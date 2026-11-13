package store

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/policy"
)

func TestBackupRoundTripBetweenStores(t *testing.T) {
	a := newStore(t)
	if _, err := a.AddClient("Printer", "192.0.2.10, 192.0.2.64/28", "printer", "a-long-password-1"); err != nil {
		t.Fatal(err)
	}
	_ = a.SetClientPolicy("Printer", policy.FromPreset(policy.PresetStrict, "printer@gbk.be"))
	_, _ = a.AddClient("Plain", "192.0.2.11", "plain", "another-long-pw-2")
	_ = a.SetClientEnabled("Plain", false)
	_ = a.SetOwnDomains([]string{"gbk.be"})
	_ = a.SetGeneral(General{Lang: "nl", RetentionDays: 60})
	_ = a.SetTLSMin("1.1")
	_ = a.SetGraphCredentials(graph.Credentials{TenantID: "t", ClientID: "c", ClientSecret: "TOP-SECRET-VALUE"}, a.now().AddDate(1, 0, 0))
	_ = a.SetAdminPassword("an-admin-password-12")

	b, err := a.ExportBackup()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(b)
	for _, forbidden := range []string{"TOP-SECRET-VALUE", "graph.client_secret", "admin.password_hash", "an-admin-password-12"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("the backup must not contain %q", forbidden)
		}
	}
	if !strings.Contains(string(raw), "$argon2id$") {
		t.Error("password hashes are part of the backup")
	}

	// Restore into a fresh store: the printer must work with its old password and rules.
	var back Backup
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	c := newStore(t)
	res, err := c.ImportBackup(back)
	if err != nil || res.Added != 2 || res.Updated != 0 {
		t.Fatalf("import = %+v, %v", res, err)
	}
	if _, err := c.Authenticate(ip("192.0.2.70"), "printer", "a-long-password-1"); err != nil {
		t.Errorf("login with the old password after restore: %v", err)
	}
	if got := c.ClientPolicy("Printer"); got.JSON() != policy.FromPreset(policy.PresetStrict, "printer@gbk.be").JSON() {
		t.Errorf("policy = %s", got.JSON())
	}
	if cl, _ := c.ClientByName("Plain"); cl.Enabled {
		t.Error("a disabled device stays disabled")
	}
	if c.OwnDomains()[0] != "gbk.be" || c.General().Lang != "nl" || c.General().RetentionDays != 60 || c.TLSMin() != "1.1" {
		t.Error("settings not restored")
	}
	if _, ok, _ := c.GraphCredentials(); ok {
		t.Error("the Microsoft connection is not part of a backup")
	}
	if c.HasAdminPassword() {
		t.Error("the admin password is not part of a backup")
	}

	// Importing again updates instead of duplicating.
	res, err = c.ImportBackup(back)
	if err != nil || res.Added != 0 || res.Updated != 2 {
		t.Errorf("second import = %+v, %v", res, err)
	}
}

func TestImportRejectsBadBackupsWithoutChangingAnything(t *testing.T) {
	s := newStore(t)
	_, _ = s.AddClient("Existing", "192.0.2.5", "existing", "a-long-password-1")
	hash, _ := HashPassword("whatever-long-pw-1")
	good := BackupClient{Name: "New", Addr: "192.0.2.6", Username: "new", PasswordHash: hash, Enabled: true}
	cases := map[string]Backup{
		"version":       {Version: 99},
		"bad hash":      {Version: 1, Clients: []BackupClient{good, {Name: "X", Addr: "192.0.2.7", Username: "x", PasswordHash: "plain-text"}}},
		"bad address":   {Version: 1, Clients: []BackupClient{{Name: "X", Addr: "nope", Username: "x", PasswordHash: hash}}},
		"duplicate":     {Version: 1, Clients: []BackupClient{good, good}},
		"bad policy":    {Version: 1, Clients: []BackupClient{{Name: "X", Addr: "192.0.2.7", Username: "x", PasswordHash: hash, Policy: json.RawMessage(`{"rcpt":{"mode":"enforce","scope":"list"}}`)}}},
		"username used": {Version: 1, Clients: []BackupClient{good, {Name: "Other", Addr: "192.0.2.8", Username: "existing", PasswordHash: hash}}},
	}
	for name, b := range cases {
		if _, err := s.ImportBackup(b); err == nil {
			t.Errorf("%s must be refused", name)
		}
		list, _ := s.ListClients()
		if len(list) != 1 || list[0].Name != "Existing" {
			t.Fatalf("%s: a refused import must change nothing, clients = %v", name, list)
		}
	}
}
