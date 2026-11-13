package web

import (
	"bytes"
	"errors"
	"github.com/kgooris/office-smtprelay/internal/config"
	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/notify"
	"github.com/kgooris/office-smtprelay/internal/store"
	"github.com/kgooris/office-smtprelay/internal/tlsutil"
	"html"
	"mime/multipart"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/kgooris/office-smtprelay/internal/relay"
)

type fakeRelay struct{ blocked map[string]time.Time }

func (f *fakeRelay) BlockedClients() map[string]time.Time { return f.blocked }
func (f *fakeRelay) UnblockClient(name string)            { delete(f.blocked, name) }

func TestPresetsAndRulesPage(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()

	// Basic (default): no rules at all.
	e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"Plain"}, "ip": {"192.0.2.20"}})
	if e.st.ClientPolicy("Plain").ActiveRules() != 0 {
		t.Error("the basic preset must not add rules")
	}

	// Recommended with a sender mailbox: limits on, recipients in test mode, sender rewritten.
	r := e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"Printer"}, "ip": {"192.0.2.21, 192.0.2.64/28"}, "preset": {"recommended"}, "mailbox": {"Printer@gbk.be"}})
	if r.status != 200 {
		t.Fatalf("add = %d", r.status)
	}
	p := e.st.ClientPolicy("Printer")
	if p.Sender.Action != "rewrite" || p.Sender.RewriteTo != "printer@gbk.be" || p.Limits.PerHour == 0 || p.Rcpt.Mode != "log" {
		t.Errorf("recommended preset = %s", p.JSON())
	}
	if c, _ := e.st.ClientByName("Printer"); len(c.More) != 1 {
		t.Errorf("two address ranges must be kept: %v", c.AddrString())
	}

	for tab, wants := range map[string][]string{
		"general": {"192.0.2.21/32, 192.0.2.64/28", "Printer"},
		"sender":  {`value="printer@gbk.be"`},
		"limits":  {`name="lim_hour" value="120"`},
	} {
		page := e.get("/clients/edit?name=Printer&tab=" + tab).body
		for _, want := range wants {
			if !strings.Contains(page, want) {
				t.Errorf("tab %s lacks %q", tab, want)
			}
		}
	}

	// Saving one tab leaves the rules of the other tabs alone.
	before := e.st.ClientPolicy("Printer")
	if r := e.post("/clients/edit", url.Values{"csrf": {csrf}, "name": {"Printer"}, "tab": {"messages"}, "reply_to": {"help@gbk.be"}, "subject_tag": {"Scan"}}); !strings.Contains(r.location, "tab=messages") || !strings.Contains(r.location, "ok=policy_saved") {
		t.Fatalf("tab save = %q", r.location)
	}
	after := e.st.ClientPolicy("Printer")
	if after.Headers.ReplyTo != "help@gbk.be" || after.Sender.Mode != before.Sender.Mode || after.Sender.RewriteTo != before.Sender.RewriteTo || after.Limits.PerHour != before.Limits.PerHour {
		t.Errorf("saving the message tab changed other rules: %s -> %s", before.JSON(), after.JSON())
	}

	// Save: sender allowlist with enforce.
	form := url.Values{"csrf": {csrf}, "name": {"Printer"}, "sender_mode": {"enforce"}, "sender_action": {"reject"}, "sender_allowed": {"printer@gbk.be\n@scan.gbk.be"},
		"rcpt_mode": {"enforce"}, "rcpt_scope": {"internal"}, "lim_mode": {"log"}, "lim_hour": {"10"}, "lim_action": {"block"}, "lim_block": {"15"},
		"reply_to": {"help@gbk.be"}, "subject_tag": {"Printer"}}
	if r := e.post("/clients/edit", form); !strings.Contains(r.location, "ok=policy_saved") {
		t.Fatalf("save = %d %q", r.status, r.location)
	}
	p = e.st.ClientPolicy("Printer")
	if p.Sender.Mode != "enforce" || len(p.Sender.Allowed) != 2 || p.Limits.PerHour != 10 || p.Limits.PerDay != 0 || p.Limits.BlockMinutes != 15 || p.Headers.SubjectTag != "Printer" {
		t.Errorf("saved policy = %s", p.JSON())
	}

	// Invalid rules are refused with a message and nothing changes.
	bad := url.Values{"csrf": {csrf}, "name": {"Printer"}, "sender_mode": {"enforce"}, "sender_action": {"reject"}}
	if r := e.post("/clients/edit", bad); r.status != 400 || !strings.Contains(r.body, "not saved") {
		t.Errorf("invalid rules: %d", r.status)
	}
	if e.st.ClientPolicy("Printer").Sender.Mode != "enforce" || len(e.st.ClientPolicy("Printer").Sender.Allowed) != 2 {
		t.Error("an invalid save must not change the stored rules")
	}

	// The client list shows the rule count and the test-mode badge.
	list := e.get("/clients").body
	if !strings.Contains(list, "4 active") || !strings.Contains(list, "test mode") {
		t.Errorf("clients page: %s", list)
	}
}

func TestPauseUnblockAndDomains(t *testing.T) {
	e := newEnv(t, nil)
	fr := &fakeRelay{blocked: map[string]time.Time{"Printer": time.Now().Add(10 * time.Minute)}}
	e.srv.d.Relay = fr
	csrf := e.login()
	e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"Printer"}, "ip": {"192.0.2.21"}})

	if d := e.get("/").body; !strings.Contains(d, "Pause all sending") || !strings.Contains(d, "temporarily blocked") {
		t.Error("the dashboard must show the emergency stop and the blocked device")
	}
	if r := e.post("/pause", url.Values{"csrf": {csrf}, "pause": {"1"}}); !strings.Contains(r.location, "ok=paused") || !e.st.Paused() {
		t.Fatalf("pause: %q", r.location)
	}
	if d := e.get("/").body; !strings.Contains(d, "Resume sending") {
		t.Error("a paused relay must offer to resume")
	}
	e.post("/pause", url.Values{"csrf": {csrf}, "pause": {"0"}})
	if e.st.Paused() {
		t.Error("resume")
	}

	if r := e.post("/clients/unblock", url.Values{"csrf": {csrf}, "name": {"Printer"}}); !strings.Contains(r.location, "ok=client_unblocked") || len(fr.blocked) != 0 {
		t.Errorf("unblock: %q", r.location)
	}

	e.post("/settings/domains", url.Values{"csrf": {csrf}, "domains": {"GBK.be, @contoso.com"}})
	if got := e.st.OwnDomains(); len(got) != 2 || got[0] != "gbk.be" {
		t.Errorf("domains = %v", got)
	}
	if !strings.Contains(e.get("/settings").body, "gbk.be, contoso.com") {
		t.Error("the settings page must show the internal domains")
	}
}

func TestTestModeHitsShownOnDashboardAndLogs(t *testing.T) {
	e := newEnv(t, nil)
	e.login()
	e.st.Record(testEvent("Printer", "sender_not_allowed: boss@x.example"))
	if !strings.Contains(e.get("/").body, "would have been blocked") {
		t.Error("the dashboard must mention test-mode hits")
	}
	if !strings.Contains(e.get("/logs?status=test&period=7d").body, "sender_not_allowed") {
		t.Error("the log filter for test mode must list them")
	}
	if strings.Contains(e.get("/logs?status=failed&period=7d").body, "sender_not_allowed") {
		t.Error("test-mode hits are not failures")
	}
}

func testEvent(client, detail string) relay.Event {
	return relay.Event{RemoteIP: netip.MustParseAddr("192.0.2.21"), Client: client, Reason: relay.ReasonPolicyTest, SMTPCode: 250, Detail: detail}
}

func TestGeneralTabActionsReturnToTheEditPage(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"Printer"}, "ip": {"192.0.2.21"}})
	r := e.post("/clients/toggle", url.Values{"csrf": {csrf}, "name": {"Printer"}, "enable": {"0"}, "back": {"edit"}})
	if !strings.HasPrefix(r.location, "/clients/edit?name=Printer&tab=general") {
		t.Errorf("toggle from the edit page returns to %q", r.location)
	}
	if !strings.Contains(e.get("/clients/edit?name=Printer").body, "Disabled") {
		t.Error("the edit page must show that the device is disabled")
	}
	r = e.post("/clients/ip", url.Values{"csrf": {csrf}, "name": {"Printer"}, "ip": {"192.0.2.30, 192.0.2.64/28"}, "back": {"edit"}})
	if !strings.HasPrefix(r.location, "/clients/edit?name=Printer&tab=general") || !strings.Contains(r.location, "ok=client_ip_changed") {
		t.Errorf("change IP returns to %q", r.location)
	}
	if r := e.post("/clients/toggle", url.Values{"csrf": {csrf}, "name": {"Printer"}, "enable": {"1"}}); !strings.HasPrefix(r.location, "/clients?") {
		t.Errorf("toggle from the list returns to %q", r.location)
	}
	if r := e.get("/clients?ip=192.0.2.9"); r.status != 303 || r.location != "/clients/new?ip=192.0.2.9" {
		t.Errorf("old add link: %d %q", r.status, r.location)
	}
}

func TestSidebarMenuAndMobileLayout(t *testing.T) {
	for _, lang := range []string{"en", "nl"} {
		e := newEnv(t, func(c *config.Config) { c.Lang = lang })
		e.login()
		body := e.get("/settings").body
		for _, want := range []string{`class="side"`, `id="navtoggle"`, `class="burger"`, `href="/settings" aria-current="page"`,
			`href="/clients"`, `href="/devices"`, `href="/logs"`, `href="/microsoft"`, `href="/test"`, `href="/help"`, `href="/account"`, `class="navgroup"`} {
			if !strings.Contains(body, want) {
				t.Errorf("[%s] menu lacks %q", lang, want)
			}
		}
		if !strings.Contains(body, `name="viewport" content="width=device-width, initial-scale=1"`) {
			t.Errorf("[%s] the viewport meta tag is needed for phones", lang)
		}
		css := e.get("/static/style.css").body
		for _, want := range []string{"@media (max-width: 800px)", ".navtoggle:checked ~ .menu", "font-size: 16px"} {
			if !strings.Contains(css, want) {
				t.Errorf("stylesheet lacks %q", want)
			}
		}
	}
	// The login page has no sidebar.
	e := newEnv(t, nil)
	if strings.Contains(e.get("/login").body, `class="side"`) {
		t.Error("the login page must not show the menu")
	}
}

func TestMessageTabSavesBccAndAttachmentRule(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"Printer"}, "ip": {"192.0.2.21"}})
	form := url.Values{"csrf": {csrf}, "name": {"Printer"}, "tab": {"messages"}, "bcc": {"Archive@gbk.be\nlog@gbk.be"},
		"attach_mode": {"enforce"}, "attach_kind": {"allow"}, "attach_exts": {"PDF, .jpg *.png"}}
	if r := e.post("/clients/edit", form); !strings.Contains(r.location, "ok=policy_saved") {
		t.Fatalf("save = %q", r.location)
	}
	p := e.st.ClientPolicy("Printer")
	if len(p.Headers.Bcc) != 2 || p.Headers.Bcc[0] != "archive@gbk.be" || p.Attach.Kind != "allow" || len(p.Attach.Extensions) != 3 || p.Attach.Extensions[2] != "png" {
		t.Errorf("policy = %s", p.JSON())
	}
	page := e.get("/clients/edit?name=Printer&tab=messages").body
	for _, want := range []string{"archive@gbk.be", "pdf, jpg, png"} {
		if !strings.Contains(page, want) {
			t.Errorf("message tab lacks %q", want)
		}
	}
	bad := url.Values{"csrf": {csrf}, "name": {"Printer"}, "tab": {"messages"}, "attach_mode": {"enforce"}}
	if r := e.post("/clients/edit", bad); r.status != 400 {
		t.Errorf("an attachment rule without file types must be refused, got %d", r.status)
	}
}

func TestNotificationsPage(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	if r := e.get("/notifications"); r.status != 200 || !strings.Contains(r.body, "Send me notifications") {
		t.Fatalf("page = %d", r.status)
	}
	// Invalid input is refused.
	if r := e.post("/notifications", url.Values{"csrf": {csrf}, "enabled": {"1"}, "to": {"nope"}, "from": {"printer@gbk.be"}}); r.status != 400 {
		t.Errorf("invalid address = %d", r.status)
	}
	form := url.Values{"csrf": {csrf}, "enabled": {"1"}, "to": {"Admin@gbk.be"}, "from": {"printer@gbk.be"},
		"kind_ms_error": {"1"}, "kind_paused": {"1"}}
	if r := e.post("/notifications", form); !strings.Contains(r.location, "ok=notify_saved") {
		t.Fatalf("save = %q", r.location)
	}
	page := e.get("/notifications").body
	if !strings.Contains(page, `value="admin@gbk.be"`) || !strings.Contains(page, `name="kind_paused" value="1" checked`) || strings.Contains(page, `name="kind_secret_expiry" value="1" checked`) {
		t.Errorf("saved settings not shown correctly")
	}

	// Test notification goes out through the mailer and is reported.
	if r := e.post("/notifications/test", url.Values{"csrf": {csrf}}); !strings.Contains(r.body, "Test notification sent") {
		t.Errorf("test = %d", r.status)
	}
	if len(e.mail.sent) != 1 || !strings.HasPrefix(e.mail.sent[0], "printer@gbk.be|From: printer@gbk.be\r\nTo: admin@gbk.be") {
		t.Errorf("sent = %q", e.mail.sent)
	}
	e.mail.sendErr = errors.New("graph: HTTP 403 ErrorAccessDenied")
	if r := e.post("/notifications/test", url.Values{"csrf": {csrf}}); !strings.Contains(r.body, "ErrorAccessDenied") {
		t.Error("a failing test notification must show Microsoft's error")
	}
	e.mail.sendErr = nil

	// Using the emergency stop sends a notification when that kind is on.
	e.post("/pause", url.Values{"csrf": {csrf}, "pause": {"1"}})
	e.srv.d.Notifier.(*notify.Notifier).Wait()
	if len(e.mail.sent) != 2 || !strings.Contains(e.mail.sent[1], "Subject: [office-smtprelay] Sending paused") {
		t.Errorf("pause notification missing: %q", e.mail.sent)
	}
}

func TestGeneralSettingsApplyImmediately(t *testing.T) {
	e := newEnv(t, nil) // default language en
	csrf := e.login()
	if !strings.Contains(e.get("/settings").body, "General settings") {
		t.Fatal("starts in English")
	}
	form := url.Values{"csrf": {csrf}, "lang": {"nl"}, "retention": {"90"}, "max_mb": {"12"}, "conns": {"6"}}
	if r := e.post("/settings/general", form); !strings.Contains(r.location, "ok=general_saved") {
		t.Fatalf("save = %q", r.location)
	}
	g := e.st.General()
	if g.Lang != "nl" || g.RetentionDays != 90 || g.MaxMessageMB != 12 || g.MaxConnsPerIP != 6 {
		t.Errorf("stored = %#v", g)
	}
	if !strings.Contains(e.get("/settings").body, "Algemene instellingen") {
		t.Error("the new default language must apply at once")
	}
	if !strings.Contains(e.get("/logs").body, "90 dagen") {
		t.Error("the new retention must be shown at once")
	}
	if r := e.post("/settings/general", url.Values{"csrf": {csrf}, "lang": {"nl"}, "retention": {"99999"}}); r.status != 400 {
		t.Errorf("out of range = %d", r.status)
	}
}

type fakeConn struct {
	info      tlsutil.CertInfo
	uploaded  [][2]string
	regen     []string
	ports     store.Ports
	bindError error
}

func (f *fakeConn) CertInfo() tlsutil.CertInfo { return f.info }
func (f *fakeConn) UploadCert(c, k []byte) error {
	if string(k) == "bad" {
		return errors.New("the certificate and key do not form a valid pair")
	}
	f.uploaded = append(f.uploaded, [2]string{string(c), string(k)})
	return nil
}
func (f *fakeConn) RegenerateCert(n []string) error { f.regen = n; return nil }
func (f *fakeConn) ApplyPorts(p store.Ports) error  { f.ports = p; return f.bindError }
func (f *fakeConn) Listening() (int, int)           { return f.ports.Implicit, f.ports.Legacy }

func multipartForm(t *testing.T, fields map[string]string, files map[string]string) (string, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	for k, v := range files {
		fw, _ := w.CreateFormFile(k, k+".pem")
		_, _ = fw.Write([]byte(v))
	}
	_ = w.Close()
	return w.FormDataContentType(), &buf
}

func TestConnectionPage(t *testing.T) {
	e := newEnv(t, nil)
	fc := &fakeConn{info: tlsutil.CertInfo{Source: tlsutil.SourceGenerated, Names: []string{"relay.lan", "192.0.2.10"}, Fingerprint: "AB12", SelfSigned: true, NotAfter: time.Now().AddDate(5, 0, 0)}}
	e.srv.d.Conn = fc
	csrf := e.login()
	page := e.get("/connection").body
	for _, want := range []string{"relay.lan, 192.0.2.10", "AB12", "Self-signed", "Extra SMTP ports"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	// minimum TLS version
	if r := e.post("/connection/tlsmin", url.Values{"csrf": {csrf}, "tls_min": {"1.0"}}); !strings.Contains(r.location, "ok=conn_saved") || e.st.TLSMin() != "1.0" {
		t.Errorf("tls min: %q %q", r.location, e.st.TLSMin())
	}
	if r := e.post("/connection/tlsmin", url.Values{"csrf": {csrf}, "tls_min": {"9.9"}}); r.status != 400 {
		t.Errorf("bad version = %d", r.status)
	}

	// extra ports
	if r := e.post("/connection/ports", url.Values{"csrf": {csrf}, "implicit": {"4650"}, "legacy": {"2526"}}); !strings.Contains(r.location, "ok=conn_saved") || fc.ports.Implicit != 4650 || fc.ports.Legacy != 2526 {
		t.Fatalf("ports: %q %#v", r.location, fc.ports)
	}
	if body := html.UnescapeString(e.get("/connection").body); !strings.Contains(body, `- "465:4650"`) || !strings.Contains(body, `- "2526:2526"`) {
		t.Error("the compose snippet must be shown")
	}
	if r := e.post("/connection/ports", url.Values{"csrf": {csrf}, "implicit": {"4650"}, "legacy": {"4650"}}); r.status != 400 {
		t.Errorf("equal ports = %d", r.status)
	}
	fc.bindError = errors.New("address already in use")
	if r := e.post("/connection/ports", url.Values{"csrf": {csrf}, "implicit": {"4650"}}); r.status != 400 || !strings.Contains(r.body, "address already in use") {
		t.Errorf("bind error = %d", r.status)
	}

	// certificate upload and regenerate
	ct, body := multipartForm(t, map[string]string{"csrf": csrf}, map[string]string{"cert": "CERT", "key": "KEY"})
	req, _ := http.NewRequest("POST", e.ts.URL+"/connection/cert", body)
	req.Header.Set("Content-Type", ct)
	if r := e.do(req); !strings.Contains(r.location, "ok=conn_cert_saved") || len(fc.uploaded) != 1 || fc.uploaded[0] != [2]string{"CERT", "KEY"} {
		t.Fatalf("upload: %q %v", r.location, fc.uploaded)
	}
	ct, body = multipartForm(t, map[string]string{"csrf": csrf}, map[string]string{"cert": "CERT", "key": "bad"})
	req, _ = http.NewRequest("POST", e.ts.URL+"/connection/cert", body)
	req.Header.Set("Content-Type", ct)
	if r := e.do(req); r.status != 400 || !strings.Contains(r.body, "valid pair") {
		t.Errorf("a refused certificate must say why: %d", r.status)
	}
	if r := e.post("/connection/regenerate", url.Values{"csrf": {csrf}, "names": {"new.lan, 192.0.2.77"}}); !strings.Contains(r.location, "ok=conn_cert_saved") || len(fc.regen) != 2 {
		t.Errorf("regenerate: %q %v", r.location, fc.regen)
	}
}

func TestConnectionPageWithEnvironmentCertificate(t *testing.T) {
	e := newEnv(t, nil)
	e.srv.d.Conn = &fakeConn{info: tlsutil.CertInfo{Source: tlsutil.SourceEnvironment, Fingerprint: "FF", NotAfter: time.Now().AddDate(1, 0, 0)}}
	e.login()
	body := e.get("/connection").body
	if !strings.Contains(body, "set during installation on the server") || strings.Contains(body, `action="/connection/cert"`) {
		t.Error("an environment certificate must not offer upload or regenerate")
	}
}

func TestDeviceConnectionTab(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"Old printer"}, "ip": {"192.0.2.40"}})
	form := url.Values{"csrf": {csrf}, "name": {"Old printer"}, "tab": {"connection"}, "tls_min": {"1.0"}, "tls_plain": {"1"}}
	if r := e.post("/clients/edit", form); !strings.Contains(r.location, "tab=connection") {
		t.Fatalf("save = %q", r.location)
	}
	p := e.st.ClientPolicy("Old printer")
	if p.TLS.MinVersion != "1.0" || !p.TLS.AllowPlain {
		t.Errorf("policy = %s", p.JSON())
	}
	if got := e.st.PolicyForIP(netip.MustParseAddr("192.0.2.40")); got.TLS.MinVersion != "1.0" {
		t.Error("PolicyForIP must find the device")
	}
	if !strings.Contains(e.get("/clients/edit?name=Old%20printer&tab=connection").body, `name="tls_plain" value="1" checked`) {
		t.Error("the tab must show the saved choice")
	}
	if r := e.post("/clients/edit", url.Values{"csrf": {csrf}, "name": {"Old printer"}, "tab": {"connection"}, "tls_min": {"0.9"}}); r.status != 400 {
		t.Errorf("unknown TLS version = %d", r.status)
	}
}

func TestBackupDownloadAndRestore(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"Printer"}, "ip": {"192.0.2.21"}, "preset": {"strict"}, "mailbox": {"printer@gbk.be"}})
	_ = e.st.SetGraphCredentials(graph.Credentials{TenantID: "t", ClientID: "c", ClientSecret: "TOP-SECRET-VALUE"}, time.Now().AddDate(1, 0, 0))

	if r := e.get("/backup"); r.status != 200 || !strings.Contains(r.body, "Download backup") {
		t.Fatalf("page = %d", r.status)
	}
	if r := e.get("/backup/export"); r.status == 200 {
		t.Error("the export must not be reachable with a plain GET")
	}
	req, _ := http.NewRequest("POST", e.ts.URL+"/backup/export", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r := e.do(req)
	if r.status != 200 || !strings.Contains(r.header.Get("Content-Disposition"), "attachment; filename=\"office-smtprelay-backup-") {
		t.Fatalf("export = %d %q", r.status, r.header.Get("Content-Disposition"))
	}
	if strings.Contains(r.body, "TOP-SECRET-VALUE") || !strings.Contains(r.body, `"name": "Printer"`) {
		t.Error("the backup must contain the devices and no secrets")
	}
	if r.header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", r.header.Get("Cache-Control"))
	}

	// Restore into a second, empty UI.
	other := newEnv(t, nil)
	csrf2 := other.login()
	ct, body := multipartForm(t, map[string]string{"csrf": csrf2}, map[string]string{"file": r.body})
	req2, _ := http.NewRequest("POST", other.ts.URL+"/backup/import", body)
	req2.Header.Set("Content-Type", ct)
	if rr := other.do(req2); rr.status != 200 || !strings.Contains(rr.body, "Restored: 1 device(s) added, 0 updated.") {
		t.Fatalf("import = %d", rr.status)
	}
	if other.st.ClientPolicy("Printer").Sender.Allowed[0] != "printer@gbk.be" {
		t.Error("the rules must come back")
	}

	// Garbage is refused.
	ct, body = multipartForm(t, map[string]string{"csrf": csrf2}, map[string]string{"file": "this is not json"})
	req3, _ := http.NewRequest("POST", other.ts.URL+"/backup/import", body)
	req3.Header.Set("Content-Type", ct)
	if rr := other.do(req3); rr.status != 400 {
		t.Errorf("garbage = %d", rr.status)
	}
}
