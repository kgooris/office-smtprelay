package web

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kgooris/office-smtprelay/internal/config"
	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/i18n"
	"github.com/kgooris/office-smtprelay/internal/relay"
	"github.com/kgooris/office-smtprelay/internal/store"
)

const adminPW = "correct-horse-battery"

type fakeMailer struct {
	mu       sync.Mutex
	sent     []string // "from|to-header"
	sendErr  error
	checkErr error
}

func (f *fakeMailer) SendMIME(_ context.Context, sender string, mime []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sendErr != nil {
		return f.sendErr
	}
	f.sent = append(f.sent, sender+"|"+string(mime))
	return nil
}
func (f *fakeMailer) CheckCredentials(context.Context) error { return f.checkErr }

type env struct {
	t    *testing.T
	srv  *Server
	ts   *httptest.Server
	st   *store.Store
	mail *fakeMailer
	c    *http.Client
}

func newEnv(t *testing.T, mutate func(*config.Config)) *env {
	t.Helper()
	dir := t.TempDir()
	key, _ := store.LoadOrCreateKey(dir)
	st, err := store.Open(filepath.Join(dir, "relay.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cfg, err := config.FromEnv(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	cfg.AdminPassword = adminPW
	if mutate != nil {
		mutate(&cfg)
	}
	mail := &fakeMailer{}
	srv, err := New(Deps{Store: st, Mailer: mail, Config: cfg, Version: "test", Logger: log.New(io.Discard, "", 0)})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &env{t: t, srv: srv, ts: ts, st: st, mail: mail, c: c}
}

type resp struct {
	status   int
	body     string
	location string
	header   http.Header
}

func (e *env) do(req *http.Request) resp {
	e.t.Helper()
	r, err := e.c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return resp{status: r.StatusCode, body: string(b), location: r.Header.Get("Location"), header: r.Header}
}

func (e *env) get(path string) resp {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
	return e.do(req)
}

func (e *env) post(path string, form url.Values, hdr ...string) resp {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.ts.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	return e.do(req)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func csrfOf(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token in page: %.200s", body)
	}
	return m[1]
}

// login signs in and returns the session CSRF token.
func (e *env) login() string {
	e.t.Helper()
	pre := csrfOf(e.t, e.get("/login").body)
	r := e.post("/login", url.Values{"csrf": {pre}, "password": {adminPW}})
	if r.status != http.StatusSeeOther || r.location != "/" {
		e.t.Fatalf("login = %d %q", r.status, r.location)
	}
	return csrfOf(e.t, e.get("/").body)
}

// ---- first run and sign-in --------------------------------------------------

func TestFirstRunSetup(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.AdminPassword = "" })
	token := e.srv.SetupToken()
	if token == "" {
		t.Fatal("a setup token must exist when no admin password is set")
	}
	if r := e.get("/"); r.status != 303 || r.location != "/setup" {
		t.Fatalf("GET / = %d %q, want redirect to /setup", r.status, r.location)
	}
	pre := csrfOf(t, e.get("/setup").body)
	form := func(tok, pw, conf string) url.Values {
		return url.Values{"csrf": {pre}, "token": {tok}, "password": {pw}, "confirm": {conf}}
	}
	if r := e.post("/setup", form("wrong", "a-new-admin-password", "a-new-admin-password")); r.status != 401 {
		t.Errorf("wrong token = %d, want 401", r.status)
	}
	if r := e.post("/setup", form(token, "a-new-admin-password", "different-password-12")); r.status != 400 {
		t.Errorf("mismatch = %d, want 400", r.status)
	}
	if r := e.post("/setup", form(token, "short", "short")); r.status != 400 {
		t.Errorf("too short = %d, want 400", r.status)
	}
	if r := e.post("/setup", form(token, "a-new-admin-password", "a-new-admin-password")); r.status != 303 || r.location != "/" {
		t.Fatalf("setup = %d %q", r.status, r.location)
	}
	if e.srv.SetupToken() != "" || !e.st.CheckAdminPassword("a-new-admin-password") {
		t.Error("token must be cleared and the password stored")
	}
	if r := e.get("/clients"); r.status != 200 {
		t.Errorf("session after setup = %d", r.status)
	}
	if r := e.get("/setup"); r.status != 303 || r.location != "/login" {
		t.Errorf("setup must be closed afterwards: %d %q", r.status, r.location)
	}
}

func TestAuthRequiredAndLogin(t *testing.T) {
	e := newEnv(t, nil)
	for _, p := range []string{"/", "/clients", "/logs", "/microsoft", "/test", "/help", "/account", "/devices", "/logs.csv"} {
		if r := e.get(p); r.status != 303 || r.location != "/login" {
			t.Errorf("GET %s unauthenticated = %d %q", p, r.status, r.location)
		}
	}
	pre := csrfOf(t, e.get("/login").body)
	if r := e.post("/login", url.Values{"csrf": {pre}, "password": {"nope-nope-nope"}}); r.status != 401 {
		t.Errorf("wrong password = %d", r.status)
	}
	if r := e.post("/login", url.Values{"csrf": {"forged"}, "password": {adminPW}}); r.status != 403 {
		t.Errorf("forged login CSRF = %d, want 403", r.status)
	}
	e.login()
	if r := e.get("/"); r.status != 200 || !strings.Contains(r.body, "Dashboard") {
		t.Errorf("dashboard = %d", r.status)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t, nil)
	pre := csrfOf(t, e.get("/login").body)
	for i := 0; i < 5; i++ {
		e.post("/login", url.Values{"csrf": {pre}, "password": {"wrong-wrong-wrong"}})
	}
	if r := e.post("/login", url.Values{"csrf": {pre}, "password": {adminPW}}); r.status != 429 {
		t.Errorf("after 5 failures even the right password = %d, want 429", r.status)
	}
}

func TestTrustProxyUsesForwardedAddress(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.TrustProxy = true })
	pre := csrfOf(t, e.get("/login").body)
	for i := 0; i < 5; i++ {
		e.post("/login", url.Values{"csrf": {pre}, "password": {"wrong-wrong-wrong"}}, "X-Forwarded-For", "203.0.113.7")
	}
	if r := e.post("/login", url.Values{"csrf": {pre}, "password": {adminPW}}, "X-Forwarded-For", "203.0.113.7"); r.status != 429 {
		t.Errorf("blocked client = %d, want 429", r.status)
	}
	if r := e.post("/login", url.Values{"csrf": {pre}, "password": {adminPW}}, "X-Forwarded-For", "203.0.113.8"); r.status != 303 {
		t.Errorf("another client behind the proxy = %d, want 303", r.status)
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t, nil)
	r := e.get("/login")
	for h, want := range map[string]string{"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store"} {
		if got := r.header.Get(h); got != want {
			t.Errorf("%s = %q, want %q", h, got, want)
		}
	}
	if csp := r.header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "unsafe") {
		t.Errorf("CSP = %q", csp)
	}
	if css := e.get("/static/style.css"); css.status != 200 || css.header.Get("Cache-Control") == "no-store" {
		t.Errorf("static css = %d cache=%q", css.status, css.header.Get("Cache-Control"))
	}
	if r := e.get("/healthz"); r.status != 200 || !strings.Contains(r.body, "ok") {
		t.Errorf("healthz = %d", r.status)
	}
}

// ---- language ---------------------------------------------------------------

func TestLanguageSwitch(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	if !strings.Contains(e.get("/").body, "Dashboard") {
		t.Fatal("default language must be English")
	}
	if r := e.post("/lang", url.Values{"lang": {"nl"}, "next": {"/clients"}}); r.status != 303 || r.location != "/clients" {
		t.Fatalf("lang = %d %q", r.status, r.location)
	}
	if body := e.get("/").body; !strings.Contains(body, "Overzicht") || !strings.Contains(body, `lang="nl"`) {
		t.Error("UI must switch to Dutch")
	}
	// Open redirects are not possible.
	for _, next := range []string{"//evil.example", "https://evil.example", `/\evil.example`} {
		if r := e.post("/lang", url.Values{"lang": {"en"}, "next": {next}}); r.location != "/" {
			t.Errorf("next=%q redirected to %q", next, r.location)
		}
	}
	// An unsupported language is ignored.
	e.post("/lang", url.Values{"lang": {"xx"}, "next": {"/"}})
	_ = csrf
	if !strings.Contains(e.get("/").body, "Dashboard") {
		t.Error("language en expected after the last valid switch")
	}
}

func TestDefaultLanguageFromConfig(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Lang = "nl" })
	e.login()
	if !strings.Contains(e.get("/").body, "Overzicht") {
		t.Error("SMTPRELAY_LANG=nl must make Dutch the default")
	}
}

var rawKey = regexp.MustCompile(`\b(nav|clients|logs|ms|test|account|dashboard|devices|login|setup|created|reason|hint|flash|title|help)\.[a-z_0-9]+\b`)

func TestAllPagesRenderInBothLanguages(t *testing.T) {
	for _, lang := range i18n.Languages {
		t.Run(lang, func(t *testing.T) {
			e := newEnv(t, func(c *config.Config) { c.Lang = lang })
			e.login()
			_, _ = e.st.AddClient("Printer", "192.0.2.50", "printer", "a-long-password-1")
			e.st.Record(relay.Event{RemoteIP: netip.MustParseAddr("192.0.2.77"), Reason: relay.ReasonIPNotAllowed, SMTPCode: 554})
			e.st.Record(relay.Event{RemoteIP: netip.MustParseAddr("192.0.2.50"), Client: "Printer", Reason: relay.ReasonBadPassword, SMTPCode: 535})
			_ = e.st.SetGraphCredentials(graph.Credentials{TenantID: "t", ClientID: "c", ClientSecret: "s"}, time.Now().AddDate(0, 0, 10))
			for _, p := range []string{"/", "/clients", "/clients/new?ip=192.0.2.9", "/clients/edit?name=Printer", "/clients/edit?name=Printer&tab=sender", "/clients/edit?name=Printer&tab=recipients", "/clients/edit?name=Printer&tab=limits", "/clients/edit?name=Printer&tab=messages", "/devices", "/logs", "/logs?status=failed&period=30d", "/microsoft", "/settings", "/test", "/help", "/account"} {
				r := e.get(p)
				if r.status != 200 {
					t.Errorf("GET %s = %d", p, r.status)
					continue
				}
				for _, m := range rawKey.FindAllString(r.body, -1) {
					if m == "logs.csv" || m == "setup.md" { // real file names, not keys
						continue
					}
					t.Errorf("GET %s shows an untranslated key %q", p, m)
				}
			}
			if !strings.Contains(e.get("/help").body, `id="entra"`) {
				t.Error("help page lost its Entra anchor")
			}
		})
	}
}

// ---- clients ----------------------------------------------------------------

var passwordRe = regexp.MustCompile(`class="secret mono">([^<]+)<`)

func TestClientLifecycleThroughUI(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()

	if r := e.post("/clients/add", url.Values{"name": {"Printer"}, "ip": {"192.0.2.50"}}); r.status != 403 {
		t.Fatalf("POST without CSRF = %d, want 403", r.status)
	}
	r := e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"Printer 1st floor"}, "ip": {"192.0.2.50"}})
	if r.status != 200 {
		t.Fatalf("add = %d", r.status)
	}
	m := passwordRe.FindStringSubmatch(r.body)
	if m == nil || len(m[1]) != 20 {
		t.Fatalf("generated password not shown once: %q", m)
	}
	pw := m[1]
	if !strings.Contains(r.body, "printer-1st-floor") || !strings.Contains(r.body, "STARTTLS") {
		t.Error("credentials page must show username and security")
	}
	if _, err := e.st.Authenticate(netip.MustParseAddr("192.0.2.50"), "printer-1st-floor", pw); err != nil {
		t.Errorf("shown password does not work: %v", err)
	}
	if strings.Contains(e.get("/clients").body, pw) {
		t.Error("the password must never be shown again")
	}

	// Duplicate and invalid input are reported, not accepted.
	if r := e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"printer 1st floor"}, "ip": {"192.0.2.51"}}); r.status != 400 || !strings.Contains(r.body, "already exists") {
		t.Errorf("duplicate = %d", r.status)
	}
	if r := e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {"x"}, "ip": {"not-an-ip"}}); r.status != 400 {
		t.Errorf("bad ip = %d", r.status)
	}

	// Reset password: new one shown, old one stops working.
	r = e.post("/clients/password", url.Values{"csrf": {csrf}, "name": {"Printer 1st floor"}})
	m2 := passwordRe.FindStringSubmatch(r.body)
	if r.status != 200 || m2 == nil || m2[1] == pw {
		t.Fatalf("reset = %d %v", r.status, m2)
	}
	if _, err := e.st.Authenticate(netip.MustParseAddr("192.0.2.50"), "printer-1st-floor", pw); err == nil {
		t.Error("old password must stop working")
	}

	// Toggle, change IP, delete.
	if r := e.post("/clients/toggle", url.Values{"csrf": {csrf}, "name": {"Printer 1st floor"}, "enable": {"0"}}); r.status != 303 || !strings.Contains(r.location, "ok=client_disabled") {
		t.Errorf("toggle = %d %q", r.status, r.location)
	}
	if e.st.IPKnown(netip.MustParseAddr("192.0.2.50")) {
		t.Error("disabled client must not be known")
	}
	if r := e.post("/clients/ip", url.Values{"csrf": {csrf}, "name": {"Printer 1st floor"}, "ip": {"192.0.2.0/24"}}); !strings.Contains(r.location, "ok=client_ip_changed") {
		t.Errorf("ip change = %q", r.location)
	}
	if r := e.post("/clients/ip", url.Values{"csrf": {csrf}, "name": {"Printer 1st floor"}, "ip": {"junk"}}); !strings.Contains(r.location, "err=client_invalid") {
		t.Errorf("bad ip change = %q", r.location)
	}
	if r := e.post("/clients/delete", url.Values{"csrf": {csrf}, "name": {"Printer 1st floor"}}); !strings.Contains(r.location, "ok=client_deleted") {
		t.Errorf("delete = %q", r.location)
	}
	if list, _ := e.st.ListClients(); len(list) != 0 {
		t.Errorf("clients left: %v", list)
	}
	// Flash texts come from the catalog only.
	if r := e.get("/clients?ok=client_deleted"); !strings.Contains(r.body, "Client deleted.") {
		t.Error("flash message missing")
	}
	if r := e.get("/clients?ok=%3Cscript%3E"); strings.Contains(r.body, "<script>") {
		t.Error("arbitrary flash text must not be rendered")
	}
}

func TestClientNameIsEscaped(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	e.post("/clients/add", url.Values{"csrf": {csrf}, "name": {`<img src=x onerror=alert(1)>`}, "ip": {"192.0.2.60"}, "username": {"xss-user"}})
	body := e.get("/clients").body
	if strings.Contains(body, "<img src=x") || !strings.Contains(body, "&lt;img") {
		t.Error("client names must be HTML-escaped")
	}
}

// ---- logs and devices ---------------------------------------------------------

func TestLogsFilterHintsAndCSV(t *testing.T) {
	e := newEnv(t, nil)
	e.login()
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.50")
	e.st.Record(relay.Event{Time: now, RemoteIP: ip, Client: "Printer", Reason: relay.ReasonSent, SMTPCode: 250, Sender: "p@example.com", Recipients: 1})
	e.st.Record(relay.Event{Time: now, RemoteIP: ip, Client: "Printer", Reason: relay.ReasonGraphForbidden, SMTPCode: 550, Sender: "=cmd|calc", Detail: "graph: HTTP 403"})
	e.st.Record(relay.Event{Time: now, RemoteIP: netip.MustParseAddr("192.0.2.99"), Reason: relay.ReasonIPNotAllowed, SMTPCode: 554})

	body := e.get("/logs?status=failed").body
	if !strings.Contains(body, "Microsoft denied the sender mailbox") || !strings.Contains(body, "not allowed to send as this mailbox") {
		t.Error("failure and its hint must be shown")
	}
	if strings.Contains(body, ">Sent<") {
		t.Error("status=failed must hide sent messages")
	}
	if !strings.Contains(e.get("/logs?status=sent").body, ">Sent<") {
		t.Error("status=sent must show sent messages")
	}
	if body := e.get("/logs?ip=192.0.2.99").body; strings.Contains(body, "192.0.2.50") && strings.Contains(body, "Microsoft denied") {
		t.Error("IP filter not applied")
	}

	r := e.get("/logs.csv?period=24h")
	if r.status != 200 || !strings.HasPrefix(r.header.Get("Content-Type"), "text/csv") {
		t.Fatalf("csv = %d %q", r.status, r.header.Get("Content-Type"))
	}
	if !strings.HasPrefix(r.body, "first_at,last_at,count,ip,client,result") {
		t.Errorf("csv header = %.80q", r.body)
	}
	if strings.Contains(r.body, ",=cmd") || !strings.Contains(r.body, "'=cmd|calc") {
		t.Error("CSV must neutralise formula injection")
	}

	dev := e.get("/devices").body
	if !strings.Contains(dev, "192.0.2.99") || !strings.Contains(dev, "/clients/new?ip=192.0.2.99") || strings.Contains(dev, "192.0.2.50<") {
		t.Error("devices page must list only the unregistered IP with an add link")
	}
}

func TestDashboardWarnings(t *testing.T) {
	e := newEnv(t, nil)
	e.login()
	if body := e.get("/").body; !strings.Contains(body, "not configured") || !strings.Contains(body, "No devices are registered") {
		t.Error("empty installation must warn about the connection and the missing clients")
	}
	_ = e.st.SetGraphCredentials(graph.Credentials{TenantID: "t", ClientID: "c", ClientSecret: "s"}, time.Now().AddDate(0, 0, 10))
	if body := e.get("/").body; !strings.Contains(body, "expires in") {
		t.Error("expiry within 30 days must warn")
	}
	_ = e.st.SetGraphCredentials(graph.Credentials{TenantID: "t", ClientID: "c", ClientSecret: "s"}, time.Now().AddDate(0, 0, -1))
	if body := e.get("/").body; !strings.Contains(body, "has expired") {
		t.Error("expired secret must warn")
	}
}

func TestSecretState(t *testing.T) {
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		configured bool
		exp        time.Time
		has        bool
		want       string
	}{
		{false, time.Time{}, false, "none"},
		{true, time.Time{}, false, "ok"},
		{true, now.AddDate(0, 0, 90), true, "ok"},
		{true, now.AddDate(0, 0, 10), true, "soon"},
		{true, now.AddDate(0, 0, -1), true, "expired"},
	}
	for _, c := range cases {
		if got, _ := secretState(c.configured, c.exp, c.has, now); got != c.want {
			t.Errorf("secretState(%v, %v, %v) = %q, want %q", c.configured, c.exp, c.has, got, c.want)
		}
	}
}

// ---- Microsoft connection and test mail ----------------------------------------

func TestMicrosoftConnection(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	form := func(secret string) url.Values {
		return url.Values{"csrf": {csrf}, "tenant": {"tenant-guid"}, "client": {"client-guid"}, "secret": {secret}, "expires": {"2027-05-01"}}
	}
	if r := e.post("/microsoft/save", form("")); !strings.Contains(r.location, "err=ms_invalid") {
		t.Errorf("first save without a secret = %q", r.location)
	}
	if r := e.post("/microsoft/save", url.Values{"csrf": {csrf}, "tenant": {"t"}, "client": {"c"}, "secret": {"s"}, "expires": {"01-05-2027"}}); !strings.Contains(r.location, "err=ms_bad_date") {
		t.Errorf("bad date = %q", r.location)
	}
	if r := e.post("/microsoft/save", form("TOP-SECRET-VALUE")); !strings.Contains(r.location, "ok=ms_saved") {
		t.Fatalf("save = %q", r.location)
	}
	page := e.get("/microsoft").body
	if strings.Contains(page, "TOP-SECRET-VALUE") {
		t.Fatal("the client secret must never be rendered")
	}
	if !strings.Contains(page, "tenant-guid") || !strings.Contains(page, "2027-05-01") {
		t.Error("tenant ID and expiry must be shown")
	}
	// Saving with an empty secret keeps the stored one.
	e.post("/microsoft/save", url.Values{"csrf": {csrf}, "tenant": {"tenant-2"}, "client": {"client-2"}, "secret": {""}, "expires": {""}})
	if c, ok, _ := e.st.GraphCredentials(); !ok || c.ClientSecret != "TOP-SECRET-VALUE" || c.TenantID != "tenant-2" {
		t.Errorf("credentials = %#v", c)
	}

	if r := e.post("/microsoft/check", url.Values{"csrf": {csrf}}); !strings.Contains(r.body, "accepted the tenant ID") {
		t.Error("successful check must say so")
	}
	e.mail.checkErr = &graph.Error{Status: 401, Code: "invalid_client", Message: "AADSTS7000215: Invalid client secret provided."}
	if r := e.post("/microsoft/check", url.Values{"csrf": {csrf}}); !strings.Contains(r.body, "AADSTS7000215") || strings.Contains(r.body, "TOP-SECRET-VALUE") {
		t.Error("failed check must show Microsoft's reason without leaking the secret")
	}
}

func TestSendTestMail(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	send := func(from, to string) resp {
		return e.post("/test", url.Values{"csrf": {csrf}, "from": {from}, "to": {to}})
	}
	if r := send("not an address", "boss@example.org"); r.status != 400 {
		t.Errorf("bad from = %d", r.status)
	}
	if r := send("printer@example.com", "boss@example.org\r\nBcc: attacker@example.net"); r.status != 400 {
		t.Errorf("header injection = %d, want 400", r.status)
	}
	if r := send("Name <printer@example.com>", "boss@example.org"); r.status != 400 {
		t.Errorf("display names are not accepted, got %d", r.status)
	}
	if len(e.mail.sent) != 0 {
		t.Fatal("invalid input must not send anything")
	}
	if r := send("Printer@Example.com", "boss@example.org"); r.status != 200 || !strings.Contains(r.body, "Test mail sent to boss@example.org") {
		t.Fatalf("send = %d", r.status)
	}
	if len(e.mail.sent) != 1 || !strings.HasPrefix(e.mail.sent[0], "printer@example.com|From: printer@example.com\r\nTo: boss@example.org\r\n") {
		t.Errorf("sent = %q", e.mail.sent)
	}
	e.mail.sendErr = errors.New("graph: HTTP 403 ErrorAccessDenied: denied")
	if r := send("printer@example.com", "boss@example.org"); !strings.Contains(r.body, "Sending failed") || !strings.Contains(r.body, "ErrorAccessDenied") {
		t.Error("failure must be shown with Microsoft's reason")
	}
}

// ---- account -----------------------------------------------------------------------

func TestChangePasswordSignsOutOtherSessions(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	other := newEnvSharingServer(e)
	other.login()
	if other.get("/clients").status != 200 {
		t.Fatal("second session must work before the change")
	}
	change := func(cur, pw, conf string) resp {
		return e.post("/account", url.Values{"csrf": {csrf}, "current": {cur}, "password": {pw}, "confirm": {conf}})
	}
	if r := change("wrong-current-pw1", "a-brand-new-password", "a-brand-new-password"); r.status != 401 {
		t.Errorf("wrong current = %d", r.status)
	}
	if r := change(adminPW, "a-brand-new-password", "another-password-12"); r.status != 400 {
		t.Errorf("mismatch = %d", r.status)
	}
	if r := change(adminPW, "short", "short"); r.status != 400 {
		t.Errorf("too short = %d", r.status)
	}
	r := change(adminPW, "a-brand-new-password", "a-brand-new-password")
	if r.status != 303 || !strings.Contains(r.location, "ok=password_changed") {
		t.Fatalf("change = %d %q", r.status, r.location)
	}
	if !e.st.CheckAdminPassword("a-brand-new-password") || e.st.CheckAdminPassword(adminPW) {
		t.Error("password not replaced")
	}
	if rr := other.get("/clients"); rr.status != 303 {
		t.Errorf("the other session must be signed out, got %d", rr.status)
	}
	if rr := e.get("/clients"); rr.status != 200 {
		t.Errorf("the current browser must stay signed in, got %d", rr.status)
	}
}

// newEnvSharingServer returns a second browser (own cookie jar) for the same server.
func newEnvSharingServer(e *env) *env {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &env{t: e.t, srv: e.srv, ts: e.ts, st: e.st, mail: e.mail, c: c}
}

func TestLogout(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	if r := e.post("/logout", url.Values{"csrf": {csrf}}); r.status != 303 || r.location != "/login" {
		t.Fatalf("logout = %d %q", r.status, r.location)
	}
	if r := e.get("/clients"); r.status != 303 {
		t.Errorf("after logout GET /clients = %d", r.status)
	}
}

// ---- translation coverage ------------------------------------------------------------

func TestEveryReasonIsExplained(t *testing.T) {
	cat, err := i18n.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range AllReasons {
		for _, lang := range i18n.Languages {
			if !cat.Has(lang, "reason."+string(r)) {
				t.Errorf("%s: missing reason.%s", lang, r)
			}
			if r != relay.ReasonSent && !cat.Has(lang, "hint."+string(r)) {
				t.Errorf("%s: missing hint.%s", lang, r)
			}
		}
		if badge(r) == "" {
			t.Errorf("no badge for %s", r)
		}
	}
}

var (
	tplKeyRe = regexp.MustCompile(`\bt "([a-z0-9_.]+)"`)
	goKeyRe  = regexp.MustCompile(`\btr\(r, "([a-z0-9_.]*[a-z0-9_])"`) // not the "flash." prefix
)

func TestAllReferencedKeysExist(t *testing.T) {
	cat, _ := i18n.Load()
	var keys []string
	entries, _ := os.ReadDir("templates")
	for _, f := range entries {
		b, _ := os.ReadFile(filepath.Join("templates", f.Name()))
		for _, m := range tplKeyRe.FindAllStringSubmatch(string(b), -1) {
			keys = append(keys, m[1])
		}
	}
	var b []byte
	files, _ := filepath.Glob("*handlers.go")
	for _, f := range files {
		part, _ := os.ReadFile(f)
		b = append(b, part...)
	}
	for _, m := range goKeyRe.FindAllStringSubmatch(string(b), -1) {
		keys = append(keys, m[1])
	}
	for name := range pageFiles {
		keys = append(keys, "title."+name)
	}
	// Redirect-driven flash messages.
	for _, k := range regexp.MustCompile(`(?:ok|err)=([a-z_]+)`).FindAllStringSubmatch(string(b), -1) {
		keys = append(keys, "flash."+k[1])
	}
	for _, k := range []string{"client_exists", "client_invalid", "client_not_found", "internal"} {
		keys = append(keys, "flash."+k)
	}
	if len(keys) < 100 {
		t.Fatalf("only %d keys found, the scan is broken", len(keys))
	}
	for _, k := range keys {
		for _, lang := range i18n.Languages {
			if !cat.Has(lang, k) {
				t.Errorf("%s: key %q is used but missing", lang, k)
			}
		}
	}
	// Every key in the catalog must be used somewhere (no dead texts).
	used := map[string]bool{}
	for _, k := range keys {
		used[k] = true
	}
	for _, k := range cat.Keys("en", "") {
		switch {
		case used[k], strings.HasPrefix(k, "reason."), strings.HasPrefix(k, "hint."), strings.HasPrefix(k, "logs.period_"), strings.HasPrefix(k, "notify.kind_"), strings.HasPrefix(k, "conn.err_"), k == "backup.err_file", strings.HasPrefix(k, "security.err_"), strings.HasPrefix(k, "flash.user_"), k == "flash.last_admin",
			k == "login.error", k == "login.code_error", k == "login.blocked", strings.HasPrefix(k, "setup."), k == "account.wrong_current", k == "test.body":
		default:
			t.Errorf("key %q is in the catalog but not used", k)
		}
	}
}

func TestUIMicrosoftFailuresAreLogged(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()
	e.mail.checkErr = &graph.Error{Status: 401, Code: "invalid_client", Message: "AADSTS7000215: Invalid client secret provided."}
	r := e.post("/microsoft/check", url.Values{"csrf": {csrf}})
	if !strings.Contains(r.body, "5 minutes") {
		t.Error("a failed check must tell the user to wait a few minutes")
	}
	e.mail.sendErr = &graph.Error{Status: 403, Code: "ErrorAccessDenied", Message: "Access is denied."}
	r = e.post("/test", url.Values{"csrf": {csrf}, "from": {"printer@example.com"}, "to": {"boss@example.org"}})
	if !strings.Contains(r.body, "5 minutes") {
		t.Error("a failed test mail must tell the user to wait a few minutes")
	}
	if !strings.Contains(e.get("/test").body, "5 minutes") {
		t.Error("the test page must mention the waiting time up front")
	}
	evs, err := e.st.ListEvents(store.EventFilter{}, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	var reasons []string
	for _, ev := range evs {
		if ev.Client != "web UI" {
			t.Errorf("unexpected client %q", ev.Client)
		}
		reasons = append(reasons, string(ev.Reason)+"|"+ev.Detail)
	}
	joined := strings.Join(reasons, "\n")
	if len(evs) != 2 || !strings.Contains(joined, "graph_auth_failed|connection check") || !strings.Contains(joined, "graph_forbidden|test mail") {
		t.Errorf("events = %q", reasons)
	}
}

func TestHelpIsSelfContained(t *testing.T) {
	for _, lang := range i18n.Languages {
		e := newEnv(t, func(c *config.Config) { c.Lang = lang })
		e.login()
		body := e.get("/help").body
		if strings.Contains(body, ".md") || strings.Contains(body, "docs/") {
			t.Errorf("[%s] the help page must not point to files the user cannot open from the UI", lang)
		}
		for _, want := range []string{`id="entra"`, `id="scope"`, `id="wait"`, `id="testmail"`, `id="problems"`, "New-ManagementRoleAssignment", "/static/Setup-EntraApp.ps1"} {
			if !strings.Contains(body, want) {
				t.Errorf("[%s] help page lacks %q", lang, want)
			}
		}
		if r := e.get("/static/Setup-EntraApp.ps1"); r.status != 200 || !strings.Contains(r.body, "New-MgApplication") {
			t.Errorf("[%s] the helper script must be downloadable", lang)
		}
	}
}

// The downloadable copy must not drift from the script in scripts/.
func TestEmbeddedScriptMatchesRepoScript(t *testing.T) {
	a, err1 := os.ReadFile("static/Setup-EntraApp.ps1")
	b, err2 := os.ReadFile("../../scripts/Setup-EntraApp.ps1")
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	if !bytes.Equal(a, b) {
		t.Error("internal/web/static/Setup-EntraApp.ps1 differs from scripts/Setup-EntraApp.ps1: copy it over")
	}
}
