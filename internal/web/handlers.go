package web

import (
	"context"
	"crypto/rand"
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/i18n"
	"github.com/kgooris/office-smtprelay/internal/policy"
	"github.com/kgooris/office-smtprelay/internal/relay"
	"github.com/kgooris/office-smtprelay/internal/store"
)

// ---- sign-in, first-run setup, language -----------------------------------

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.d.Store.HasAdminPassword() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if c, err := r.Cookie(cookieSession); err == nil {
		if _, ok := s.sess.get(c.Value); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
	}
	v := view{CSRF: s.preToken(w, r)}
	s.flashFromQuery(r, &v)
	s.render(w, r, http.StatusOK, "login", v)
}

func (s *Server) loginPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkPre(r) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}
	if !s.d.Store.HasAdminPassword() {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	ip, now := s.remoteIP(r), s.now()
	show := func(status int, key string) {
		s.render(w, r, status, "login", view{CSRF: s.preToken(w, r), Flash: s.tr(r, key), FlashKind: "err"})
	}
	if s.login.Blocked(ip, now) {
		show(http.StatusTooManyRequests, "login.blocked")
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	if username == "" {
		username = "admin" // the login form of older versions had no username field
	}
	u, err := s.d.Store.AuthUser(username, r.PostFormValue("password"))
	if err != nil {
		s.login.Fail(ip, now)
		s.d.Logger.Printf("web UI: failed sign-in from %s", ip)
		show(http.StatusUnauthorized, "login.error")
		return
	}
	if u.TOTPEnabled { // password is right; the second step decides
		s.begin2FA(w, r, u)
		return
	}
	s.login.Reset(ip)
	s.startSession(w, r, u)
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u store.User) {
	id, _ := s.sess.create(u)
	s.d.Store.TouchLogin(u.ID)
	s.setCookie(w, r, cookieSession, id, 0)
	s.setCookie(w, r, cookiePre, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, _ *session, sid string) {
	s.sess.destroy(sid)
	s.setCookie(w, r, cookieSession, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

type setupData struct{ NeedToken bool }

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	if s.d.Store.HasAdminPassword() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "setup", view{CSRF: s.preToken(w, r), Data: setupData{NeedToken: s.SetupToken() != ""}})
}

func (s *Server) setupPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkPre(r) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.d.Store.HasAdminPassword() {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip, now := s.remoteIP(r), s.now()
	show := func(status int, key string) {
		s.render(w, r, status, "setup", view{CSRF: s.preToken(w, r), Flash: s.tr(r, key), FlashKind: "err",
			Data: setupData{NeedToken: s.setupToken != ""}})
	}
	if s.login.Blocked(ip, now) {
		show(http.StatusTooManyRequests, "login.blocked")
		return
	}
	if s.setupToken != "" && !tokensEqual(s.setupToken, strings.TrimSpace(r.PostFormValue("token"))) {
		s.login.Fail(ip, now)
		show(http.StatusUnauthorized, "setup.bad_token")
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("confirm") {
		show(http.StatusBadRequest, "setup.mismatch")
		return
	}
	if err := s.d.Store.SetAdminPassword(pw); err != nil {
		show(http.StatusBadRequest, "setup.too_short")
		return
	}
	s.setupToken = ""
	s.d.Logger.Printf("web UI: admin password set from %s", ip)
	admin, err := s.d.Store.UserByName("admin")
	if err != nil {
		s.fail(w, err)
		return
	}
	s.startSession(w, r, admin)
}

func (s *Server) langPost(w http.ResponseWriter, r *http.Request) {
	if lang := r.PostFormValue("lang"); i18n.Supported(lang) {
		http.SetCookie(w, &http.Cookie{Name: cookieLang, Value: lang, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, Secure: s.secure(r), SameSite: http.SameSiteLaxMode})
	}
	next := r.PostFormValue("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		next = "/"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

// ---- dashboard -------------------------------------------------------------

type clientRow struct {
	store.Client
	LastSent time.Time
}

type dashboardData struct {
	GraphConfigured bool
	SecretState     string // none | ok | soon | expired
	SecretDays      int
	HasClients      bool
	Clients         []clientRow
	Sent24h         int
	Failures24h     int
	Unknown7d       int
	Recent          []store.StoredEvent
	Paused          bool
	TestHits7d      int
	Blocked         []string
}

const secretWarnDays = 30

// secretState classifies the secret expiry relative to now.
func secretState(configured bool, exp time.Time, hasExp bool, now time.Time) (string, int) {
	if !configured {
		return "none", 0
	}
	if !hasExp {
		return "ok", 0
	}
	days := int(exp.Sub(now).Hours() / 24)
	switch {
	case !exp.After(now):
		return "expired", days
	case days <= secretWarnDays:
		return "soon", days
	}
	return "ok", days
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	now := s.now()
	st := s.d.Store
	_, configured, _ := st.GraphCredentials()
	exp, hasExp := st.SecretExpires()
	d := dashboardData{GraphConfigured: configured}
	d.SecretState, d.SecretDays = secretState(configured, exp, hasExp, now)

	clients, _ := st.ListClients()
	lastSent, _ := st.LastSentByClient()
	for _, c := range clients {
		d.Clients = append(d.Clients, clientRow{Client: c, LastSent: lastSent[c.Name]})
	}
	d.HasClients = len(clients) > 0
	since := now.Add(-24 * time.Hour)
	d.Sent24h, _ = st.CountEvents(store.EventFilter{Reason: relay.ReasonSent, Since: since})
	d.Failures24h, _ = st.SumFailures(since)
	unknown, _ := st.UnknownDevices(now.Add(-7*24*time.Hour), 500)
	d.Unknown7d = len(unknown)
	d.Recent, _ = st.ListEvents(store.EventFilter{OnlyFail: true}, 5, 0)
	d.Paused = st.Paused()
	d.TestHits7d, _ = st.CountEvents(store.EventFilter{Reason: relay.ReasonPolicyTest, Since: now.Add(-7 * 24 * time.Hour)})
	if s.d.Relay != nil {
		for name := range s.d.Relay.BlockedClients() {
			d.Blocked = append(d.Blocked, name)
		}
	}

	v := view{Nav: true, Active: "dashboard", CSRF: sd.csrf, Data: d}
	s.flashFromQuery(r, &v)
	s.render(w, r, http.StatusOK, "dashboard", v)
}

// ---- clients ---------------------------------------------------------------

type clientsData struct {
	Clients []store.Client
}

// newClientData fills the "add a device" form.
type newClientData struct {
	FormName, FormIP, FormUser string
	FormPreset, FormMailbox    string
}

func (s *Server) clientsView(r *http.Request, sd *session, d clientsData) view {
	d.Clients, _ = s.d.Store.ListClients()
	v := view{Nav: true, Active: "clients", CSRF: sd.csrf, Data: d}
	s.flashFromQuery(r, &v)
	return v
}

func (s *Server) clientsPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if ip := strings.TrimSpace(r.URL.Query().Get("ip")); ip != "" { // old link from the unknown devices page
		http.Redirect(w, r, "/clients/new?ip="+url.QueryEscape(ip), http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "clients", s.clientsView(r, sd, clientsData{}))
}

func (s *Server) clientNewPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	d := newClientData{FormIP: strings.TrimSpace(r.URL.Query().Get("ip"))}
	s.render(w, r, http.StatusOK, "client_new", view{Nav: true, Active: "clients", CSRF: sd.csrf, Data: d})
}

// clientErrKey returns the flash key suffix (flash.<suffix>) for a store error.
func (s *Server) clientErrKey(err error) string {
	switch {
	case errors.Is(err, store.ErrExists):
		return "client_exists"
	case errors.Is(err, store.ErrInvalid):
		return "client_invalid"
	case errors.Is(err, store.ErrNotFound):
		return "client_not_found"
	}
	s.d.Logger.Printf("web UI: %v", err)
	return "internal"
}

type createdData struct {
	Name, Host, Port, Username, Password, Addr string
	Reset                                      bool
}

func (s *Server) clientAdd(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	ip := strings.TrimSpace(r.PostFormValue("ip"))
	user := strings.TrimSpace(r.PostFormValue("username"))
	if user == "" {
		user = strings.ToLower(strings.ReplaceAll(name, " ", "-"))
	}
	pw, err := store.GeneratePassword(20)
	if err != nil {
		s.fail(w, err)
		return
	}
	preset, mailbox := r.PostFormValue("preset"), r.PostFormValue("mailbox")
	c, err := s.d.Store.AddClient(name, ip, user, pw)
	if err == nil && preset != "" && preset != policy.PresetBasic {
		pol := policy.FromPreset(preset, mailbox)
		if err = pol.Validate(); err == nil {
			err = s.d.Store.SetClientPolicy(c.Name, pol)
		}
		if err != nil {
			_ = s.d.Store.DeleteClient(c.Name) // do not leave a half-configured client behind
		}
	}
	if err != nil {
		v := view{Nav: true, Active: "clients", CSRF: sd.csrf,
			Data: newClientData{FormName: name, FormIP: ip, FormUser: r.PostFormValue("username"), FormPreset: preset, FormMailbox: mailbox}}
		v.Flash, v.FlashKind = s.tr(r, "flash."+s.clientErrKey(err)), "err"
		s.render(w, r, http.StatusBadRequest, "client_new", v)
		return
	}
	s.d.Logger.Printf("web UI: client %q added (%s)", c.Name, c.Addr)
	s.render(w, r, http.StatusOK, "client_created", view{Nav: true, Active: "clients", CSRF: sd.csrf,
		Data: createdData{Name: c.Name, Host: hostOnly(r.Host), Port: s.d.Config.PublicSMTPPort,
			Username: c.Username, Password: pw, Addr: c.Addr.String()}})
}

func (s *Server) clientToggle(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	enable := r.PostFormValue("enable") == "1"
	key := "ok=client_enabled"
	if !enable {
		key = "ok=client_disabled"
	}
	if err := s.d.Store.SetClientEnabled(r.PostFormValue("name"), enable); err != nil {
		key = "err=" + s.clientErrKey(err)
	}
	http.Redirect(w, r, backTo(r, key), http.StatusSeeOther)
}

func (s *Server) clientPassword(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	name := r.PostFormValue("name")
	pw, err := store.GeneratePassword(20)
	if err == nil {
		err = s.d.Store.SetClientPassword(name, pw)
	}
	if err != nil {
		http.Redirect(w, r, "/clients?err="+s.clientErrKey(err), http.StatusSeeOther)
		return
	}
	var cl store.Client
	list, _ := s.d.Store.ListClients()
	for _, c := range list {
		if strings.EqualFold(c.Name, name) {
			cl = c
		}
	}
	s.d.Logger.Printf("web UI: password of client %q reset", cl.Name)
	s.render(w, r, http.StatusOK, "client_created", view{Nav: true, Active: "clients", CSRF: sd.csrf,
		Data: createdData{Name: cl.Name, Host: hostOnly(r.Host), Port: s.d.Config.PublicSMTPPort,
			Username: cl.Username, Password: pw, Addr: cl.Addr.String(), Reset: true}})
}

func (s *Server) clientIP(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	key := "ok=client_ip_changed"
	if err := s.d.Store.SetClientAddr(r.PostFormValue("name"), r.PostFormValue("ip")); err != nil {
		key = "err=" + s.clientErrKey(err)
	}
	http.Redirect(w, r, backTo(r, key), http.StatusSeeOther)
}

func (s *Server) clientDelete(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	key := "ok=client_deleted"
	if err := s.d.Store.DeleteClient(r.PostFormValue("name")); err != nil {
		key = "err=" + s.clientErrKey(err)
	}
	http.Redirect(w, r, "/clients?"+key, http.StatusSeeOther)
}

// ---- unknown devices -------------------------------------------------------

type devicesData struct{ Devices []store.UnknownDevice }

func (s *Server) devicesPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	devs, _ := s.d.Store.UnknownDevices(s.now().Add(-30*24*time.Hour), 200)
	s.render(w, r, http.StatusOK, "devices", view{Nav: true, Active: "devices", CSRF: sd.csrf, Data: devicesData{Devices: devs}})
}

// ---- logs ------------------------------------------------------------------

const logPageSize = 50

type periodOption struct{ Value, Label string }

var periods = []periodOption{
	{"1h", "logs.period_1h"}, {"24h", "logs.period_24h"}, {"7d", "logs.period_7d"}, {"30d", "logs.period_30d"},
}

var periodDur = map[string]time.Duration{
	"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

type logsData struct {
	Events                     []store.StoredEvent
	Status, Period, Client, IP string
	Periods                    []periodOption
	ClientNames                []string
	Prev, Next                 string
	RetentionDays              int
}

func (s *Server) logFilter(r *http.Request) (store.EventFilter, logsData) {
	q := r.URL.Query()
	d := logsData{Status: q.Get("status"), Period: q.Get("period"), Client: clip(q.Get("client")), IP: clip(strings.TrimSpace(q.Get("ip"))),
		Periods: periods, RetentionDays: s.d.Store.EffectiveRetentionDays(s.d.Config.EventRetentionDays)}
	if d.Status != "failed" && d.Status != "sent" && d.Status != "test" {
		d.Status = ""
	}
	if _, ok := periodDur[d.Period]; !ok {
		d.Period = "24h"
	}
	f := store.EventFilter{Client: d.Client, RemoteIP: d.IP, Since: s.now().Add(-periodDur[d.Period])}
	switch d.Status {
	case "failed":
		f.OnlyFail = true
	case "test":
		f.Reason = relay.ReasonPolicyTest
	case "sent":
		f.Reason = relay.ReasonSent
	}
	return f, d
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func (s *Server) logsPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	f, d := s.logFilter(r)
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 0 {
		page = 0
	}
	evs, err := s.d.Store.ListEvents(f, logPageSize+1, page*logPageSize)
	if err != nil {
		s.fail(w, err)
		return
	}
	link := func(p int) string {
		v := url.Values{"status": {d.Status}, "period": {d.Period}, "client": {d.Client}, "ip": {d.IP}, "page": {strconv.Itoa(p)}}
		return "/logs?" + v.Encode()
	}
	if len(evs) > logPageSize {
		evs, d.Next = evs[:logPageSize], link(page+1)
	}
	if page > 0 {
		d.Prev = link(page - 1)
	}
	d.Events = evs
	clients, _ := s.d.Store.ListClients()
	for _, c := range clients {
		d.ClientNames = append(d.ClientNames, c.Name)
	}
	sort.Strings(d.ClientNames)
	s.render(w, r, http.StatusOK, "logs", view{Nav: true, Active: "logs", CSRF: sd.csrf, Data: d})
}

// csvSafe prevents spreadsheet formula injection from log fields.
func csvSafe(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

func (s *Server) logsCSV(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	f, _ := s.logFilter(r)
	evs, err := s.d.Store.ListEvents(f, 5000, 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="office-smtprelay-log.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"first_at", "last_at", "count", "ip", "client", "result", "smtp_code", "sender", "recipients", "bytes", "detail"})
	for _, e := range evs {
		_ = cw.Write([]string{e.FirstAt.UTC().Format(time.RFC3339), e.LastAt.UTC().Format(time.RFC3339), strconv.Itoa(e.Count),
			e.RemoteIP, csvSafe(e.Client), string(e.Reason), strconv.Itoa(e.SMTPCode), csvSafe(e.Sender),
			strconv.Itoa(e.Recipients), strconv.Itoa(e.Bytes), csvSafe(e.Detail)})
	}
	cw.Flush()
}

// ---- Microsoft 365 connection ---------------------------------------------

type microsoftData struct {
	Configured         bool
	TenantID, ClientID string
	SecretState        string
	SecretDays         int
	HasExpiry          bool
	ExpiresText        string
	ExpiresInput       string
}

func (s *Server) microsoftView(r *http.Request, sd *session) view {
	creds, configured, _ := s.d.Store.GraphCredentials()
	exp, hasExp := s.d.Store.SecretExpires()
	d := microsoftData{Configured: configured, TenantID: creds.TenantID, ClientID: creds.ClientID, HasExpiry: hasExp}
	d.SecretState, d.SecretDays = secretState(configured, exp, hasExp, s.now())
	if hasExp {
		d.ExpiresText, d.ExpiresInput = exp.Format("2006-01-02"), exp.Format("2006-01-02")
	}
	v := view{Nav: true, Active: "microsoft", CSRF: sd.csrf, Data: d}
	s.flashFromQuery(r, &v)
	return v
}

func (s *Server) microsoftPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	s.render(w, r, http.StatusOK, "microsoft", s.microsoftView(r, sd))
}

func (s *Server) microsoftSave(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	tenant := strings.TrimSpace(r.PostFormValue("tenant"))
	client := strings.TrimSpace(r.PostFormValue("client"))
	secret := strings.TrimSpace(r.PostFormValue("secret"))
	var exp time.Time
	if e := strings.TrimSpace(r.PostFormValue("expires")); e != "" {
		var err error
		if exp, err = time.Parse("2006-01-02", e); err != nil {
			http.Redirect(w, r, "/microsoft?err=ms_bad_date", http.StatusSeeOther)
			return
		}
	}
	if secret == "" { // keep the stored secret
		if existing, ok, _ := s.d.Store.GraphCredentials(); ok {
			secret = existing.ClientSecret
		}
	}
	if tenant == "" || client == "" || secret == "" || len(tenant) > 200 || len(client) > 200 || len(secret) > 500 ||
		strings.ContainsAny(tenant+client, " \t\r\n/") {
		http.Redirect(w, r, "/microsoft?err=ms_invalid", http.StatusSeeOther)
		return
	}
	if err := s.d.Store.SetGraphCredentials(graph.Credentials{TenantID: tenant, ClientID: client, ClientSecret: secret}, exp); err != nil {
		s.fail(w, err)
		return
	}
	s.d.Logger.Printf("web UI: Microsoft 365 connection saved")
	http.Redirect(w, r, "/microsoft?ok=ms_saved", http.StatusSeeOther)
}

func (s *Server) microsoftCheck(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	v := s.microsoftView(r, sd)
	if err := s.d.Mailer.CheckCredentials(ctx); err != nil {
		s.recordMSFailure(r, "", "connection check", err)
		v.Flash, v.FlashKind = s.tr(r, "ms.check_failed", err.Error())+" "+s.tr(r, "ms.wait_hint"), "err"
	} else {
		v.Flash, v.FlashKind = s.tr(r, "ms.check_ok"), "ok"
	}
	s.render(w, r, http.StatusOK, "microsoft", v)
}

// ---- test mail -------------------------------------------------------------

type testData struct{ From, To string }

func (s *Server) testPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	v := view{Nav: true, Active: "test", CSRF: sd.csrf, Data: testData{}}
	s.flashFromQuery(r, &v)
	s.render(w, r, http.StatusOK, "test", v)
}

func plainAddress(s string) (string, bool) {
	a, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil || a.Address == "" || strings.ContainsAny(a.Address, "\r\n") || a.Name != "" {
		return "", false
	}
	return strings.ToLower(a.Address), true
}

func (s *Server) testSend(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	from, ok1 := plainAddress(r.PostFormValue("from"))
	to, ok2 := plainAddress(r.PostFormValue("to"))
	v := view{Nav: true, Active: "test", CSRF: sd.csrf, Data: testData{From: r.PostFormValue("from"), To: r.PostFormValue("to")}}
	if !ok1 || !ok2 {
		v.Flash, v.FlashKind = s.tr(r, "test.bad_address"), "err"
		s.render(w, r, http.StatusBadRequest, "test", v)
		return
	}
	id := make([]byte, 12)
	_, _ = rand.Read(id)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: office-smtprelay test\r\nDate: %s\r\nMessage-ID: <%x@office-smtprelay>\r\n"+
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		from, to, s.now().Format(time.RFC1123Z), id, s.tr(r, "test.body"))
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	if err := s.d.Mailer.SendMIME(ctx, from, []byte(msg)); err != nil {
		s.recordMSFailure(r, from, "test mail", err)
		v.Flash, v.FlashKind = s.tr(r, "test.failed", err.Error())+" "+s.tr(r, "ms.wait_hint"), "err"
		s.render(w, r, http.StatusOK, "test", v)
		return
	}
	v.Flash, v.FlashKind = s.tr(r, "test.sent", to), "ok"
	s.render(w, r, http.StatusOK, "test", v)
}

// ---- help, account ---------------------------------------------------------

type helpData struct{ Host, Port string }

func (s *Server) helpPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	s.render(w, r, http.StatusOK, "help", view{Nav: true, Active: "help", CSRF: sd.csrf,
		Data: helpData{Host: hostOnly(r.Host), Port: s.d.Config.PublicSMTPPort}})
}

// recordMSFailure writes a failure of a UI-triggered Microsoft call (test mail,
// connection check) to the event log, so it is visible on the Logs page like
// failures of real mail. Client is "web UI" to tell them apart.
func (s *Server) recordMSFailure(r *http.Request, sender, what string, err error) {
	detail := what + ": " + err.Error()
	if len(detail) > 400 {
		detail = detail[:400] + "…"
	}
	s.d.Store.Record(relay.Event{
		RemoteIP: s.remoteIP(r),
		Client:   "web UI",
		Reason:   relay.ClassifySendError(err),
		Sender:   sender,
		Detail:   detail,
	})
}
