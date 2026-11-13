// Package web implements the administration UI: sign-in, clients, the
// Microsoft 365 connection, logs and help, in English and Dutch.
package web

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/kgooris/office-smtprelay/internal/config"
	"github.com/kgooris/office-smtprelay/internal/i18n"
	"github.com/kgooris/office-smtprelay/internal/notify"
	"github.com/kgooris/office-smtprelay/internal/ratelimit"
	"github.com/kgooris/office-smtprelay/internal/relay"
	"github.com/kgooris/office-smtprelay/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

// Mailer sends the test message and validates the Microsoft connection.
type Mailer interface {
	relay.Sender
	CheckCredentials(ctx context.Context) error
}

// Deps are the collaborators of the UI.
type Deps struct {
	Store   *store.Store
	Mailer  Mailer
	Config  config.Config
	Version string
	Logger  *log.Logger
	Relay   RelayControl // optional: lets the UI show and lift temporary blocks
	// Notifier sends the administrator alerts. When nil the UI creates its own.
	Notifier Notifier
	// Conn manages the certificate and extra listeners of the running relay.
	Conn Connection
}

// Server is the web UI.
type Server struct {
	d     Deps
	cat   *i18n.Catalog
	pages map[string]*template.Template
	sess  *sessions
	tfa   map[string]*pending2FA // sign-ins that passed the password and wait for the code
	tfaMu sync.Mutex
	login *ratelimit.FailLimiter
	now   func() time.Time

	setupMu    sync.Mutex
	setupToken string // required on first start unless SMTPRELAY_ADMIN_PASSWORD was given
}

// SetupToken returns the one-time token needed on the first-run page (empty
// when the admin password already exists).
func (s *Server) SetupToken() string {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	return s.setupToken
}

// page files; every page is parsed together with the layout.
var pageFiles = map[string][]string{
	"login":          {"login.html"},
	"login2fa":       {"login2fa.html"},
	"security":       {"security.html"},
	"setup":          {"setup.html"},
	"dashboard":      {"dashboard.html"},
	"clients":        {"clients.html"},
	"client_created": {"client_created.html"},
	"client_edit":    {"client_edit.html"},
	"client_new":     {"client_new.html"},
	"settings":       {"settings.html"},
	"notifications":  {"notifications.html"},
	"conn":           {"conn.html"},
	"backup":         {"backup.html"},
	"devices":        {"devices.html"},
	"logs":           {"logs.html"},
	"microsoft":      {"microsoft.html"},
	"test":           {"test.html"},
	"account":        {"account.html"},
	"help":           {"help.html", "help_en.html", "help_nl.html"},
}

// New builds the UI. If no admin password exists yet it either seeds it from
// SMTPRELAY_ADMIN_PASSWORD or creates a one-time setup token (logged once).
func New(d Deps) (*Server, error) {
	if d.Logger == nil {
		d.Logger = log.Default()
	}
	if d.Conn == nil {
		d.Conn = noConn{}
	}
	if d.Notifier == nil {
		n := notify.New(d.Store, d.Mailer, d.Config.Lang, d.Logger)
		n.LangFn = func() string { return d.Store.EffectiveLang(d.Config.Lang) }
		d.Notifier = n
	}
	cat, err := i18n.Load()
	if err != nil {
		return nil, err
	}
	s := &Server{d: d, cat: cat, pages: map[string]*template.Template{}, sess: newSessions(), tfa: map[string]*pending2FA{},
		login: ratelimit.New(5, 10*time.Minute), now: time.Now}
	s.sess.idle = func() time.Duration { return d.Store.IdleTimeout(defaultIdle) }

	funcs := template.FuncMap{
		"t":       func(key string, _ ...any) string { return key }, // replaced per request
		"fmtTime": fmtTime,
		"badge":   badge,
		"upper":   strings.ToUpper,
	}
	for name, files := range pageFiles {
		paths := []string{"templates/layout.html"}
		for _, f := range files {
			paths = append(paths, "templates/"+f)
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(assets, paths...)
		if err != nil {
			return nil, fmt.Errorf("web: template %s: %w", name, err)
		}
		s.pages[name] = t
	}

	if !d.Store.HasAdminPassword() {
		if d.Config.AdminPassword != "" {
			if err := d.Store.SetAdminPassword(d.Config.AdminPassword); err != nil {
				return nil, err
			}
			d.Logger.Printf("web UI: admin password set from SMTPRELAY_ADMIN_PASSWORD (remove it from the environment after the first start)")
		} else {
			s.setupToken = randToken(9)
			d.Logger.Printf("web UI: first start. Open the UI and enter this one-time setup token to choose the admin password: %s", s.setupToken)
		}
	}
	return s, nil
}

// Handler returns the HTTP handler for the whole UI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /static/", http.HandlerFunc(s.static))

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginPost)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupPost)
	mux.HandleFunc("POST /lang", s.langPost)
	mux.HandleFunc("POST /logout", s.auth(s.logout))
	mux.HandleFunc("GET /login/2fa", s.login2FAPage)
	mux.HandleFunc("POST /login/2fa", s.login2FAPost)
	mux.HandleFunc("GET /security", s.auth(s.securityPage))
	mux.HandleFunc("POST /security/user/add", s.auth(s.secUserAdd))
	mux.HandleFunc("POST /security/user/role", s.auth(s.secUserRole))
	mux.HandleFunc("POST /security/user/reset", s.auth(s.secUserReset))
	mux.HandleFunc("POST /security/user/2fa-off", s.auth(s.secUser2FAOff))
	mux.HandleFunc("POST /security/user/delete", s.auth(s.secUserDelete))
	mux.HandleFunc("POST /security/access", s.auth(s.secAccess))
	mux.HandleFunc("POST /account/totp/begin", s.auth(s.accountTOTPBegin))
	mux.HandleFunc("POST /account/totp/confirm", s.auth(s.accountTOTPConfirm))
	mux.HandleFunc("POST /account/totp/disable", s.auth(s.accountTOTPDisable))

	mux.HandleFunc("GET /{$}", s.auth(s.dashboard))
	mux.HandleFunc("GET /clients", s.auth(s.clientsPage))
	mux.HandleFunc("POST /clients/add", s.auth(s.clientAdd))
	mux.HandleFunc("GET /settings", s.auth(s.settingsPage))
	mux.HandleFunc("GET /backup", s.auth(s.backupPage))
	mux.HandleFunc("POST /backup/export", s.auth(s.backupExport))
	mux.HandleFunc("POST /backup/import", s.auth(s.backupImport))
	mux.HandleFunc("GET /connection", s.auth(s.connPage))
	mux.HandleFunc("POST /connection/tlsmin", s.auth(s.connTLSMin))
	mux.HandleFunc("POST /connection/ports", s.auth(s.connPorts))
	mux.HandleFunc("POST /connection/cert", s.auth(s.connCert))
	mux.HandleFunc("POST /connection/regenerate", s.auth(s.connRegenerate))
	mux.HandleFunc("GET /notifications", s.auth(s.notificationsPage))
	mux.HandleFunc("POST /notifications", s.auth(s.notificationsSave))
	mux.HandleFunc("POST /notifications/test", s.auth(s.notificationsTest))
	mux.HandleFunc("GET /clients/new", s.auth(s.clientNewPage))
	mux.HandleFunc("GET /clients/edit", s.auth(s.clientEditPage))
	mux.HandleFunc("POST /clients/edit", s.auth(s.clientEditSave))
	mux.HandleFunc("POST /clients/unblock", s.auth(s.clientUnblock))
	mux.HandleFunc("POST /pause", s.auth(s.pauseToggle))
	mux.HandleFunc("POST /settings/domains", s.auth(s.domainsSave))
	mux.HandleFunc("POST /settings/general", s.auth(s.generalSave))
	mux.HandleFunc("POST /clients/toggle", s.auth(s.clientToggle))
	mux.HandleFunc("POST /clients/password", s.auth(s.clientPassword))
	mux.HandleFunc("POST /clients/ip", s.auth(s.clientIP))
	mux.HandleFunc("POST /clients/delete", s.auth(s.clientDelete))
	mux.HandleFunc("GET /devices", s.auth(s.devicesPage))
	mux.HandleFunc("GET /logs", s.auth(s.logsPage))
	mux.HandleFunc("GET /logs.csv", s.auth(s.logsCSV))
	mux.HandleFunc("GET /microsoft", s.auth(s.microsoftPage))
	mux.HandleFunc("POST /microsoft/save", s.auth(s.microsoftSave))
	mux.HandleFunc("POST /microsoft/check", s.auth(s.microsoftCheck))
	mux.HandleFunc("GET /test", s.auth(s.testPage))
	mux.HandleFunc("POST /test", s.auth(s.testSend))
	mux.HandleFunc("GET /help", s.auth(s.helpPage))
	mux.HandleFunc("GET /account", s.auth(s.accountPage))
	mux.HandleFunc("POST /account", s.auth(s.accountPost))

	return s.secureHeaders(s.ipGate(mux))
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	if err := s.d.Store.Ping(); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintln(w, "ok")
}

func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	http.FileServerFS(assets).ServeHTTP(w, r)
}

// ---- middleware ------------------------------------------------------------

func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		if s.secure(r) {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}

type authed func(w http.ResponseWriter, r *http.Request, sd *session, sid string)

// auth requires a valid session (and a valid CSRF token on POST).
func (s *Server) auth(h authed) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.d.Store.HasAdminPassword() {
			http.Redirect(w, r, "/setup", http.StatusSeeOther)
			return
		}
		var sid string
		if c, err := r.Cookie(cookieSession); err == nil {
			sid = c.Value
		}
		sd, ok := s.sess.get(sid)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost && !sd.admin() && !readOnlyMay(r.URL.Path) {
			http.Error(w, "this account is read-only", http.StatusForbidden)
			return
		}
		if r.Method == http.MethodPost && !tokensEqual(sd.csrf, r.PostFormValue("csrf")) {
			http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
			return
		}
		h(w, r, sd, sid)
	}
}

// ---- request helpers -------------------------------------------------------

func (s *Server) secure(r *http.Request) bool {
	return r.TLS != nil || (s.d.Config.TrustProxy && strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"))
}

// remoteIP returns the client IP, honouring X-Forwarded-For only when a
// reverse proxy is trusted.
func (s *Server) remoteIP(r *http.Request) netip.Addr {
	if s.d.Config.TrustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if a, err := netip.ParseAddr(first); err == nil {
				return a.Unmap()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

func (s *Server) lang(r *http.Request) string {
	if c, err := r.Cookie(cookieLang); err == nil && i18n.Supported(c.Value) {
		return c.Value
	}
	if l := s.d.Store.EffectiveLang(s.d.Config.Lang); i18n.Supported(l) {
		return l
	}
	return i18n.Languages[0]
}

func (s *Server) tr(r *http.Request, key string, args ...any) string {
	return s.cat.T(s.lang(r), key, args...)
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: value, Path: "/", MaxAge: maxAge,
		HttpOnly: true, Secure: s.secure(r), SameSite: http.SameSiteStrictMode,
	})
}

// preToken returns the CSRF token for forms shown before sign-in.
func (s *Server) preToken(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(cookiePre); err == nil && len(c.Value) >= 20 {
		return c.Value
	}
	tok := randToken(24)
	s.setCookie(w, r, cookiePre, tok, 3600)
	return tok
}

func (s *Server) checkPre(r *http.Request) bool {
	c, err := r.Cookie(cookiePre)
	return err == nil && tokensEqual(c.Value, r.PostFormValue("csrf"))
}

// hostOnly strips the port from a Host header value.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return strings.Trim(hostport, "[]")
}

// ---- rendering -------------------------------------------------------------

type view struct {
	Lang      string
	Languages []string
	Version   string
	TitleKey  string
	Active    string
	Path      string
	CSRF      string
	UserName  string // the signed-in user, for the menu
	IsAdmin   bool
	Nav       bool
	Flash     string
	FlashKind string // ok | err | warn
	Data      any
}

// flashFromQuery turns ?ok=key or ?err=key into a flash message. Only keys
// that exist in the catalog are accepted, so the URL cannot inject text.
func (s *Server) flashFromQuery(r *http.Request, v *view) {
	for _, kind := range []string{"ok", "err"} {
		if k := r.URL.Query().Get(kind); k != "" && s.cat.Has("en", "flash."+k) {
			v.Flash, v.FlashKind = s.tr(r, "flash."+k), kind
			return
		}
	}
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, v view) {
	tpl, ok := s.pages[name]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	lang := s.lang(r)
	t, err := tpl.Clone()
	if err != nil {
		s.fail(w, err)
		return
	}
	t.Funcs(template.FuncMap{"t": func(key string, args ...any) string { return s.cat.T(lang, key, args...) }})
	v.Lang, v.Languages, v.Version, v.Path = lang, i18n.Languages, s.d.Version, r.URL.Path
	if v.Nav {
		if c, err := r.Cookie(cookieSession); err == nil {
			if sd, ok := s.sess.peek(c.Value); ok {
				v.UserName, v.IsAdmin = sd.username, sd.admin()
			}
		}
	}
	if v.TitleKey == "" {
		v.TitleKey = "title." + name
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "layout", v); err != nil {
		s.fail(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	s.d.Logger.Printf("web UI error: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// ---- template helpers ------------------------------------------------------

func fmtTime(t time.Time) string {
	if t.IsZero() {
		return "–"
	}
	return t.Local().Format("2006-01-02 15:04")
}

// badge maps a log reason to a colour class.
func badge(r relay.Reason) string {
	switch r {
	case relay.ReasonSent:
		return "ok"
	case relay.ReasonAuthBlocked, relay.ReasonGraphAuth, relay.ReasonGraphForbidden,
		relay.ReasonGraphNotFound, relay.ReasonGraphRejected, relay.ReasonInternal:
		return "err"
	case relay.ReasonPolicyTest:
		return "off"
	}
	return "warn"
}

// AllReasons lists every log reason the UI must be able to explain.
var AllReasons = []relay.Reason{
	relay.ReasonSent, relay.ReasonIPNotAllowed, relay.ReasonAuthRequired, relay.ReasonUnknownUser,
	relay.ReasonBadPassword, relay.ReasonWrongIP, relay.ReasonAuthBlocked, relay.ReasonNoSender,
	relay.ReasonNoRecipients, relay.ReasonTooLarge, relay.ReasonGraphAuth, relay.ReasonGraphForbidden,
	relay.ReasonGraphNotFound, relay.ReasonGraphRejected, relay.ReasonGraphTemporary,
	relay.ReasonInternal, relay.ReasonMessageReadFail,
	relay.ReasonSenderNotAllowed, relay.ReasonRcptNotAllowed, relay.ReasonLimitExceeded,
	relay.ReasonClientBlocked, relay.ReasonPaused, relay.ReasonPolicyTest, relay.ReasonAttachment, relay.ReasonConnLimit, relay.ReasonTLSRequired,
}
