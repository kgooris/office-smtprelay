package web

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/kgooris/office-smtprelay/internal/store"
	"github.com/kgooris/office-smtprelay/internal/totp"
)

// ---- second step of the sign-in ---------------------------------------------------

const (
	cookieTFA      = "tfa"
	tfaValidFor    = 5 * time.Minute
	tfaMaxAttempts = 5
)

// pending2FA is a sign-in that passed the password and waits for the code.
type pending2FA struct {
	userID   int64
	until    time.Time
	attempts int
}

func (s *Server) begin2FA(w http.ResponseWriter, r *http.Request, u store.User) {
	tok := randToken(24)
	s.tfaMu.Lock()
	for k, p := range s.tfa { // forget old ones
		if s.now().After(p.until) {
			delete(s.tfa, k)
		}
	}
	s.tfa[tok] = &pending2FA{userID: u.ID, until: s.now().Add(tfaValidFor)}
	s.tfaMu.Unlock()
	s.setCookie(w, r, cookieTFA, tok, int(tfaValidFor.Seconds()))
	http.Redirect(w, r, "/login/2fa", http.StatusSeeOther)
}

func (s *Server) pendingFor(r *http.Request) (string, *pending2FA) {
	c, err := r.Cookie(cookieTFA)
	if err != nil {
		return "", nil
	}
	s.tfaMu.Lock()
	defer s.tfaMu.Unlock()
	p, ok := s.tfa[c.Value]
	if !ok || s.now().After(p.until) {
		delete(s.tfa, c.Value)
		return "", nil
	}
	return c.Value, p
}

func (s *Server) login2FAPage(w http.ResponseWriter, r *http.Request) {
	if _, p := s.pendingFor(r); p == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login2fa", view{CSRF: s.preToken(w, r)})
}

func (s *Server) login2FAPost(w http.ResponseWriter, r *http.Request) {
	if !s.checkPre(r) {
		http.Error(w, "invalid or missing CSRF token", http.StatusForbidden)
		return
	}
	tok, p := s.pendingFor(r)
	if p == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	ip, now := s.remoteIP(r), s.now()
	show := func(status int, key string) {
		s.render(w, r, status, "login2fa", view{CSRF: s.preToken(w, r), Flash: s.tr(r, key), FlashKind: "err"})
	}
	if s.login.Blocked(ip, now) {
		show(http.StatusTooManyRequests, "login.blocked")
		return
	}
	if !s.d.Store.CheckSecondFactor(p.userID, r.PostFormValue("code"), now) {
		s.login.Fail(ip, now)
		s.tfaMu.Lock()
		p.attempts++
		if p.attempts >= tfaMaxAttempts {
			delete(s.tfa, tok) // start again with the password
		}
		s.tfaMu.Unlock()
		s.d.Logger.Printf("web UI: wrong verification code from %s", ip)
		show(http.StatusUnauthorized, "login.code_error")
		return
	}
	u, err := s.d.Store.UserByID(p.userID)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.tfaMu.Lock()
	delete(s.tfa, tok)
	s.tfaMu.Unlock()
	s.setCookie(w, r, cookieTFA, "", -1)
	s.login.Reset(ip)
	s.startSession(w, r, u)
}

// ---- read-only accounts and the network restriction --------------------------------

// readOnlyMay reports whether a read-only user may POST to path: only their own
// account (password, two-step verification) and signing out.
func readOnlyMay(path string) bool {
	return path == "/logout" || path == "/account" || strings.HasPrefix(path, "/account/")
}

// ipGate refuses visitors from addresses outside the allowed networks, when
// the administrator has set any. The loopback address is always allowed, so
// the container health check keeps working.
func (s *Server) ipGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		allow := s.d.Store.UIAllow()
		if len(allow) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		ip := s.remoteIP(r)
		if ip.IsLoopback() {
			next.ServeHTTP(w, r)
			return
		}
		for _, p := range allow {
			if p.Contains(ip) {
				next.ServeHTTP(w, r)
				return
			}
		}
		s.d.Logger.Printf("web UI: refused %s (not in the allowed networks)", ip)
		http.Error(w, "Access from this address is not allowed.", http.StatusForbidden)
	})
}

// ---- own account: password and two-step verification -------------------------------

type accountData struct {
	Username  string
	Role      string
	TOTP      bool
	CodesLeft int
	// during setup
	Secret, URI string
	// shown once after activation
	Recovery []string
}

func (s *Server) accountView(r *http.Request, sd *session) view {
	d := accountData{Username: sd.username, Role: sd.role}
	if u, err := s.d.Store.UserByID(sd.userID); err == nil {
		d.TOTP = u.TOTPEnabled
		d.CodesLeft = s.d.Store.RecoveryCodesLeft(u.ID)
	}
	v := view{Nav: true, Active: "account", CSRF: sd.csrf, Data: d}
	s.flashFromQuery(r, &v)
	return v
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	s.render(w, r, http.StatusOK, "account", s.accountView(r, sd))
}

func (s *Server) accountPost(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	v := s.accountView(r, sd)
	deny := func(status int, key string) {
		v.Flash, v.FlashKind = s.tr(r, key), "err"
		s.render(w, r, status, "account", v)
	}
	ip, now := s.remoteIP(r), s.now()
	if s.login.Blocked(ip, now) {
		deny(http.StatusTooManyRequests, "login.blocked")
		return
	}
	if !s.d.Store.CheckUserPassword(sd.userID, r.PostFormValue("current")) {
		s.login.Fail(ip, now)
		deny(http.StatusUnauthorized, "account.wrong_current")
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("confirm") {
		deny(http.StatusBadRequest, "setup.mismatch")
		return
	}
	if err := s.d.Store.SetUserPassword(sd.userID, pw); err != nil {
		deny(http.StatusBadRequest, "setup.too_short")
		return
	}
	s.d.Logger.Printf("web UI: password of %q changed from %s", sd.username, ip)
	s.sess.destroyUser(sd.userID) // sign this user out everywhere, then start a fresh session here
	u, err := s.d.Store.UserByID(sd.userID)
	if err != nil {
		s.fail(w, err)
		return
	}
	id, _ := s.sess.create(u)
	s.setCookie(w, r, cookieSession, id, 0)
	http.Redirect(w, r, "/account?ok=password_changed", http.StatusSeeOther)
}

func (s *Server) accountTOTPBegin(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	secret, err := s.d.Store.BeginTOTP(sd.userID)
	if err != nil {
		s.fail(w, err)
		return
	}
	v := s.accountView(r, sd)
	d := v.Data.(accountData)
	d.Secret, d.URI = secret, totp.URI("office-smtprelay", sd.username, secret)
	v.Data = d
	s.render(w, r, http.StatusOK, "account", v)
}

func (s *Server) accountTOTPConfirm(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	codes, err := s.d.Store.ConfirmTOTP(sd.userID, r.PostFormValue("code"), s.now())
	v := s.accountView(r, sd)
	if err != nil {
		if secret, ok := s.d.Store.PendingTOTP(sd.userID); ok { // keep the setup open
			d := v.Data.(accountData)
			d.Secret, d.URI = secret, totp.URI("office-smtprelay", sd.username, secret)
			v.Data = d
		}
		v.Flash, v.FlashKind = s.tr(r, "totp.bad_code"), "err"
		s.render(w, r, http.StatusBadRequest, "account", v)
		return
	}
	d := s.accountView(r, sd).Data.(accountData)
	d.Recovery = codes
	v.Data = d
	v.Flash, v.FlashKind = s.tr(r, "totp.enabled"), "ok"
	s.d.Logger.Printf("web UI: two-step verification enabled for %q", sd.username)
	s.render(w, r, http.StatusOK, "account", v)
}

func (s *Server) accountTOTPDisable(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	ip, now := s.remoteIP(r), s.now()
	if s.login.Blocked(ip, now) || !s.d.Store.CheckUserPassword(sd.userID, r.PostFormValue("current")) {
		s.login.Fail(ip, now)
		v := s.accountView(r, sd)
		v.Flash, v.FlashKind = s.tr(r, "account.wrong_current"), "err"
		s.render(w, r, http.StatusUnauthorized, "account", v)
		return
	}
	if err := s.d.Store.DisableTOTP(sd.userID); err != nil {
		s.fail(w, err)
		return
	}
	s.d.Logger.Printf("web UI: two-step verification disabled for %q", sd.username)
	http.Redirect(w, r, "/account?ok=totp_disabled", http.StatusSeeOther)
}

// ---- security page (administrators) -------------------------------------------------

type securityData struct {
	Users      []store.User
	Me         int64
	YourIP     string
	Allow      string
	Session    string
	NewName    string
	NewPass    string // shown once after adding a user or resetting a password
	NewPassFor string
}

func (s *Server) securityView(r *http.Request, sd *session) view {
	users, _ := s.d.Store.Users()
	var allow []string
	for _, p := range s.d.Store.UIAllow() {
		allow = append(allow, p.String())
	}
	d := securityData{Users: users, Me: sd.userID, YourIP: s.remoteIP(r).String(), Allow: strings.Join(allow, ", "),
		Session: numText(s.d.Store.SessionMinutes())}
	v := view{Nav: true, Active: "security", CSRF: sd.csrf, Data: d}
	s.flashFromQuery(r, &v)
	return v
}

func (s *Server) requireAdmin(w http.ResponseWriter, sd *session) bool {
	if !sd.admin() {
		http.Error(w, "administrators only", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if !s.requireAdmin(w, sd) {
		return
	}
	s.render(w, r, http.StatusOK, "security", s.securityView(r, sd))
}

func (s *Server) secErrKey(err error) string {
	switch {
	case errors.Is(err, store.ErrLastAdmin):
		return "last_admin"
	case errors.Is(err, store.ErrExists):
		return "user_exists"
	case errors.Is(err, store.ErrNotFound):
		return "user_not_found"
	case errors.Is(err, store.ErrInvalid):
		return "user_invalid"
	}
	s.d.Logger.Printf("web UI: %v", err)
	return "internal"
}

func userID(r *http.Request) int64 {
	n, _ := strconv.ParseInt(r.PostFormValue("id"), 10, 64)
	return n
}

func (s *Server) secUserAdd(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if !s.requireAdmin(w, sd) {
		return
	}
	name, role := strings.TrimSpace(r.PostFormValue("username")), r.PostFormValue("role")
	pw := r.PostFormValue("password")
	generated := false
	if pw == "" {
		var err error
		if pw, err = store.GeneratePassword(20); err != nil {
			s.fail(w, err)
			return
		}
		generated = true
	}
	if _, err := s.d.Store.AddUser(name, pw, role); err != nil {
		http.Redirect(w, r, "/security?err="+s.secErrKey(err), http.StatusSeeOther)
		return
	}
	s.d.Logger.Printf("web UI: user %q (%s) added by %q", name, role, sd.username)
	if !generated {
		http.Redirect(w, r, "/security?ok=user_added", http.StatusSeeOther)
		return
	}
	v := s.securityView(r, sd)
	d := v.Data.(securityData)
	d.NewPass, d.NewPassFor = pw, name
	v.Data = d
	v.Flash, v.FlashKind = s.tr(r, "flash.user_added"), "ok"
	s.render(w, r, http.StatusOK, "security", v)
}

func (s *Server) secUserRole(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if !s.requireAdmin(w, sd) {
		return
	}
	id := userID(r)
	if err := s.d.Store.SetUserRole(id, r.PostFormValue("role")); err != nil {
		http.Redirect(w, r, "/security?err="+s.secErrKey(err), http.StatusSeeOther)
		return
	}
	s.sess.destroyUser(id) // the new role applies at the next sign-in
	if id == sd.userID {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/security?ok=user_saved", http.StatusSeeOther)
}

func (s *Server) secUserReset(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if !s.requireAdmin(w, sd) {
		return
	}
	id := userID(r)
	u, err := s.d.Store.UserByID(id)
	if err != nil {
		http.Redirect(w, r, "/security?err="+s.secErrKey(err), http.StatusSeeOther)
		return
	}
	pw, err := store.GeneratePassword(20)
	if err == nil {
		err = s.d.Store.SetUserPassword(id, pw)
	}
	if err != nil {
		http.Redirect(w, r, "/security?err="+s.secErrKey(err), http.StatusSeeOther)
		return
	}
	s.sess.destroyUser(id)
	s.d.Logger.Printf("web UI: password of %q reset by %q", u.Username, sd.username)
	v := s.securityView(r, sd)
	d := v.Data.(securityData)
	d.NewPass, d.NewPassFor = pw, u.Username
	v.Data = d
	v.Flash, v.FlashKind = s.tr(r, "flash.user_saved"), "ok"
	s.render(w, r, http.StatusOK, "security", v)
}

func (s *Server) secUser2FAOff(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if !s.requireAdmin(w, sd) {
		return
	}
	if err := s.d.Store.DisableTOTP(userID(r)); err != nil {
		http.Redirect(w, r, "/security?err="+s.secErrKey(err), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/security?ok=user_saved", http.StatusSeeOther)
}

func (s *Server) secUserDelete(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if !s.requireAdmin(w, sd) {
		return
	}
	id := userID(r)
	if err := s.d.Store.DeleteUser(id); err != nil {
		http.Redirect(w, r, "/security?err="+s.secErrKey(err), http.StatusSeeOther)
		return
	}
	s.sess.destroyUser(id)
	if id == sd.userID {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/security?ok=user_deleted", http.StatusSeeOther)
}

// secAccess saves the network restriction and the session time. Saving a
// restriction that would lock out the person saving it is refused.
func (s *Server) secAccess(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	if !s.requireAdmin(w, sd) {
		return
	}
	fail := func(key string) {
		v := s.securityView(r, sd)
		d := v.Data.(securityData)
		d.Allow, d.Session = r.PostFormValue("allow"), r.PostFormValue("session")
		v.Data = d
		v.Flash, v.FlashKind = s.tr(r, key), "err"
		s.render(w, r, http.StatusBadRequest, "security", v)
	}
	minutes := atoiLoose(r.PostFormValue("session"))
	if err := s.d.Store.SetSessionMinutes(minutes); err != nil {
		fail("security.err_session")
		return
	}
	text := r.PostFormValue("allow")
	if strings.TrimSpace(text) != "" {
		list, err := store.ParseAddrList(text)
		if err != nil {
			fail("security.err_allow")
			return
		}
		ok := s.remoteIP(r).IsLoopback()
		for _, p := range list {
			if p.Contains(s.remoteIP(r)) {
				ok = true
			}
		}
		if !ok {
			fail("security.err_lockout")
			return
		}
	}
	if _, err := s.d.Store.SetUIAllow(text); err != nil {
		fail("security.err_allow")
		return
	}
	s.d.Logger.Printf("web UI: access settings changed by %q", sd.username)
	http.Redirect(w, r, "/security?ok=security_saved", http.StatusSeeOther)
}
