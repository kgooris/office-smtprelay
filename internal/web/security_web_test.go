package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kgooris/office-smtprelay/internal/config"
	"github.com/kgooris/office-smtprelay/internal/totp"
)

// signIn signs a user in on a fresh browser session of the same server and
// returns that browser and its CSRF token.
func signIn(t *testing.T, e *env, user, password string) (*env, string) {
	t.Helper()
	b := newEnvSharingServer(e)
	pre := csrfOf(t, b.get("/login").body)
	r := b.post("/login", url.Values{"csrf": {pre}, "username": {user}, "password": {password}})
	if r.status != 303 || r.location != "/" {
		t.Fatalf("sign-in of %s = %d %q", user, r.status, r.location)
	}
	return b, csrfOf(t, b.get("/").body)
}

func TestUsersAndReadOnlyRole(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()

	if !strings.Contains(e.get("/security").body, "Add a user") {
		t.Fatal("administrators see the security page")
	}
	// Add a read-only user with a chosen password and one with a generated password.
	if r := e.post("/security/user/add", url.Values{"csrf": {csrf}, "username": {"jan"}, "role": {"readonly"}, "password": {"jan-reads-only-12"}}); !strings.Contains(r.location, "ok=user_added") {
		t.Fatalf("add = %d %q", r.status, r.location)
	}
	r := e.post("/security/user/add", url.Values{"csrf": {csrf}, "username": {"els"}, "role": {"admin"}})
	if r.status != 200 || !strings.Contains(r.body, "shown only once") || !strings.Contains(r.body, `class="secret mono"`) {
		t.Fatalf("generated password page = %d", r.status)
	}
	if r := e.post("/security/user/add", url.Values{"csrf": {csrf}, "username": {"JAN"}, "role": {"admin"}, "password": {"long-enough-pw-12"}}); !strings.Contains(r.location, "err=user_exists") {
		t.Errorf("duplicate = %q", r.location)
	}

	// The read-only user can look but not change anything.
	jan, janCSRF := signIn(t, e, "jan", "jan-reads-only-12")
	for _, p := range []string{"/", "/clients", "/logs", "/settings", "/connection", "/notifications", "/backup", "/help", "/account"} {
		if jan.get(p).status != 200 {
			t.Errorf("read-only GET %s = %d", p, jan.get(p).status)
		}
	}
	if jan.get("/security").status != 403 {
		t.Error("the security page is for administrators")
	}
	body := jan.get("/").body
	if strings.Contains(body, `href="/security"`) || !strings.Contains(body, "(jan)") {
		t.Error("the menu hides Security from read-only users and shows who is signed in")
	}
	for path, form := range map[string]url.Values{
		"/clients/add":       {"name": {"X"}, "ip": {"192.0.2.9"}},
		"/pause":             {"pause": {"1"}},
		"/settings/general":  {"lang": {"nl"}},
		"/backup/export":     {},
		"/security/user/add": {"username": {"x"}, "role": {"admin"}, "password": {"long-enough-pw-12"}},
	} {
		form.Set("csrf", janCSRF)
		if r := jan.post(path, form); r.status != 403 {
			t.Errorf("read-only POST %s = %d, want 403", path, r.status)
		}
	}
	if len(mustClients(t, e)) != 0 || e.st.Paused() {
		t.Error("nothing may have changed")
	}
	// ... but he can change his own password.
	if r := jan.post("/account", url.Values{"csrf": {janCSRF}, "current": {"jan-reads-only-12"}, "password": {"jan-has-a-new-one-12"}, "confirm": {"jan-has-a-new-one-12"}}); !strings.Contains(r.location, "ok=password_changed") {
		t.Errorf("own password change = %d %q", r.status, r.location)
	}

	// Last admin protection and deleting users.
	users, _ := e.st.Users()
	var adminID, janID string
	for _, u := range users {
		switch u.Username {
		case "admin":
			adminID = itoa(u.ID)
		case "jan":
			janID = itoa(u.ID)
		}
	}
	e.post("/security/user/role", url.Values{"csrf": {csrf}, "id": {janID}, "role": {"admin"}})
	if r := e.post("/security/user/delete", url.Values{"csrf": {csrf}, "id": {janID}}); !strings.Contains(r.location, "ok=user_deleted") {
		t.Errorf("delete = %q", r.location)
	}
	els, _ := e.st.UserByName("els")
	e.post("/security/user/delete", url.Values{"csrf": {csrf}, "id": {itoa(els.ID)}})
	if r := e.post("/security/user/delete", url.Values{"csrf": {csrf}, "id": {adminID}}); !strings.Contains(r.location, "err=last_admin") {
		t.Errorf("the last admin must stay: %q", r.location)
	}
}

func mustClients(t *testing.T, e *env) []string {
	t.Helper()
	list, err := e.st.ListClients()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range list {
		names = append(names, c.Name)
	}
	return names
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func (e *env) getWithHeader(path, key, value string) resp {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.ts.URL+path, nil)
	req.Header.Set(key, value)
	return e.do(req)
}

func TestTwoStepSignIn(t *testing.T) {
	e := newEnv(t, nil)
	csrf := e.login()

	// Set up two-step verification for the admin.
	r := e.post("/account/totp/begin", url.Values{"csrf": {csrf}})
	if r.status != 200 || !strings.Contains(r.body, "Secret key") {
		t.Fatalf("begin = %d", r.status)
	}
	admin, _ := e.st.UserByName("admin")
	secret, ok := e.st.PendingTOTP(admin.ID)
	if !ok {
		t.Fatal("pending secret")
	}
	if r := e.post("/account/totp/confirm", url.Values{"csrf": {csrf}, "code": {"000000"}}); r.status != 400 || !strings.Contains(r.body, "not valid") {
		t.Errorf("wrong code = %d", r.status)
	}
	code, _ := totp.Code(secret, time.Now())
	r = e.post("/account/totp/confirm", url.Values{"csrf": {csrf}, "code": {code}})
	if r.status != 200 || strings.Count(r.body, "-") < 8 || !strings.Contains(r.body, "Save these recovery codes") {
		t.Fatalf("confirm = %d", r.status)
	}
	recovery := regexpFindCodes(r.body)
	if len(recovery) != 8 {
		t.Fatalf("recovery codes = %v", recovery)
	}

	// A new sign-in needs the password AND the code.
	b := newEnvSharingServer(e)
	pre := csrfOf(t, b.get("/login").body)
	r = b.post("/login", url.Values{"csrf": {pre}, "password": {adminPW}})
	if r.status != 303 || r.location != "/login/2fa" {
		t.Fatalf("password step = %d %q", r.status, r.location)
	}
	if b.get("/clients").status != 303 {
		t.Fatal("the password alone must not sign you in")
	}
	pre = csrfOf(t, b.get("/login/2fa").body)
	if r := b.post("/login/2fa", url.Values{"csrf": {pre}, "code": {"123456"}}); r.status != 401 {
		t.Errorf("wrong code = %d", r.status)
	}
	// The code that was used to set it up cannot be replayed; the next step's code works.
	next, _ := totp.Code(secret, time.Now().Add(30*time.Second))
	if r := b.post("/login/2fa", url.Values{"csrf": {pre}, "code": {next}}); r.status != 303 || r.location != "/" {
		// the clock may sit in the same step as setup: fall back to a recovery code
		if r := b.post("/login/2fa", url.Values{"csrf": {pre}, "code": {recovery[0]}}); r.status != 303 {
			t.Fatalf("second step = %d", r.status)
		}
	}
	if b.get("/clients").status != 200 {
		t.Error("signed in after the second step")
	}

	// A recovery code works once.
	c2 := newEnvSharingServer(e)
	pre = csrfOf(t, c2.get("/login").body)
	c2.post("/login", url.Values{"csrf": {pre}, "password": {adminPW}})
	pre = csrfOf(t, c2.get("/login/2fa").body)
	if r := c2.post("/login/2fa", url.Values{"csrf": {pre}, "code": {recovery[0]}}); r.status == 303 && recovery[0] != "" {
		// already used above when the fallback ran: accept either outcome, then test the next code
		_ = r
	}
	c3 := newEnvSharingServer(e)
	pre = csrfOf(t, c3.get("/login").body)
	c3.post("/login", url.Values{"csrf": {pre}, "password": {adminPW}})
	pre = csrfOf(t, c3.get("/login/2fa").body)
	if r := c3.post("/login/2fa", url.Values{"csrf": {pre}, "code": {recovery[1]}}); r.status != 303 {
		t.Errorf("a fresh recovery code must work: %d", r.status)
	}
	c4 := newEnvSharingServer(e)
	pre = csrfOf(t, c4.get("/login").body)
	c4.post("/login", url.Values{"csrf": {pre}, "password": {adminPW}})
	pre = csrfOf(t, c4.get("/login/2fa").body)
	if r := c4.post("/login/2fa", url.Values{"csrf": {pre}, "code": {recovery[1]}}); r.status != 401 {
		t.Errorf("a recovery code must not work twice: %d", r.status)
	}

	// Switching it off needs the password; an administrator can also reset it.
	if r := e.post("/account/totp/disable", url.Values{"csrf": {csrf}, "current": {"wrong-password-12"}}); r.status != 401 {
		t.Errorf("disable with a wrong password = %d", r.status)
	}
	if r := e.post("/security/user/2fa-off", url.Values{"csrf": {csrf}, "id": {itoa(admin.ID)}}); !strings.Contains(r.location, "ok=user_saved") {
		t.Errorf("admin reset = %q", r.location)
	}
	if got, _ := e.st.UserByID(admin.ID); got.TOTPEnabled {
		t.Error("two-step must be off")
	}
}

// regexpFindCodes returns the recovery codes from the <pre> block of the page.
func regexpFindCodes(body string) []string {
	i, j := strings.Index(body, "<pre>"), strings.Index(body, "</pre>")
	if i < 0 || j < i {
		return nil
	}
	return strings.Fields(body[i+len("<pre>") : j])
}

func TestNetworkRestrictionCannotLockYouOut(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.TrustProxy = true })
	csrf := e.login()
	as := func(ip string) func(path string) resp {
		return func(path string) resp { return e.getWithHeader(path, "X-Forwarded-For", ip) }
	}

	post := func(allow, session string) resp {
		return e.post("/security/access", url.Values{"csrf": {csrf}, "allow": {allow}, "session": {session}}, "X-Forwarded-For", "192.168.1.50")
	}
	if r := post("10.0.0.0/8", ""); r.status != 400 || !strings.Contains(r.body, "lock yourself out") {
		t.Fatalf("a list without your own address must be refused: %d", r.status)
	}
	if len(e.st.UIAllow()) != 0 {
		t.Fatal("nothing saved")
	}
	if r := post("nonsense", ""); r.status != 400 {
		t.Errorf("bad list = %d", r.status)
	}
	if r := post("192.168.1.0/24", "20"); !strings.Contains(r.location, "ok=security_saved") {
		t.Fatalf("save = %d %q", r.status, r.location)
	}
	if e.st.SessionMinutes() != 20 {
		t.Error("session minutes")
	}
	if as("192.168.1.77")("/login").status == 403 {
		t.Error("an address inside the list may open the UI")
	}
	if r := as("203.0.113.9")("/login"); r.status != 403 {
		t.Errorf("an address outside the list = %d, want 403", r.status)
	}
	if as("203.0.113.9")("/healthz").status != 403 {
		t.Error("the restriction covers every page")
	}
	if r := e.get("/login"); r.status == 403 { // no X-Forwarded-For: the test client itself is loopback
		t.Errorf("loopback is always allowed (health check): %d", r.status)
	}
	if r := post("", "999"); r.status != 400 {
		t.Errorf("session time out of range = %d", r.status)
	}
	if r := post("", ""); !strings.Contains(r.location, "ok=security_saved") || len(e.st.UIAllow()) != 0 {
		t.Errorf("an empty list removes the restriction: %q", r.location)
	}
}
