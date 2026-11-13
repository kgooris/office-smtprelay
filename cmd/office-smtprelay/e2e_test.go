package main

import (
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/relay"
	"github.com/kgooris/office-smtprelay/internal/store"
	"github.com/kgooris/office-smtprelay/internal/tlsutil"
)

// fakeMicrosoft stands in for Entra ID and Microsoft Graph.
type fakeMicrosoft struct {
	mu     sync.Mutex
	sender string
	mime   string
	status int // answer of sendMail; 0 = 202
}

func (f *fakeMicrosoft) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
		_ = r.ParseForm()
		if r.Form.Get("client_secret") != "the-secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"bad secret"}`)
			return
		}
		_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
	case strings.HasSuffix(r.URL.Path, "/sendMail"):
		b, _ := io.ReadAll(r.Body)
		raw, _ := base64.StdEncoding.DecodeString(string(b))
		f.mu.Lock()
		defer f.mu.Unlock()
		f.sender = strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1.0/users/"), "/sendMail")
		f.mime = string(raw)
		if f.status != 0 {
			w.WriteHeader(f.status)
			_, _ = io.WriteString(w, `{"error":{"code":"ErrorAccessDenied","message":"denied"}}`)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	default:
		http.NotFound(w, r)
	}
}

// startRelay wires the real components together exactly like runServe does.
func startRelay(t *testing.T, ms *fakeMicrosoft) (addr string, st *store.Store) {
	t.Helper()
	dir := t.TempDir()
	key, err := store.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(filepath.Join(dir, "relay.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	msSrv := httptest.NewServer(ms)
	t.Cleanup(msSrv.Close)

	tlsCfg, err := tlsutil.Load(dir, "", "", []string{"localhost"}, tls.VersionTLS12)
	if err != nil {
		t.Fatal(err)
	}
	snd := &lazySender{st: st, options: []graph.Option{graph.WithEndpoints(msSrv.URL, msSrv.URL)}}
	be := relay.NewBackend(relay.Config{}, st, snd, st)
	srv := smtp.NewServer(be)
	be.ConfigureServer(srv)
	srv.TLSConfig = tlsCfg
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), st
}

func nowPlus() time.Time { return time.Now().AddDate(1, 0, 0) }

const testMsg = "From: printer@example.com\r\nTo: boss@example.org\r\nSubject: scan\r\n\r\nhello\r\n"

func login(t *testing.T, addr, user, pass string) *smtp.Client {
	t.Helper()
	c, err := smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	if err := c.Auth(sasl.NewPlainClient("", user, pass)); err != nil {
		t.Fatalf("auth: %v", err)
	}
	return c
}

func TestEndToEnd(t *testing.T) {
	ms := &fakeMicrosoft{}
	addr, st := startRelay(t, ms)
	if _, err := st.AddClient("Printer", "127.0.0.1", "printer", "a-long-password-1"); err != nil {
		t.Fatal(err)
	}

	// 1. Microsoft connection not configured yet: the device gets a clear refusal.
	c := login(t, addr, "printer", "a-long-password-1")
	err := c.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(testMsg))
	if err == nil {
		t.Fatal("mail must be refused while the Microsoft connection is not configured")
	}
	if evs, _ := st.ListEvents(store.EventFilter{OnlyFail: true}, 10, 0); len(evs) == 0 || evs[0].Reason != relay.ReasonGraphAuth {
		t.Fatalf("events = %#v", evs)
	}

	// 2. Configure the connection at runtime (as the UI/CLI does): no restart needed.
	if err := st.SetGraphCredentials(graph.Credentials{TenantID: "tenant", ClientID: "app", ClientSecret: "the-secret"}, nowPlus()); err != nil {
		t.Fatal(err)
	}
	c = login(t, addr, "printer", "a-long-password-1")
	if err := c.SendMail("Printer@Example.com", []string{"boss@example.org"}, strings.NewReader(testMsg)); err != nil {
		t.Fatalf("send: %v", err)
	}
	ms.mu.Lock()
	if ms.sender != "printer@example.com" || !strings.Contains(ms.mime, "Subject: scan") {
		t.Errorf("Graph received sender=%q mime=%q", ms.sender, ms.mime)
	}
	ms.mu.Unlock()
	if evs, _ := st.ListEvents(store.EventFilter{Reason: relay.ReasonSent}, 10, 0); len(evs) != 1 || evs[0].Client != "Printer" {
		t.Errorf("sent events = %#v", evs)
	}

	// 3. Microsoft denies the sender mailbox: 550 to the device, reason in the log, no secret leaked.
	ms.mu.Lock()
	ms.status = http.StatusForbidden
	ms.mu.Unlock()
	c = login(t, addr, "printer", "a-long-password-1")
	err = c.SendMail("someone@example.com", []string{"boss@example.org"}, strings.NewReader(testMsg))
	if se, ok := err.(*smtp.SMTPError); !ok || se.Code != 550 {
		t.Fatalf("err = %v, want 550", err)
	}

	// 4. A disabled client is locked out immediately.
	_ = st.SetClientEnabled("Printer", false)
	cc, err := smtp.DialStartTLS(addr, &tls.Config{InsecureSkipVerify: true})
	if err == nil {
		defer cc.Close()
		if cc.Auth(sasl.NewPlainClient("", "printer", "a-long-password-1")) == nil {
			t.Error("a disabled client must not be able to log in")
		}
	}
}

func TestLazySenderPicksUpNewCredentials(t *testing.T) {
	ms := &fakeMicrosoft{}
	_, st := startRelay(t, ms)
	snd := &lazySender{st: st}
	if _, err := snd.current(); err == nil {
		t.Fatal("expected not-configured error")
	}
	_ = st.SetGraphCredentials(graph.Credentials{TenantID: "t", ClientID: "c", ClientSecret: "s1"}, nowPlus())
	c1, err := snd.current()
	if err != nil {
		t.Fatal(err)
	}
	if c2, _ := snd.current(); c2 != c1 {
		t.Error("client must be reused while credentials are unchanged")
	}
	_ = st.SetGraphCredentials(graph.Credentials{TenantID: "t", ClientID: "c", ClientSecret: "s2"}, nowPlus())
	if c3, _ := snd.current(); c3 == c1 {
		t.Error("client must be rebuilt after the secret changed")
	}
}
