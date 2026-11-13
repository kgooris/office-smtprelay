package relay

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/kgooris/office-smtprelay/internal/graph"
	"github.com/kgooris/office-smtprelay/internal/policy"
)

// ---- fakes -----------------------------------------------------------------

type fakeRegistry struct {
	ipKnown bool
	users   map[string]string // username -> password

	// optional rules (relay.Runtime)
	pol    policy.Policy
	own    []string
	paused bool
}

func (r *fakeRegistry) ClientPolicy(string) policy.Policy { return r.pol }
func (r *fakeRegistry) OwnDomains() []string              { return r.own }
func (r *fakeRegistry) Paused() bool                      { return r.paused }

func (r *fakeRegistry) IPKnown(netip.Addr) bool { return r.ipKnown }
func (r *fakeRegistry) Authenticate(_ netip.Addr, u, p string) (string, error) {
	pw, ok := r.users[u]
	if !ok {
		return "", ErrUnknownUser
	}
	if pw != p {
		return "printer", ErrBadPassword
	}
	return "printer", nil
}

type sentMail struct {
	sender string
	mime   string
}

type fakeSender struct {
	mu   sync.Mutex
	sent []sentMail
	err  error
}

func (f *fakeSender) SendMIME(_ context.Context, sender string, mime []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentMail{sender, string(mime)})
	return nil
}

type eventLog struct {
	mu sync.Mutex
	ev []Event
}

func (l *eventLog) Record(e Event) { l.mu.Lock(); l.ev = append(l.ev, e); l.mu.Unlock() }
func (l *eventLog) last(t *testing.T) Event {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.ev) == 0 {
		t.Fatal("no events recorded")
	}
	return l.ev[len(l.ev)-1]
}

// ---- harness ---------------------------------------------------------------

type harness struct {
	addr   string
	reg    *fakeRegistry
	sender *fakeSender
	events *eventLog
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newHarness(t *testing.T, mutate func(*Config)) *harness {
	t.Helper()
	h := &harness{
		reg:    &fakeRegistry{ipKnown: true, users: map[string]string{"printer": "s3cret"}},
		sender: &fakeSender{},
		events: &eventLog{},
	}
	cfg := Config{}
	if mutate != nil {
		mutate(&cfg)
	}
	be := NewBackend(cfg, h.reg, h.sender, h.events)
	srv := smtp.NewServer(be)
	be.ConfigureServer(srv)
	srv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{selfSignedCert(t)}, MinVersion: tls.VersionTLS12}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	h.addr = ln.Addr().String()
	return h
}

// connect dials the relay and optionally upgrades to TLS.
func (h *harness) connect(t *testing.T, starttls bool) *smtp.Client {
	t.Helper()
	var (
		c   *smtp.Client
		err error
	)
	if starttls {
		c, err = smtp.DialStartTLS(h.addr, &tls.Config{InsecureSkipVerify: true})
	} else {
		c, err = smtp.Dial(h.addr)
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func smtpCode(err error) int {
	var se *smtp.SMTPError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

const msg = "From: printer@example.com\r\nTo: boss@example.org\r\nSubject: scan\r\n\r\nhello\r\n"

// ---- tests -----------------------------------------------------------------

func TestSend_PLAIN(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err != nil {
		t.Fatal(err)
	}
	if err := c.SendMail("Printer@Example.com", []string{"boss@example.org"}, strings.NewReader(msg)); err != nil {
		t.Fatal(err)
	}
	if len(h.sender.sent) != 1 || h.sender.sent[0].sender != "printer@example.com" {
		t.Fatalf("sent = %#v", h.sender.sent)
	}
	if !strings.Contains(h.sender.sent[0].mime, "Subject: scan") {
		t.Error("message content missing")
	}
	if e := h.events.last(t); e.Reason != ReasonSent || e.Client != "printer" || e.SMTPCode != 250 {
		t.Errorf("event = %#v", e)
	}
}

func TestSend_LOGIN(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(t, true)
	if err := c.Auth(sasl.NewLoginClient("printer", "s3cret")); err != nil {
		t.Fatal(err)
	}
	if err := c.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(msg)); err != nil {
		t.Fatal(err)
	}
	if len(h.sender.sent) != 1 {
		t.Fatal("message not delivered")
	}
}

func TestIPNotAllowed(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.ipKnown = false
	// go-smtp creates the session after EHLO, so the refusal is the EHLO answer.
	c, err := smtp.Dial(h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("device.example"); smtpCode(err) != 554 {
		t.Fatalf("EHLO err = %v, want 554", err)
	}
	if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err == nil {
		t.Fatal("a refused IP must not be able to authenticate")
	}
	if e := h.events.last(t); e.Reason != ReasonIPNotAllowed || e.SMTPCode != 554 {
		t.Errorf("event = %#v", e)
	}
}

func TestAuthRequiresTLS(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(t, false)
	if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err == nil {
		t.Fatal("AUTH must not be accepted before STARTTLS")
	}
	if len(h.sender.sent) != 0 {
		t.Error("nothing may be sent")
	}
}

func TestMailWithoutAuth(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(t, true)
	err := c.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(msg))
	if smtpCode(err) != 530 {
		t.Fatalf("err = %v, want 530", err)
	}
	if e := h.events.last(t); e.Reason != ReasonAuthRequired {
		t.Errorf("event = %#v", e)
	}
}

func TestBadPasswordAndUnknownUser(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "printer", "nope")); smtpCode(err) != 535 {
		t.Fatalf("err = %v, want 535", err)
	}
	if e := h.events.last(t); e.Reason != ReasonBadPassword {
		t.Errorf("event = %#v", e)
	}
	c2 := h.connect(t, true)
	if err := c2.Auth(sasl.NewPlainClient("", "ghost", "x")); smtpCode(err) != 535 {
		t.Fatalf("err = %v, want 535", err)
	}
	if e := h.events.last(t); e.Reason != ReasonUnknownUser {
		t.Errorf("event = %#v", e)
	}
}

func TestBruteForceBlocksAfterLimit(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxAuthFailures = 3 })
	for i := 0; i < 3; i++ {
		c := h.connect(t, true)
		if err := c.Auth(sasl.NewPlainClient("", "printer", "bad")); smtpCode(err) != 535 {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Even the right password is refused now.
	c := h.connect(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); smtpCode(err) != 454 {
		t.Fatalf("err = %v, want 454", err)
	}
	if e := h.events.last(t); e.Reason != ReasonAuthBlocked {
		t.Errorf("event = %#v", e)
	}
}

func TestMessageTooLarge(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.MaxMessageBytes = 200 })
	c := h.connect(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err != nil {
		t.Fatal(err)
	}
	big := msg + strings.Repeat("x", 1000) + "\r\n"
	err := c.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(big))
	if smtpCode(err) != 552 {
		t.Fatalf("err = %v, want 552", err)
	}
	if len(h.sender.sent) != 0 {
		t.Error("oversized message was forwarded")
	}
}

func TestGraphErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantCode   int
		wantReason Reason
	}{
		{"forbidden", &graph.Error{Status: 403, Code: "ErrorAccessDenied"}, 550, ReasonGraphForbidden},
		{"not found", &graph.Error{Status: 404}, 550, ReasonGraphNotFound},
		{"bad secret", &graph.Error{Status: 401, Code: "invalid_client"}, 554, ReasonGraphAuth},
		{"throttled", &graph.Error{Status: 429}, 451, ReasonGraphTemporary},
		{"server error", &graph.Error{Status: 503}, 451, ReasonGraphTemporary},
		{"rejected", &graph.Error{Status: 400}, 554, ReasonGraphRejected},
		{"timeout", context.DeadlineExceeded, 451, ReasonGraphTemporary},
		{"other", errors.New("boom"), 554, ReasonInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, nil)
			h.sender.err = tc.err
			c := h.connect(t, true)
			if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err != nil {
				t.Fatal(err)
			}
			err := c.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(msg))
			if smtpCode(err) != tc.wantCode {
				t.Fatalf("code = %d (%v), want %d", smtpCode(err), err, tc.wantCode)
			}
			if e := h.events.last(t); e.Reason != tc.wantReason {
				t.Errorf("reason = %s, want %s", e.Reason, tc.wantReason)
			}
			// The reply must never leak internals.
			if strings.Contains(err.Error(), "ErrorAccessDenied") || strings.Contains(err.Error(), "invalid_client") {
				t.Errorf("SMTP reply leaks Graph detail: %v", err)
			}
		})
	}
}

func TestEnsureEnvelopeRecipients(t *testing.T) {
	// Recipient only in the envelope gets a Bcc header.
	out := string(ensureEnvelopeRecipients([]byte(msg), []string{"boss@example.org", "secret@example.net"}))
	if !strings.HasPrefix(out, "Bcc: secret@example.net\r\n") {
		t.Errorf("missing Bcc header: %q", out)
	}
	// Everything already in To/Cc: unchanged.
	if got := string(ensureEnvelopeRecipients([]byte(msg), []string{"boss@example.org"})); got != msg {
		t.Errorf("message changed unexpectedly: %q", got)
	}
	// Existing Bcc header: untouched.
	withBcc := "Bcc: a@example.net\r\n" + msg
	if got := string(ensureEnvelopeRecipients([]byte(withBcc), []string{"x@example.net"})); got != withBcc {
		t.Errorf("message with Bcc changed: %q", got)
	}
	// Garbage is passed through.
	if got := string(ensureEnvelopeRecipients([]byte("not a message"), []string{"x@example.net"})); got != "not a message" {
		t.Errorf("garbage changed: %q", got)
	}
}
