package relay

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/kgooris/office-smtprelay/internal/policy"
)

func TestPolicy_DefaultChangesNothing(t *testing.T) {
	h := newHarness(t, nil)
	c := h.connect(t, true)
	if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err != nil {
		t.Fatal(err)
	}
	if err := c.SendMail("anyone@elsewhere.example", []string{"x@gmail.com"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("with no rules a registered device may send anything: %v", err)
	}
}

func TestPolicy_SenderReject(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.pol = policy.Policy{Sender: policy.SenderRule{Mode: policy.Enforce, Allowed: []string{"printer@example.com"}}}
	c := h.connect(t, true)
	_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c.SendMail("boss@example.com", []string{"a@example.org"}, strings.NewReader(msg)); smtpCode(err) != 550 {
		t.Fatalf("err = %v, want 550", err)
	}
	if e := h.events.last(t); e.Reason != ReasonSenderNotAllowed {
		t.Errorf("event = %#v", e)
	}
	if len(h.sender.sent) != 0 {
		t.Error("nothing may be sent")
	}
	c2 := h.connect(t, true)
	_ = c2.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c2.SendMail("printer@example.com", []string{"a@example.org"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("allowed sender refused: %v", err)
	}
}

func TestPolicy_TestModeLogsButSends(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.pol = policy.Policy{Sender: policy.SenderRule{Mode: policy.Log, Allowed: []string{"printer@example.com"}}}
	c := h.connect(t, true)
	_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c.SendMail("boss@example.com", []string{"a@example.org"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("test mode must not refuse: %v", err)
	}
	if len(h.sender.sent) != 1 {
		t.Fatal("the message must be delivered")
	}
	var found bool
	for _, e := range h.events.ev {
		if e.Reason == ReasonPolicyTest && strings.Contains(e.Detail, "sender_not_allowed") {
			found = true
		}
	}
	if !found {
		t.Errorf("test-mode hit not logged: %#v", h.events.ev)
	}
}

func TestPolicy_SenderRewrite(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.pol = policy.Policy{
		Sender:  policy.SenderRule{Mode: policy.Enforce, Action: policy.Rewrite, RewriteTo: "printer@gbk.be"},
		Headers: policy.Headers{ReplyTo: "helpdesk@gbk.be", SubjectTag: "Printer"},
	}
	c := h.connect(t, true)
	_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	raw := "From: \"Scan\" <scanner@kopieerder.local>\r\nTo: boss@example.org\r\nSubject: scan\r\n\r\nhello\r\n"
	if err := c.SendMail("scanner@kopieerder.local", []string{"boss@example.org"}, strings.NewReader(raw)); err != nil {
		t.Fatalf("a rewrite must never refuse: %v", err)
	}
	got := h.sender.sent[0]
	if got.sender != "printer@gbk.be" {
		t.Errorf("Graph sender = %q", got.sender)
	}
	for _, want := range []string{"From: \"Scan\" <printer@gbk.be>", "X-Original-From:", "Reply-To: helpdesk@gbk.be", "Subject: [Printer] scan"} {
		if !strings.Contains(got.mime, want) {
			t.Errorf("missing %q in\n%s", want, got.mime)
		}
	}
}

func TestPolicy_Recipients(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.own = []string{"example.org"}
	h.reg.pol = policy.Policy{Rcpt: policy.RcptRule{Mode: policy.Enforce, Scope: policy.ScopeInternal}}
	c := h.connect(t, true)
	_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c.SendMail("printer@example.com", []string{"boss@example.org", "x@gmail.com"}, strings.NewReader(msg)); smtpCode(err) != 550 {
		t.Fatalf("err = %v, want 550 for the external recipient", err)
	}
	if e := h.events.last(t); e.Reason != ReasonRcptNotAllowed {
		t.Errorf("event = %#v", e)
	}
	c2 := h.connect(t, true)
	_ = c2.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c2.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("internal recipient refused: %v", err)
	}
}

func TestPolicy_RateLimitAndBlock(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.pol = policy.Policy{Limits: policy.LimitRule{Mode: policy.Enforce, PerHour: 2}}
	send := func() error {
		c := h.connect(t, true)
		_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
		return c.SendMail("printer@example.com", []string{"a@example.org"}, strings.NewReader(msg))
	}
	for i := 0; i < 2; i++ {
		if err := send(); err != nil {
			t.Fatalf("message %d: %v", i+1, err)
		}
	}
	if err := send(); smtpCode(err) != 451 {
		t.Fatalf("third message: %v, want 451", err)
	}
	if e := h.events.last(t); e.Reason != ReasonLimitExceeded {
		t.Errorf("event = %#v", e)
	}

	// With the "block" action the whole device is blocked afterwards.
	h2 := newHarness(t, nil)
	h2.reg.pol = policy.Policy{Limits: policy.LimitRule{Mode: policy.Enforce, PerHour: 1, Action: policy.LimitBlock, BlockMinutes: 10}}
	send2 := func() error {
		c := h2.connect(t, true)
		_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
		return c.SendMail("printer@example.com", []string{"a@example.org"}, strings.NewReader(msg))
	}
	if err := send2(); err != nil {
		t.Fatal(err)
	}
	if err := send2(); smtpCode(err) != 451 {
		t.Fatalf("limit hit: %v", err)
	}
	if err := send2(); smtpCode(err) != 454 {
		t.Fatalf("blocked device: %v, want 454", err)
	}
}

func TestPolicy_MaxRecipientsAndSize(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.pol = policy.Policy{Limits: policy.LimitRule{Mode: policy.Enforce, MaxRcpts: 1, MaxSizeMB: 1}}
	c := h.connect(t, true)
	_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c.SendMail("printer@example.com", []string{"a@example.org", "b@example.org"}, strings.NewReader(msg)); smtpCode(err) != 452 {
		t.Fatalf("recipients: %v, want 452", err)
	}
	c2 := h.connect(t, true)
	_ = c2.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	big := msg + strings.Repeat(strings.Repeat("x", 98)+"\r\n", 22000) // short lines: go-smtp caps the line length
	if err := c2.SendMail("printer@example.com", []string{"a@example.org"}, strings.NewReader(big)); smtpCode(err) != 552 {
		t.Fatalf("size: %v, want 552", err)
	}
}

func TestPolicy_PauseStopsEverything(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.paused = true
	// go-smtp creates the session after EHLO, so the refusal is the EHLO answer.
	c, err := smtp.Dial(h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("device.example"); smtpCode(err) != 421 {
		t.Fatalf("EHLO err = %v, want 421", err)
	}
	if e := h.events.last(t); e.Reason != ReasonPaused {
		t.Errorf("event = %#v", e)
	}
	h.reg.paused = false
	c2 := h.connect(t, true)
	if err := c2.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err != nil {
		t.Fatalf("after resume: %v", err)
	}
}

const withExe = "From: printer@example.com\r\nTo: boss@example.org\r\nSubject: scan\r\nMIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=\"B\"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n" +
	"--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"setup.exe\"\r\n\r\nMZ\r\n--B--\r\n"

func TestPolicy_Attachments(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.pol = policy.Policy{Attach: policy.AttachRule{Mode: policy.Enforce, Kind: policy.AttachBlock, Extensions: []string{"exe"}}}
	c := h.connect(t, true)
	_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(withExe)); smtpCode(err) != 554 {
		t.Fatalf("err = %v, want 554", err)
	}
	if e := h.events.last(t); e.Reason != ReasonAttachment || !strings.Contains(e.Detail, "setup.exe") {
		t.Errorf("event = %#v", e)
	}
	c2 := h.connect(t, true)
	_ = c2.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c2.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("a message without attachments must pass: %v", err)
	}

	// Test mode logs and delivers.
	h2 := newHarness(t, nil)
	h2.reg.pol = policy.Policy{Attach: policy.AttachRule{Mode: policy.Log, Kind: policy.AttachBlock, Extensions: []string{"exe"}}}
	c3 := h2.connect(t, true)
	_ = c3.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c3.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(withExe)); err != nil {
		t.Fatalf("test mode must not refuse: %v", err)
	}
	if len(h2.sender.sent) != 1 {
		t.Error("delivered in test mode")
	}
}

func TestPolicy_BlindCopy(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.pol = policy.Policy{Headers: policy.Headers{Bcc: []string{"Archive@gbk.be", "boss@example.org"}}}
	c := h.connect(t, true)
	_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
	if err := c.SendMail("printer@example.com", []string{"boss@example.org"}, strings.NewReader(msg)); err != nil {
		t.Fatal(err)
	}
	got := h.sender.sent[0].mime
	if !strings.Contains(got, "Bcc: archive@gbk.be\r\n") {
		t.Errorf("the blind copy address must be added as a Bcc header:\n%s", got)
	}
	if strings.Contains(got, "boss@example.org, ") || strings.Count(got, "boss@example.org") != 1 {
		t.Errorf("an address already in To must not be added twice:\n%s", got)
	}
}

func TestLiveLimits_MessageSize(t *testing.T) {
	var maxBytes int64 = 10 << 20
	h := newHarness(t, func(c *Config) { c.Limits = func() Limits { return Limits{MaxMessageBytes: maxBytes} } })
	big := msg + strings.Repeat(strings.Repeat("x", 98)+"\r\n", 22000) // about 2 MB
	send := func() error {
		c := h.connect(t, true)
		_ = c.Auth(sasl.NewPlainClient("", "printer", "s3cret"))
		return c.SendMail("printer@example.com", []string{"a@example.org"}, strings.NewReader(big))
	}
	if err := send(); err != nil {
		t.Fatalf("under the limit: %v", err)
	}
	maxBytes = 1 << 20 // the administrator lowers the limit: no restart needed
	if err := send(); smtpCode(err) != 552 {
		t.Fatalf("over the new limit: %v, want 552", err)
	}
	if e := h.events.last(t); e.Reason != ReasonTooLarge {
		t.Errorf("event = %#v", e)
	}
}

func TestLiveLimits_ConnectionsPerIP(t *testing.T) {
	h := newHarness(t, func(c *Config) { c.Limits = func() Limits { return Limits{MaxConnsPerIP: 1} } })
	first := h.connect(t, false)
	if err := first.Hello("a.example"); err != nil {
		t.Fatal(err)
	}
	second := h.connect(t, false)
	if err := second.Hello("b.example"); smtpCode(err) != 421 {
		t.Fatalf("second connection: %v, want 421", err)
	}
	if e := h.events.last(t); e.Reason != ReasonConnLimit {
		t.Errorf("event = %#v", e)
	}
	_ = first.Quit() // frees the slot
	time.Sleep(100 * time.Millisecond)
	third := h.connect(t, false)
	if err := third.Hello("c.example"); err != nil {
		t.Fatalf("after the first connection closed: %v", err)
	}
}

// legacyHarness runs the optional listener without encryption.
func legacyHarness(t *testing.T, pol policy.Policy) *harness {
	t.Helper()
	h := &harness{
		reg:    &fakeRegistry{ipKnown: true, users: map[string]string{"printer": "s3cret"}, pol: pol},
		sender: &fakeSender{},
		events: &eventLog{},
	}
	be := NewBackend(Config{}, h.reg, h.sender, h.events)
	srv := smtp.NewServer(be.ForLegacy())
	be.ConfigureServer(srv)
	srv.Backend = be.ForLegacy()
	srv.AllowInsecureAuth = true
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	h.addr = ln.Addr().String()
	return h
}

func TestLegacyListener_OnlyForDevicesThatMay(t *testing.T) {
	// A device without the exception is refused on the unencrypted listener.
	h := legacyHarness(t, policy.Policy{})
	c := h.connect(t, false)
	if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); smtpCode(err) != 538 {
		t.Fatalf("auth err = %v, want 538", err)
	}
	if e := h.events.last(t); e.Reason != ReasonTLSRequired || e.Client != "printer" {
		t.Errorf("event = %#v", e)
	}
	if err := c.SendMail("printer@example.com", []string{"a@example.org"}, strings.NewReader(msg)); err == nil {
		t.Fatal("a device that failed to sign in must not be able to send")
	}

	// With the exception it works without TLS.
	h2 := legacyHarness(t, policy.Policy{TLS: policy.TLSRule{AllowPlain: true}})
	c2 := h2.connect(t, false)
	if err := c2.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err != nil {
		t.Fatalf("allowed device: %v", err)
	}
	if err := c2.SendMail("printer@example.com", []string{"a@example.org"}, strings.NewReader(msg)); err != nil {
		t.Fatalf("send: %v", err)
	}
}

func TestNormalListenerStillRequiresTLS(t *testing.T) {
	h := newHarness(t, nil)
	h.reg.pol = policy.Policy{TLS: policy.TLSRule{AllowPlain: true}} // irrelevant on the normal listener
	c := h.connect(t, false)
	if err := c.Auth(sasl.NewPlainClient("", "printer", "s3cret")); err == nil {
		t.Fatal("sign-in without STARTTLS must stay impossible on the normal listener")
	}
}
