// Package relay implements the SMTP server side of office-smtprelay:
// it admits devices by source IP and credentials and hands accepted
// messages to a Sender (Microsoft Graph).
package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/kgooris/office-smtprelay/internal/policy"
	"github.com/kgooris/office-smtprelay/internal/ratelimit"
)

// Reason is a stable, language-independent code stored in the event log.
// The UI translates it when it is displayed.
type Reason string

const (
	ReasonSent            Reason = "sent"
	ReasonIPNotAllowed    Reason = "ip_not_allowed"
	ReasonAuthRequired    Reason = "auth_required"
	ReasonUnknownUser     Reason = "unknown_user"
	ReasonBadPassword     Reason = "bad_password"
	ReasonWrongIP         Reason = "user_wrong_ip"
	ReasonAuthBlocked     Reason = "auth_blocked"
	ReasonNoSender        Reason = "no_sender"
	ReasonNoRecipients    Reason = "no_recipients"
	ReasonTooLarge        Reason = "message_too_large"
	ReasonGraphAuth       Reason = "graph_auth_failed"
	ReasonGraphForbidden  Reason = "graph_forbidden"
	ReasonGraphNotFound   Reason = "graph_mailbox_not_found"
	ReasonGraphRejected   Reason = "graph_rejected"
	ReasonGraphTemporary  Reason = "graph_temporary"
	ReasonInternal        Reason = "internal_error"
	ReasonMessageReadFail Reason = "message_read_failed"

	// Optional per-client rules (see package policy).
	ReasonSenderNotAllowed Reason = "sender_not_allowed"
	ReasonRcptNotAllowed   Reason = "rcpt_not_allowed"
	ReasonLimitExceeded    Reason = "limit_exceeded"
	ReasonClientBlocked    Reason = "client_blocked"
	ReasonAttachment       Reason = "attachment_not_allowed"
	ReasonConnLimit        Reason = "connection_limit"
	ReasonTLSRequired      Reason = "tls_required"
	ReasonPaused           Reason = "paused"
	// ReasonPolicyTest marks a rule violation in test mode: the message was NOT refused.
	ReasonPolicyTest Reason = "policy_test"
)

// Authentication errors returned by a Registry.
var (
	ErrUnknownUser = errors.New("unknown user")
	ErrBadPassword = errors.New("bad password")
	// ErrWrongIP means the user exists but is registered for another IP address.
	ErrWrongIP = errors.New("user not allowed from this IP")
)

// Event describes one connection attempt or message for the log.
type Event struct {
	Time       time.Time
	RemoteIP   netip.Addr
	Client     string // client name, empty if unknown
	Reason     Reason
	SMTPCode   int
	Sender     string
	Recipients int
	Bytes      int
	Detail     string // short technical detail, never message content
}

// Recorder receives events. Implementations must be safe for concurrent use.
type Recorder interface{ Record(Event) }

// Registry knows the registered devices.
type Registry interface {
	// IPKnown reports whether an enabled client is registered for this IP.
	IPKnown(ip netip.Addr) bool
	// Authenticate verifies the credentials of a client registered for this IP.
	// It returns the client name, or ErrUnknownUser / ErrBadPassword.
	Authenticate(ip netip.Addr, username, password string) (clientName string, err error)
}

// Runtime is implemented by registries that also know the optional per-client
// rules and the global switches. A Registry without it behaves as before.
type Runtime interface {
	ClientPolicy(name string) policy.Policy
	OwnDomains() []string
	Paused() bool
}

// Sender delivers a MIME message as the given mailbox.
type Sender interface {
	SendMIME(ctx context.Context, sender string, mime []byte) error
}

// statusError is implemented by errors that carry an HTTP status and a
// "temporary" flag (the Graph client's *graph.Error does).
type statusError interface {
	error
	Temporary() bool
	HTTPStatus() int
}

// Limits are the settings the administrator can change while the relay runs.
type Limits struct {
	MaxMessageBytes int64 // 0 = use Config.MaxMessageBytes
	MaxConnsPerIP   int   // 0 = unlimited
}

// hardMessageCeiling is the largest message the SMTP library will ever read;
// the (changeable) limit below it is enforced by the relay itself.
const hardMessageCeiling = 150 << 20

// Config holds server settings.
type Config struct {
	// Limits, when set, is asked for the current limits on every use, so they
	// can be changed without a restart.
	Limits func() Limits

	Hostname        string
	MaxMessageBytes int64         // default 35 MiB
	MaxRecipients   int           // default 100
	MaxAuthFailures int           // per IP within AuthFailWindow; default 5
	AuthFailWindow  time.Duration // default 10 minutes
	SendTimeout     time.Duration // default 2 minutes
}

func (c *Config) defaults() {
	if c.Hostname == "" {
		c.Hostname = "office-smtprelay"
	}
	if c.MaxMessageBytes == 0 {
		c.MaxMessageBytes = 35 << 20
	}
	if c.MaxRecipients == 0 {
		c.MaxRecipients = 100
	}
	if c.MaxAuthFailures == 0 {
		c.MaxAuthFailures = 5
	}
	if c.AuthFailWindow == 0 {
		c.AuthFailWindow = 10 * time.Minute
	}
	if c.SendTimeout == 0 {
		c.SendTimeout = 2 * time.Minute
	}
}

// Backend implements smtp.Backend.
type Backend struct {
	cfg      Config
	registry Registry
	sender   Sender
	rec      Recorder
	limiter  *ratelimit.FailLimiter
	connMu   sync.Mutex
	conns    map[netip.Addr]int
	counts   *ratelimit.Counter
	blocks   *ratelimit.Blocks
	rt       Runtime // nil when the registry has no optional rules
	now      func() time.Time
}

func (b *Backend) limits() Limits {
	var l Limits
	if b.cfg.Limits != nil {
		l = b.cfg.Limits()
	}
	if l.MaxMessageBytes <= 0 {
		l.MaxMessageBytes = b.cfg.MaxMessageBytes
	}
	return l
}

// acquire counts a new connection from ip; it reports false when the limit is reached.
func (b *Backend) acquire(ip netip.Addr, max int) bool {
	b.connMu.Lock()
	defer b.connMu.Unlock()
	if max > 0 && b.conns[ip] >= max {
		return false
	}
	b.conns[ip]++
	return true
}

func (b *Backend) release(ip netip.Addr) {
	b.connMu.Lock()
	defer b.connMu.Unlock()
	if b.conns[ip] <= 1 {
		delete(b.conns, ip)
	} else {
		b.conns[ip]--
	}
}

// BlockedClients lists clients that are temporarily blocked by a rate limit.
func (b *Backend) BlockedClients() map[string]time.Time { return b.blocks.Active(b.now()) }

// UnblockClient lifts a temporary block.
func (b *Backend) UnblockClient(name string) { b.blocks.Clear(name) }

// NewBackend creates the SMTP backend.
func NewBackend(cfg Config, reg Registry, snd Sender, rec Recorder) *Backend {
	cfg.defaults()
	b := &Backend{cfg: cfg, registry: reg, sender: snd, rec: rec,
		limiter: ratelimit.New(cfg.MaxAuthFailures, cfg.AuthFailWindow),
		counts:  ratelimit.NewCounter(), blocks: ratelimit.NewBlocks(), conns: map[netip.Addr]int{}, now: time.Now}
	b.rt, _ = reg.(Runtime)
	return b
}

// ConfigureServer applies the relay's limits to an smtp.Server.
func (b *Backend) ConfigureServer(s *smtp.Server) {
	s.Backend = b
	s.Domain = b.cfg.Hostname
	s.MaxMessageBytes = hardMessageCeiling
	s.MaxRecipients = b.cfg.MaxRecipients
	s.ReadTimeout = 2 * time.Minute
	s.WriteTimeout = 2 * time.Minute
	s.AllowInsecureAuth = false // credentials only after STARTTLS
}

func (b *Backend) record(e Event) {
	if b.rec != nil {
		e.Time = b.now()
		b.rec.Record(e)
	}
}

// ForLegacy returns the backend for the optional listener without encryption.
// Only devices whose rules allow it (TLS.AllowPlain) can sign in there.
func (b *Backend) ForLegacy() smtp.Backend { return legacyBackend{b} }

type legacyBackend struct{ b *Backend }

func (l legacyBackend) NewSession(c *smtp.Conn) (smtp.Session, error) { return l.b.newSession(c, true) }

// NewSession is called for each new connection.
func (b *Backend) NewSession(c *smtp.Conn) (smtp.Session, error) { return b.newSession(c, false) }

func (b *Backend) newSession(c *smtp.Conn, legacy bool) (smtp.Session, error) {
	ip := remoteIP(c.Conn().RemoteAddr())
	if !ip.IsValid() || !b.registry.IPKnown(ip) {
		err := &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Access denied"}
		b.record(Event{RemoteIP: ip, Reason: ReasonIPNotAllowed, SMTPCode: err.Code})
		return nil, err
	}
	if b.rt != nil && b.rt.Paused() {
		err := &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 3, 2}, Message: "Service temporarily paused by the administrator, try again later"}
		b.record(Event{RemoteIP: ip, Reason: ReasonPaused, SMTPCode: err.Code})
		return nil, err
	}
	if !b.acquire(ip, b.limits().MaxConnsPerIP) {
		err := &smtp.SMTPError{Code: 421, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many connections from your address, try again later"}
		b.record(Event{RemoteIP: ip, Reason: ReasonConnLimit, SMTPCode: err.Code})
		return nil, err
	}
	return &session{b: b, ip: ip, counted: true, legacy: legacy}, nil
}

func remoteIP(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		return ta.AddrPort().Addr().Unmap()
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return ap.Addr().Unmap()
	}
	return netip.Addr{}
}

type session struct {
	b      *Backend
	ip     netip.Addr
	client string // set after successful AUTH
	from   string
	sendAs string // sender used towards Microsoft when the rules rewrite it
	rcpts  []string
	pol    policy.Policy
	// counted is true while this session holds a slot of the connection limit.
	counted bool
	// legacy is true on the listener without encryption.
	legacy bool
}

func (s *session) ownDomains() []string {
	if s.b.rt == nil {
		return nil
	}
	return s.b.rt.OwnDomains()
}

// testHit logs a rule violation in test mode; the message is not refused.
func (s *session) testHit(rule, detail string) {
	s.b.record(Event{RemoteIP: s.ip, Client: s.client, Reason: ReasonPolicyTest, SMTPCode: 250, Sender: s.from, Detail: rule + ": " + safe(detail)})
}

func (s *session) AuthMechanisms() []string { return []string{sasl.Plain, sasl.Login} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(_, user, pass string) error { return s.authenticate(user, pass) }), nil
	case sasl.Login:
		return &loginServer{auth: s.authenticate}, nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

func (s *session) authenticate(user, pass string) error {
	if s.b.limiter.Blocked(s.ip, s.b.now()) {
		s.b.record(Event{RemoteIP: s.ip, Reason: ReasonAuthBlocked, SMTPCode: 454, Detail: "user=" + safe(user)})
		return &smtp.SMTPError{Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Too many failed attempts, try again later"}
	}
	name, err := s.b.registry.Authenticate(s.ip, user, pass)
	if err != nil {
		s.b.limiter.Fail(s.ip, s.b.now())
		reason := ReasonBadPassword
		switch {
		case errors.Is(err, ErrUnknownUser):
			reason = ReasonUnknownUser
		case errors.Is(err, ErrWrongIP):
			reason = ReasonWrongIP
		}
		s.b.record(Event{RemoteIP: s.ip, Client: name, Reason: reason, SMTPCode: 535, Detail: "user=" + safe(user)})
		return &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Authentication credentials invalid"}
	}
	var pol policy.Policy
	if s.b.rt != nil {
		pol = s.b.rt.ClientPolicy(name)
	}
	if s.legacy && !pol.TLS.AllowPlain {
		s.b.record(Event{RemoteIP: s.ip, Client: name, Reason: ReasonTLSRequired, SMTPCode: 538, Detail: "user=" + safe(user)})
		return &smtp.SMTPError{Code: 538, EnhancedCode: smtp.EnhancedCode{5, 7, 11}, Message: "Encryption required: this device may not sign in without TLS"}
	}
	s.b.limiter.Reset(s.ip)
	s.client = name
	s.pol = pol
	return nil
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.client == "" {
		s.b.record(Event{RemoteIP: s.ip, Reason: ReasonAuthRequired, SMTPCode: 530})
		return &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Authentication required"}
	}
	from = strings.ToLower(strings.TrimSpace(from))
	if from == "" {
		s.b.record(Event{RemoteIP: s.ip, Client: s.client, Reason: ReasonNoSender, SMTPCode: 550})
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 7}, Message: "Empty sender is not accepted"}
	}
	s.from, s.sendAs = from, ""
	if s.b.rt != nil && s.b.rt.Paused() {
		s.b.record(Event{RemoteIP: s.ip, Client: s.client, Reason: ReasonPaused, SMTPCode: 454})
		return &smtp.SMTPError{Code: 454, EnhancedCode: smtp.EnhancedCode{4, 3, 2}, Message: "Service temporarily paused by the administrator, try again later"}
	}
	if until := s.b.blocks.Until(s.client, s.b.now()); !until.IsZero() {
		s.b.record(Event{RemoteIP: s.ip, Client: s.client, Reason: ReasonClientBlocked, SMTPCode: 454, Detail: "until " + until.Local().Format("15:04")})
		return &smtp.SMTPError{Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "This device is temporarily blocked, try again later"}
	}
	switch v, to := s.pol.CheckSender(from); v {
	case policy.Refused:
		s.b.record(Event{RemoteIP: s.ip, Client: s.client, Reason: ReasonSenderNotAllowed, SMTPCode: 550, Sender: from})
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sender address not allowed for this device"}
	case policy.WouldFail:
		s.testHit("sender_not_allowed", from)
	case policy.Rewritten:
		s.sendAs = to
	}
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	to = strings.ToLower(strings.TrimSpace(to))
	switch s.pol.CheckRecipient(to, s.ownDomains()) {
	case policy.Refused:
		s.b.record(Event{RemoteIP: s.ip, Client: s.client, Reason: ReasonRcptNotAllowed, SMTPCode: 550, Sender: s.from, Detail: "to=" + safe(to)})
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Recipient not allowed for this device"}
	case policy.WouldFail:
		s.testHit("rcpt_not_allowed", to)
	}
	switch s.pol.CheckRecipientCount(len(s.rcpts) + 1) {
	case policy.Refused:
		s.b.record(Event{RemoteIP: s.ip, Client: s.client, Reason: ReasonLimitExceeded, SMTPCode: 452, Sender: s.from, Detail: "too many recipients"})
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients for this device"}
	case policy.WouldFail:
		s.testHit("limit_exceeded", "too many recipients")
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Reset() { s.from, s.sendAs, s.rcpts = "", "", nil }

func (s *session) Logout() error {
	if s.counted {
		s.counted = false
		s.b.release(s.ip)
	}
	return nil
}

func (s *session) Data(r io.Reader) error {
	ev := Event{RemoteIP: s.ip, Client: s.client, Sender: s.from, Recipients: len(s.rcpts)}
	fail := func(reason Reason, e *smtp.SMTPError, detail string) error {
		ev.Reason, ev.SMTPCode, ev.Detail = reason, e.Code, detail
		s.b.record(ev)
		return e
	}
	if len(s.rcpts) == 0 {
		return fail(ReasonNoRecipients, &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 5, 1}, Message: "No recipients"}, "")
	}
	limit := s.b.limits().MaxMessageBytes
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	ev.Bytes = len(data)
	if err == nil && int64(len(data)) > limit {
		return fail(ReasonTooLarge, &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too large"}, "")
	}
	if err != nil {
		if errors.Is(err, smtp.ErrDataTooLarge) {
			return fail(ReasonTooLarge, &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too large"}, "")
		}
		return fail(ReasonMessageReadFail, &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 2}, Message: "Could not read message"}, err.Error())
	}
	switch s.pol.CheckSize(len(data)) {
	case policy.Refused:
		return fail(ReasonLimitExceeded, &smtp.SMTPError{Code: 552, EnhancedCode: smtp.EnhancedCode{5, 3, 4}, Message: "Message too large for this device"}, "size limit of this device")
	case policy.WouldFail:
		s.testHit("limit_exceeded", "message size")
	}
	if s.pol.Attach.Mode.Active() {
		switch v, name := s.pol.CheckAttachments(policy.AttachmentNames(data)); v {
		case policy.Refused:
			return fail(ReasonAttachment, &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Attachment type not allowed for this device"}, "file: "+safe(name))
		case policy.WouldFail:
			s.testHit("attachment_not_allowed", name)
		}
	}
	hour, day := s.b.counts.Counts(s.client, s.b.now())
	switch s.pol.CheckRate(hour, day) {
	case policy.Refused:
		if d := s.pol.BlockDuration(); d > 0 {
			s.b.blocks.Block(s.client, s.b.now(), time.Duration(d)*time.Minute)
			return fail(ReasonClientBlocked, &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 1}, Message: "Sending limit reached, this device is blocked for a while"},
				fmt.Sprintf("rate limit hit (%d/hour, %d/day); blocked %d min", hour, day, d))
		}
		return fail(ReasonLimitExceeded, &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 7, 1}, Message: "Sending limit reached, try again later"},
			fmt.Sprintf("rate limit (%d/hour, %d/day)", hour, day))
	case policy.WouldFail:
		s.testHit("limit_exceeded", fmt.Sprintf("rate (%d/hour, %d/day)", hour, day))
	}
	s.b.counts.Add(s.client, s.b.now())

	edit := policy.HeaderEdit{From: s.sendAs, ReplyTo: s.pol.Headers.ReplyTo, SubjectTag: s.pol.Headers.SubjectTag}
	data = policy.ApplyHeaders(data, edit)
	sender := s.from
	if s.sendAs != "" {
		sender = s.sendAs
		ev.Detail = "sender rewritten to " + s.sendAs
	}
	rcpts := s.rcpts
	for _, b := range s.pol.Headers.Bcc { // blind copies configured for this device
		if b = strings.ToLower(strings.TrimSpace(b)); b != "" && !containsString(rcpts, b) {
			rcpts = append(append([]string{}, rcpts...), b)
		}
	}
	data = ensureEnvelopeRecipients(data, rcpts)

	ctx, cancel := context.WithTimeout(context.Background(), s.b.cfg.SendTimeout)
	defer cancel()
	if err := s.b.sender.SendMIME(ctx, sender, data); err != nil {
		reason, serr := mapSendError(err)
		return fail(reason, serr, err.Error())
	}
	ev.Reason, ev.SMTPCode = ReasonSent, 250
	s.b.record(ev)
	return nil
}

func containsString(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

// ClassifySendError returns the log reason for a Microsoft send/connection failure.
// Other packages (the web UI) use it so UI-triggered failures show up in the event log too.
func ClassifySendError(err error) Reason {
	reason, _ := mapSendError(err)
	return reason
}

// mapSendError translates a Graph failure into an SMTP reply and a log reason.
// The reply text is generic on purpose; the detail goes to the event log only.
func mapSendError(err error) (Reason, *smtp.SMTPError) {
	var se statusError
	status := 0
	if errors.As(err, &se) {
		status = se.HTTPStatus()
		if se.Temporary() {
			return ReasonGraphTemporary, &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 1}, Message: "Temporary failure, try again later"}
		}
	}
	switch status {
	case 401:
		return ReasonGraphAuth, &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 3}, Message: "Relay is not authorized by Microsoft 365, contact the administrator"}
	case 403:
		return ReasonGraphForbidden, &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sender not permitted by Microsoft 365"}
	case 404:
		return ReasonGraphNotFound, &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 1}, Message: "Sender mailbox not found"}
	case 400:
		return ReasonGraphRejected, &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 6, 0}, Message: "Message rejected by Microsoft 365"}
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &netErr) {
		return ReasonGraphTemporary, &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 1}, Message: "Temporary failure, try again later"}
	}
	return ReasonInternal, &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 0, 0}, Message: "Message could not be delivered"}
}

// ensureEnvelopeRecipients makes sure every RCPT TO address appears in a
// To, Cc or Bcc header, because Graph delivers to the addresses found in the
// MIME headers, not to the SMTP envelope. Missing addresses are added as a
// Bcc header. If the message already has a Bcc header it is left untouched.
// NOTE: whether Graph honours a Bcc header in MIME input must be verified
// against a real tenant (see docs/entra-setup.md, test plan).
func ensureEnvelopeRecipients(data []byte, rcpts []string) []byte {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return data
	}
	if msg.Header.Get("Bcc") != "" {
		return data
	}
	seen := map[string]bool{}
	for _, h := range []string{"To", "Cc"} {
		list, err := msg.Header.AddressList(h)
		if err != nil {
			continue
		}
		for _, a := range list {
			seen[strings.ToLower(a.Address)] = true
		}
	}
	var missing []string
	for _, r := range rcpts {
		if !seen[r] {
			missing = append(missing, r)
		}
	}
	if len(missing) == 0 {
		return data
	}
	out := make([]byte, 0, len(data)+64)
	out = append(out, "Bcc: "+strings.Join(missing, ", ")+"\r\n"...)
	return append(out, data...)
}

// safe strips control characters and limits length of user-supplied log text.
func safe(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}
