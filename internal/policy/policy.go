// Package policy holds the optional per-client rules of the relay (allowed
// senders, allowed recipients, limits, header changes) and the pure functions
// that evaluate them. Everything defaults to "off": a zero Policy changes
// nothing about how a client behaves.
package policy

import (
	"encoding/json"
	"net/mail"
	"strings"
)

// Mode says what happens when a rule is violated.
type Mode string

const (
	Off     Mode = ""        // rule not active
	Log     Mode = "log"     // test mode: violations are logged, never blocked
	Enforce Mode = "enforce" // violations are refused (or rewritten)
)

// Valid reports whether m is one of the known modes.
func (m Mode) Valid() bool { return m == Off || m == Log || m == Enforce }

// Active reports whether the rule is evaluated at all.
func (m Mode) Active() bool { return m == Log || m == Enforce }

// Sender actions.
const (
	Reject  = "reject"  // refuse a sender that is not allowed
	Rewrite = "rewrite" // change the From header (never refuses)
)

// SenderRule limits which sender addresses a client may use.
type SenderRule struct {
	Mode      Mode     `json:"mode,omitempty"`
	Action    string   `json:"action,omitempty"`     // reject (default) or rewrite
	Allowed   []string `json:"allowed,omitempty"`    // addresses, "@domain" or "*@domain"
	RewriteTo string   `json:"rewrite_to,omitempty"` // the sender to use when Action is rewrite
}

// Recipient scopes.
const (
	ScopeInternal = "internal" // only the relay's own domains (global setting)
	ScopeList     = "list"     // only the listed addresses and domains
)

// RcptRule limits which recipients a client may mail.
type RcptRule struct {
	Mode    Mode     `json:"mode,omitempty"`
	Scope   string   `json:"scope,omitempty"`   // internal (default) or list
	Allowed []string `json:"allowed,omitempty"` // addresses, "@domain" or "*@domain"; with scope internal also extra allowed ones
}

// Limit actions.
const (
	LimitReject = "reject" // answer 451 for the message that exceeds the limit
	LimitBlock  = "block"  // block the whole client for BlockMinutes
)

// LimitRule caps the volume of a client. Zero means "no limit" for that value.
type LimitRule struct {
	Mode         Mode   `json:"mode,omitempty"`
	PerHour      int    `json:"per_hour,omitempty"`
	PerDay       int    `json:"per_day,omitempty"`
	MaxRcpts     int    `json:"max_rcpts,omitempty"`
	MaxSizeMB    int    `json:"max_size_mb,omitempty"`
	Action       string `json:"action,omitempty"`        // reject (default) or block
	BlockMinutes int    `json:"block_minutes,omitempty"` // for Action block; default 30
}

// Headers are optional changes to every message of a client. They are not
// "rules": a non-empty value is simply applied.
type Headers struct {
	ReplyTo    string   `json:"reply_to,omitempty"`
	SubjectTag string   `json:"subject_tag,omitempty"`
	Bcc        []string `json:"bcc,omitempty"` // every message is also delivered (as blind copy) to these addresses
}

// Policy is the complete set of optional rules of one client.
type Policy struct {
	Sender  SenderRule `json:"sender,omitzero"`
	Rcpt    RcptRule   `json:"rcpt,omitzero"`
	Limits  LimitRule  `json:"limits,omitzero"`
	Headers Headers    `json:"headers,omitzero"`
	Attach  AttachRule `json:"attach,omitzero"`
	TLS     TLSRule    `json:"tls,omitzero"`
}

// TLSRule is how a device may connect. By default a device must use TLS
// (STARTTLS) before it can sign in. Older devices get an exception here.
type TLSRule struct {
	// MinVersion overrides the relay-wide minimum TLS version for this device
	// ("1.0", "1.1", "1.2" or "1.3"); empty means the relay-wide setting.
	MinVersion string `json:"min_version,omitempty"`
	// AllowPlain lets the device sign in on the optional "no encryption"
	// listener. Only for devices that cannot do TLS at all.
	AllowPlain bool `json:"allow_plain,omitempty"`
}

// ValidTLSVersion reports whether v is a version the UI offers.
func ValidTLSVersion(v string) bool {
	switch v {
	case "", "1.0", "1.1", "1.2", "1.3":
		return true
	}
	return false
}

// Parse decodes a stored policy. Empty or damaged input yields the zero
// Policy (all rules off): a corrupt value must never block a device.
func Parse(s string) Policy {
	var p Policy
	if strings.TrimSpace(s) == "" {
		return p
	}
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return Policy{}
	}
	return p
}

// JSON encodes the policy for storage.
func (p Policy) JSON() string {
	b, err := json.Marshal(p)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// Validate checks the values a user entered.
func (p Policy) Validate() error {
	for _, m := range []Mode{p.Sender.Mode, p.Rcpt.Mode, p.Limits.Mode, p.Attach.Mode} {
		if !m.Valid() {
			return errInvalid("unknown mode " + string(m))
		}
	}
	if k := p.Attach.Kind; k != "" && k != AttachBlock && k != AttachAllow {
		return errInvalid("unknown attachment kind")
	}
	if p.Attach.Mode.Active() && len(p.Attach.Extensions) == 0 {
		return errInvalid("list at least one file extension for the attachment rule")
	}
	for _, e := range p.Attach.Extensions {
		if !validExtension(e) {
			return errInvalid("invalid file extension " + e + " (use letters and digits only, like pdf)")
		}
	}
	if !ValidTLSVersion(p.TLS.MinVersion) {
		return errInvalid("unknown TLS version")
	}
	if len(p.Headers.Bcc) > 10 {
		return errInvalid("at most 10 blind-copy addresses")
	}
	for _, b := range p.Headers.Bcc {
		if _, ok := PlainAddress(b); !ok {
			return errInvalid("invalid blind-copy address " + b)
		}
	}
	if a := p.Sender.Action; a != "" && a != Reject && a != Rewrite {
		return errInvalid("unknown sender action")
	}
	if p.Sender.Mode.Active() && p.Sender.Action == Rewrite {
		if _, ok := PlainAddress(p.Sender.RewriteTo); !ok {
			return errInvalid("the address to rewrite the sender to is not a valid e-mail address")
		}
	}
	if p.Sender.Mode.Active() && p.Sender.Action != Rewrite && len(p.Sender.Allowed) == 0 {
		return errInvalid("list at least one allowed sender")
	}
	if s := p.Rcpt.Scope; s != "" && s != ScopeInternal && s != ScopeList {
		return errInvalid("unknown recipient scope")
	}
	if p.Rcpt.Mode.Active() && p.Rcpt.Scope == ScopeList && len(p.Rcpt.Allowed) == 0 {
		return errInvalid("list at least one allowed recipient or domain")
	}
	for _, list := range [][]string{p.Sender.Allowed, p.Rcpt.Allowed} {
		for _, e := range list {
			if !validPattern(e) {
				return errInvalid("invalid address or domain " + e)
			}
		}
	}
	if a := p.Limits.Action; a != "" && a != LimitReject && a != LimitBlock {
		return errInvalid("unknown limit action")
	}
	for _, n := range []int{p.Limits.PerHour, p.Limits.PerDay, p.Limits.MaxRcpts, p.Limits.MaxSizeMB, p.Limits.BlockMinutes} {
		if n < 0 || n > 1_000_000 {
			return errInvalid("limits must be between 0 and 1000000")
		}
	}
	if strings.ContainsAny(p.Headers.ReplyTo, "\r\n") || strings.ContainsAny(p.Headers.SubjectTag, "\r\n") {
		return errInvalid("line breaks are not allowed in headers")
	}
	if p.Headers.ReplyTo != "" {
		if _, ok := PlainAddress(p.Headers.ReplyTo); !ok {
			return errInvalid("the Reply-To address is not a valid e-mail address")
		}
	}
	if len(p.Headers.SubjectTag) > 40 {
		return errInvalid("the subject tag is too long (max 40 characters)")
	}
	return nil
}

type errInvalid string

func (e errInvalid) Error() string { return string(e) }

// PlainAddress returns the lower-cased address of a plain "user@host" string
// (no display name, no angle brackets).
func PlainAddress(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "\r\n<> ,;") {
		return "", false
	}
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || a.Address == "" {
		return "", false
	}
	return strings.ToLower(a.Address), true
}

func validPattern(e string) bool {
	e = strings.ToLower(strings.TrimSpace(e))
	if strings.HasPrefix(e, "*@") {
		e = e[1:]
	}
	if strings.HasPrefix(e, "@") {
		d := e[1:]
		return d != "" && !strings.ContainsAny(d, " @,;<>\r\n") && strings.Contains(d, ".")
	}
	_, ok := PlainAddress(e)
	return ok
}

// matches reports whether address addr is covered by one entry of list.
func matches(list []string, addr string) bool {
	addr = strings.ToLower(strings.TrimSpace(addr))
	at := strings.LastIndexByte(addr, '@')
	for _, e := range list {
		e = strings.ToLower(strings.TrimSpace(e))
		switch {
		case e == "":
		case strings.HasPrefix(e, "*@"):
			if at >= 0 && addr[at:] == e[1:] {
				return true
			}
		case strings.HasPrefix(e, "@"):
			if at >= 0 && addr[at:] == e {
				return true
			}
		case e == addr:
			return true
		}
	}
	return false
}

// domainList turns bare domains ("contoso.com") into "@contoso.com" entries.
func domainList(domains []string) []string {
	out := make([]string, 0, len(domains))
	for _, d := range domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !strings.HasPrefix(d, "@") {
			d = "@" + d
		}
		out = append(out, d)
	}
	return out
}

// Verdict is the result of evaluating one rule.
type Verdict int

const (
	Allowed   Verdict = iota // nothing to do
	WouldFail                // test mode: violation, but let it through
	Refused                  // enforce mode: refuse
	Rewritten                // enforce mode: the sender is rewritten instead of refused
)

func verdict(m Mode, violated bool) Verdict {
	switch {
	case !violated || !m.Active():
		return Allowed
	case m == Log:
		return WouldFail
	}
	return Refused
}

// CheckSender evaluates the sender rule for one envelope sender. For
// Rewritten, the second result is the address to use.
func (p Policy) CheckSender(from string) (Verdict, string) {
	r := p.Sender
	if !r.Mode.Active() {
		return Allowed, ""
	}
	allowed := append([]string{}, r.Allowed...)
	if r.RewriteTo != "" {
		allowed = append(allowed, r.RewriteTo)
	}
	ok := matches(allowed, from)
	if ok {
		return Allowed, ""
	}
	if r.Action == Rewrite {
		if r.Mode == Log {
			return WouldFail, r.RewriteTo
		}
		return Rewritten, r.RewriteTo
	}
	return verdict(r.Mode, true), ""
}

// CheckRecipient evaluates the recipient rule for one address. ownDomains is
// the relay's global list of internal domains.
func (p Policy) CheckRecipient(rcpt string, ownDomains []string) Verdict {
	r := p.Rcpt
	if !r.Mode.Active() {
		return Allowed
	}
	ok := matches(r.Allowed, rcpt)
	if !ok && r.Scope != ScopeList {
		ok = matches(domainList(ownDomains), rcpt)
	}
	return verdict(r.Mode, !ok)
}

// CheckRecipientCount evaluates MaxRcpts.
func (p Policy) CheckRecipientCount(n int) Verdict {
	l := p.Limits
	return verdict(l.Mode, l.MaxRcpts > 0 && n > l.MaxRcpts)
}

// CheckSize evaluates MaxSizeMB for a message of n bytes.
func (p Policy) CheckSize(n int) Verdict {
	l := p.Limits
	return verdict(l.Mode, l.MaxSizeMB > 0 && int64(n) > int64(l.MaxSizeMB)<<20)
}

// CheckRate evaluates the hourly and daily message limits, given how many
// messages the client already sent in the last hour and day.
func (p Policy) CheckRate(lastHour, lastDay int) Verdict {
	l := p.Limits
	over := (l.PerHour > 0 && lastHour >= l.PerHour) || (l.PerDay > 0 && lastDay >= l.PerDay)
	return verdict(l.Mode, over)
}

// BlockDuration returns how long a client is blocked when the rate limit is
// hit with Action block, or 0 when the action is "reject".
func (p Policy) BlockDuration() int {
	if p.Limits.Action != LimitBlock {
		return 0
	}
	if p.Limits.BlockMinutes > 0 {
		return p.Limits.BlockMinutes
	}
	return 30
}

// Preset names offered when adding a client.
const (
	PresetBasic       = "basic"
	PresetRecommended = "recommended"
	PresetStrict      = "strict"
)

// FromPreset builds a policy. senderMailbox is optional: when given, the
// recommended preset rewrites every sender to it (never refusing a printer)
// and the strict preset only allows it.
func FromPreset(name, senderMailbox string) Policy {
	senderMailbox, _ = PlainAddress(senderMailbox)
	var p Policy
	switch name {
	case PresetRecommended:
		p.Limits = LimitRule{Mode: Enforce, PerHour: 120, PerDay: 600, MaxRcpts: 25, Action: LimitReject}
		p.Rcpt = RcptRule{Mode: Log, Scope: ScopeInternal}
		p.Attach = AttachRule{Mode: Log, Kind: AttachBlock, Extensions: DangerousExtensions}
		if senderMailbox != "" {
			p.Sender = SenderRule{Mode: Enforce, Action: Rewrite, RewriteTo: senderMailbox}
		}
	case PresetStrict:
		p.Limits = LimitRule{Mode: Enforce, PerHour: 30, PerDay: 150, MaxRcpts: 10, MaxSizeMB: 20, Action: LimitBlock, BlockMinutes: 30}
		p.Rcpt = RcptRule{Mode: Enforce, Scope: ScopeInternal}
		p.Attach = AttachRule{Mode: Enforce, Kind: AttachBlock, Extensions: DangerousExtensions}
		if senderMailbox != "" {
			p.Sender = SenderRule{Mode: Enforce, Action: Reject, Allowed: []string{senderMailbox}}
		}
	}
	return p
}
