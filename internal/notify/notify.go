// Package notify sends short alert mails to the administrator (Microsoft
// errors, secret about to expire, a device blocked, sending paused). The mails
// go through the relay's own Microsoft 365 connection. Every kind of alert can
// be switched off and is debounced, so a failing connection cannot flood the
// mailbox.
package notify

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"mime"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/kgooris/office-smtprelay/internal/relay"
)

// Setting keys.
const (
	keyEnabled = "notify.enabled"
	keyTo      = "notify.to"
	keyFrom    = "notify.from"
	keyEvents  = "notify.events"
	keyExpiry  = "notify.expiry_sent"
)

// Alert kinds that can be switched on or off.
const (
	KindMSError      = "ms_error"
	KindSecretExpiry = "secret_expiry"
	KindClientBlock  = "client_blocked"
	KindPaused       = "paused"
)

// AllKinds lists every kind in the order the UI shows them.
var AllKinds = []string{KindMSError, KindSecretExpiry, KindClientBlock, KindPaused}

// Settings is the administrator's choice of alerts.
type Settings struct {
	Enabled bool
	To      string
	From    string // sender mailbox in the Microsoft 365 tenant
	Kinds   map[string]bool
}

// Wants reports whether alerts of this kind are switched on.
func (s Settings) Wants(kind string) bool {
	return s.Enabled && s.To != "" && s.From != "" && s.Kinds[kind]
}

// Store is the part of the database the notifier uses.
type Store interface {
	Setting(key string) (string, bool, error)
	SetSetting(key, value string, secret bool) error
	SecretExpires() (time.Time, bool)
}

// Sender delivers a MIME message as the given mailbox.
type Sender interface {
	SendMIME(ctx context.Context, sender string, mime []byte) error
}

// Notifier sends the alerts.
type Notifier struct {
	st   Store
	snd  Sender
	lang string
	// LangFn, when set, gives the current language of the alert texts.
	LangFn func() string
	log    *log.Logger
	now    func() time.Time

	mu   sync.Mutex
	last map[string]time.Time
	wg   sync.WaitGroup
}

// New creates a notifier. lang is "en" or "nl" and selects the mail text.
func New(st Store, snd Sender, lang string, lg *log.Logger) *Notifier {
	if lg == nil {
		lg = log.Default()
	}
	return &Notifier{st: st, snd: snd, lang: lang, log: lg, now: time.Now, last: map[string]time.Time{}}
}

// Settings returns the stored settings (alerts off when nothing was saved).
func (n *Notifier) Settings() Settings {
	s := Settings{Kinds: map[string]bool{}}
	if v, ok, _ := n.st.Setting(keyEnabled); ok && v == "1" {
		s.Enabled = true
	}
	s.To, _, _ = n.st.Setting(keyTo)
	s.From, _, _ = n.st.Setting(keyFrom)
	if v, ok, _ := n.st.Setting(keyEvents); ok {
		for _, k := range strings.Split(v, ",") {
			s.Kinds[strings.TrimSpace(k)] = true
		}
	} else { // default once enabled: everything except the noisy "paused" notice
		for _, k := range AllKinds {
			s.Kinds[k] = k != KindPaused
		}
	}
	return s
}

// ErrInvalid is returned by Save for bad addresses.
var ErrInvalid = errors.New("invalid value")

func plain(s string) (string, bool) {
	s = strings.TrimSpace(s)
	a, err := mail.ParseAddress(s)
	if err != nil || a.Name != "" || strings.ContainsAny(s, "\r\n<> ,;") {
		return "", false
	}
	return strings.ToLower(a.Address), true
}

// Save stores the settings after checking the addresses.
func (n *Notifier) Save(s Settings) error {
	to, ok1 := plain(s.To)
	from, ok2 := plain(s.From)
	if s.Enabled && (!ok1 || !ok2) {
		return fmt.Errorf("%w: give a valid recipient and sender mailbox", ErrInvalid)
	}
	if !ok1 {
		to = ""
	}
	if !ok2 {
		from = ""
	}
	var kinds []string
	for _, k := range AllKinds {
		if s.Kinds[k] {
			kinds = append(kinds, k)
		}
	}
	enabled := "0"
	if s.Enabled {
		enabled = "1"
	}
	for k, v := range map[string]string{keyEnabled: enabled, keyTo: to, keyFrom: from, keyEvents: strings.Join(kinds, ",")} {
		if err := n.st.SetSetting(k, v, false); err != nil {
			return err
		}
	}
	return nil
}

// Wait blocks until all alerts that are being sent have finished (for tests and shutdown).
func (n *Notifier) Wait() { n.wg.Wait() }

// debounce reports whether key may fire now and, if so, remembers the time.
func (n *Notifier) debounce(key string, every time.Duration) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	if t, ok := n.last[key]; ok && now.Sub(t) < every {
		return false
	}
	n.last[key] = now
	return true
}

// Observe looks at one relay event and sends an alert when it is one the
// administrator wants to hear about. It never blocks the SMTP session.
func (n *Notifier) Observe(e relay.Event) {
	if e.Client == "web UI" { // tests done from the web UI are not alerts
		return
	}
	switch e.Reason {
	case relay.ReasonGraphAuth, relay.ReasonGraphForbidden, relay.ReasonGraphNotFound, relay.ReasonGraphRejected, relay.ReasonInternal:
		n.fire(KindMSError, "ms:"+string(e.Reason), 6*time.Hour, string(e.Reason), e.Client, e.Detail)
	case relay.ReasonClientBlocked:
		n.fire(KindClientBlock, "blocked:"+e.Client, time.Hour, e.Client, e.Detail, "")
	}
}

// NotifyPaused tells the administrator that sending was paused or resumed.
func (n *Notifier) NotifyPaused(paused bool) {
	key, arg := "paused", "paused"
	if !paused {
		key, arg = "resumed", "resumed"
	}
	n.fire(KindPaused, key, 0, arg, "", "")
}

func (n *Notifier) language() string {
	if n.LangFn != nil {
		if l := n.LangFn(); l != "" {
			return l
		}
	}
	return n.lang
}

func (n *Notifier) fire(kind, key string, every time.Duration, a, b, c string) {
	s := n.Settings()
	if !s.Wants(kind) {
		return
	}
	if every > 0 && !n.debounce(key, every) {
		return
	}
	subject, body := text(n.language(), kind, a, b, c)
	n.wg.Add(1)
	go func() {
		defer n.wg.Done()
		if err := n.send(s, subject, body); err != nil {
			n.log.Printf("notify: could not send %q: %v", subject, err)
		}
	}()
}

func (n *Notifier) send(s Settings, subject, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return n.snd.SendMIME(ctx, s.From, compose(s.From, s.To, subject, body, n.now()))
}

// SendTest sends a test alert immediately (ignoring the on/off switches) and
// returns the error, so the UI can show it.
func (n *Notifier) SendTest(ctx context.Context) error {
	s := n.Settings()
	if s.To == "" || s.From == "" {
		return fmt.Errorf("%w: save a recipient and a sender mailbox first", ErrInvalid)
	}
	subject, body := text(n.language(), "test", "", "", "")
	return n.snd.SendMIME(ctx, s.From, compose(s.From, s.To, subject, body, n.now()))
}

// CheckExpiry sends the "secret expires soon" alert once per threshold
// (30, 7 and 1 days before, and when expired).
func (n *Notifier) CheckExpiry() {
	exp, ok := n.st.SecretExpires()
	if !ok {
		return
	}
	s := n.Settings()
	if !s.Wants(KindSecretExpiry) {
		return
	}
	days := int(exp.Sub(n.now()).Hours() / 24)
	threshold := -1
	for _, t := range []int{30, 7, 1, 0} {
		if days <= t {
			threshold = t
		}
	}
	if threshold < 0 {
		return
	}
	mark := fmt.Sprintf("%d:%d", exp.Unix(), threshold)
	if prev, _, _ := n.st.Setting(keyExpiry); prev != "" {
		var pe int64
		var pt int
		if _, err := fmt.Sscanf(prev, "%d:%d", &pe, &pt); err == nil && pe == exp.Unix() && pt <= threshold {
			return // this threshold (or a closer one) was already reported
		}
	}
	subject, body := text(n.language(), KindSecretExpiry, fmt.Sprint(days), exp.Format("2006-01-02"), "")
	if err := n.send(s, subject, body); err != nil {
		n.log.Printf("notify: could not send %q: %v", subject, err)
		return
	}
	_ = n.st.SetSetting(keyExpiry, mark, false)
}

// ExpiryLoop checks the secret expiry now and every 6 hours until ctx ends.
func (n *Notifier) ExpiryLoop(ctx context.Context) {
	n.CheckExpiry()
	t := time.NewTicker(6 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.CheckExpiry()
		}
	}
}

// Recorder wraps an event recorder so that every event is also shown to the notifier.
type Recorder struct {
	Inner relay.Recorder
	N     *Notifier
}

// Record implements relay.Recorder.
func (r Recorder) Record(e relay.Event) {
	r.Inner.Record(e)
	r.N.Observe(e)
}

func compose(from, to, subject, body string, now time.Time) []byte {
	enc := base64.StdEncoding.EncodeToString([]byte(body))
	var wrapped strings.Builder
	for len(enc) > 76 {
		wrapped.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	wrapped.WriteString(enc + "\r\n")
	return []byte("From: " + from + "\r\nTo: " + to + "\r\nSubject: " + mime.QEncoding.Encode("utf-8", subject) +
		"\r\nDate: " + now.Format(time.RFC1123Z) + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n" +
		"Content-Transfer-Encoding: base64\r\nAuto-Submitted: auto-generated\r\n\r\n" + wrapped.String())
}
