package notify

import (
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kgooris/office-smtprelay/internal/relay"
)

type fakeStore struct {
	mu  sync.Mutex
	m   map[string]string
	exp time.Time
}

func (f *fakeStore) Setting(k string) (string, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.m[k]
	return v, ok, nil
}
func (f *fakeStore) SetSetting(k, v string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[k] = v
	return nil
}
func (f *fakeStore) SecretExpires() (time.Time, bool) { return f.exp, !f.exp.IsZero() }

type fakeSender struct {
	mu   sync.Mutex
	sent []string
	from []string
	err  error
}

func (f *fakeSender) SendMIME(_ context.Context, from string, mime []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.from = append(f.from, from)
	f.sent = append(f.sent, string(mime))
	return nil
}
func (f *fakeSender) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sent) }

func setup(t *testing.T) (*Notifier, *fakeStore, *fakeSender, *time.Time) {
	t.Helper()
	st := &fakeStore{m: map[string]string{}}
	snd := &fakeSender{}
	n := New(st, snd, "en", log.New(io.Discard, "", 0))
	now := time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)
	n.now = func() time.Time { return now }
	return n, st, snd, &now
}

func enable(t *testing.T, n *Notifier) {
	t.Helper()
	if err := n.Save(Settings{Enabled: true, To: "Admin@GBK.be", From: "printer@gbk.be",
		Kinds: map[string]bool{KindMSError: true, KindSecretExpiry: true, KindClientBlock: true, KindPaused: true}}); err != nil {
		t.Fatal(err)
	}
}

func TestOffByDefault(t *testing.T) {
	n, _, snd, _ := setup(t)
	n.Observe(relay.Event{Reason: relay.ReasonGraphForbidden})
	n.NotifyPaused(true)
	n.Wait()
	if snd.count() != 0 {
		t.Fatal("nothing may be sent until alerts are switched on")
	}
	if s := n.Settings(); s.Enabled || s.Wants(KindMSError) {
		t.Error("defaults must be off")
	}
}

func TestSaveValidation(t *testing.T) {
	n, _, _, _ := setup(t)
	if err := n.Save(Settings{Enabled: true, To: "not an address", From: "a@b.c"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("err = %v", err)
	}
	if err := n.Save(Settings{Enabled: false, To: "", From: ""}); err != nil {
		t.Errorf("switching off needs no addresses: %v", err)
	}
	enable(t, n)
	if s := n.Settings(); s.To != "admin@gbk.be" || !s.Wants(KindPaused) {
		t.Errorf("settings = %#v", s)
	}
}

func TestMicrosoftErrorAlertIsDebounced(t *testing.T) {
	n, _, snd, now := setup(t)
	enable(t, n)
	ev := relay.Event{Client: "printer", Reason: relay.ReasonGraphForbidden, Detail: "graph: HTTP 403 ErrorAccessDenied"}
	n.Observe(ev)
	n.Observe(ev)
	n.Observe(ev)
	n.Wait()
	if snd.count() != 1 {
		t.Fatalf("sent %d alerts for a burst, want 1", snd.count())
	}
	m := snd.sent[0]
	if snd.from[0] != "printer@gbk.be" || !strings.Contains(m, "To: admin@gbk.be") || !strings.Contains(m, "Auto-Submitted: auto-generated") {
		t.Errorf("message:\n%s", m)
	}
	*now = now.Add(7 * time.Hour)
	n.Observe(ev)
	n.Wait()
	if snd.count() != 2 {
		t.Error("after the debounce time a new alert is allowed")
	}
}

func TestUITestsAndMinorReasonsAreNotAlerts(t *testing.T) {
	n, _, snd, _ := setup(t)
	enable(t, n)
	n.Observe(relay.Event{Client: "web UI", Reason: relay.ReasonGraphForbidden})
	n.Observe(relay.Event{Client: "printer", Reason: relay.ReasonGraphTemporary})
	n.Observe(relay.Event{Client: "printer", Reason: relay.ReasonBadPassword})
	n.Wait()
	if snd.count() != 0 {
		t.Errorf("sent %d alerts, want 0", snd.count())
	}
}

func TestBlockedAndPausedAlerts(t *testing.T) {
	n, _, snd, _ := setup(t)
	enable(t, n)
	n.Observe(relay.Event{Client: "Printer 1", Reason: relay.ReasonClientBlocked, Detail: "rate limit hit"})
	n.NotifyPaused(true)
	n.NotifyPaused(false)
	n.Wait()
	if snd.count() != 3 {
		t.Fatalf("sent %d, want 3", snd.count())
	}
	all := strings.Join(snd.sent, "\n")
	if !strings.Contains(all, "Subject: [office-smtprelay] Device blocked: Printer 1") {
		t.Errorf("blocked alert missing:\n%s", all)
	}
	// a switched-off kind stays silent
	s := n.Settings()
	s.Kinds[KindPaused] = false
	_ = n.Save(s)
	n.NotifyPaused(true)
	n.Wait()
	if snd.count() != 3 {
		t.Error("paused alerts are switched off")
	}
}

func TestSecretExpiryThresholds(t *testing.T) {
	n, st, snd, now := setup(t)
	enable(t, n)
	st.exp = now.Add(40 * 24 * time.Hour)
	n.CheckExpiry()
	if snd.count() != 0 {
		t.Fatal("no alert 40 days before")
	}
	*now = now.Add(11 * 24 * time.Hour) // 29 days left
	n.CheckExpiry()
	n.CheckExpiry()
	if snd.count() != 1 {
		t.Fatalf("30-day alert sent %d times, want once", snd.count())
	}
	*now = now.Add(21 * 24 * time.Hour) // 8 days left: still the 30 threshold... then 7
	n.CheckExpiry()
	if snd.count() != 1 {
		t.Error("no new alert between thresholds")
	}
	*now = now.Add(2 * 24 * time.Hour) // 6 days left
	n.CheckExpiry()
	if snd.count() != 2 {
		t.Errorf("7-day alert expected, sent %d", snd.count())
	}
	st.exp = now.Add(300 * 24 * time.Hour) // a new secret was entered
	n.CheckExpiry()
	if snd.count() != 2 {
		t.Error("a renewed secret needs no alert")
	}
}

func TestSendTestReportsErrors(t *testing.T) {
	n, _, snd, _ := setup(t)
	if err := n.SendTest(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Errorf("without settings: %v", err)
	}
	enable(t, n)
	if err := n.SendTest(context.Background()); err != nil || snd.count() != 1 {
		t.Fatalf("test alert: %v", err)
	}
	snd.err = errors.New("graph: HTTP 403")
	if err := n.SendTest(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("the Microsoft error must be returned, got %v", err)
	}
}

func TestDutchText(t *testing.T) {
	n, _, snd, _ := setup(t)
	n.lang = "nl"
	enable(t, n)
	n.NotifyPaused(true)
	n.Wait()
	if !strings.Contains(snd.sent[0], "Subject: [office-smtprelay] Verzending gepauzeerd") {
		t.Errorf("message:\n%s", snd.sent[0])
	}
}
