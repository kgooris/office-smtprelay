package web

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/kgooris/office-smtprelay/internal/notify"
)

// Notifier is the alert service the UI configures.
type Notifier interface {
	Settings() notify.Settings
	Save(notify.Settings) error
	SendTest(ctx context.Context) error
	NotifyPaused(paused bool)
}

type notifyData struct {
	Enabled bool
	To      string
	From    string
	Kinds   map[string]bool
	All     []string
}

func (s *Server) notifyView(r *http.Request, sd *session, st notify.Settings) view {
	v := view{Nav: true, Active: "notifications", CSRF: sd.csrf,
		Data: notifyData{Enabled: st.Enabled, To: st.To, From: st.From, Kinds: st.Kinds, All: notify.AllKinds}}
	s.flashFromQuery(r, &v)
	return v
}

func (s *Server) notificationsPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	s.render(w, r, http.StatusOK, "notifications", s.notifyView(r, sd, s.d.Notifier.Settings()))
}

func (s *Server) notificationsSave(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	st := notify.Settings{Enabled: r.PostFormValue("enabled") == "1", To: r.PostFormValue("to"), From: r.PostFormValue("from"), Kinds: map[string]bool{}}
	for _, k := range notify.AllKinds {
		st.Kinds[k] = r.PostFormValue("kind_"+k) == "1"
	}
	if err := s.d.Notifier.Save(st); err != nil {
		v := s.notifyView(r, sd, st)
		if errors.Is(err, notify.ErrInvalid) {
			v.Flash, v.FlashKind = s.tr(r, "notify.invalid"), "err"
			s.render(w, r, http.StatusBadRequest, "notifications", v)
			return
		}
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/notifications?ok=notify_saved", http.StatusSeeOther)
}

func (s *Server) notificationsTest(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	v := s.notifyView(r, sd, s.d.Notifier.Settings())
	if err := s.d.Notifier.SendTest(ctx); err != nil {
		if !errors.Is(err, notify.ErrInvalid) {
			s.recordMSFailure(r, "", "notification test", err)
		}
		v.Flash, v.FlashKind = s.tr(r, "notify.test_failed", err.Error()), "err"
	} else {
		v.Flash, v.FlashKind = s.tr(r, "notify.test_ok"), "ok"
	}
	s.render(w, r, http.StatusOK, "notifications", v)
}
