package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/kgooris/office-smtprelay/internal/policy"
	"github.com/kgooris/office-smtprelay/internal/store"
)

// RelayControl is the part of the SMTP backend the UI needs to show and lift
// temporary blocks. It is optional (nil in some tests).
type RelayControl interface {
	BlockedClients() map[string]time.Time
	UnblockClient(name string)
}

// ---- per-client rules --------------------------------------------------------

// editData is what the rules page shows. Lists are joined into text so the
// template can put them straight into a text area.
type editData struct {
	Name, Addr, Username string
	Tab                  string
	Enabled              bool
	LastSeen             time.Time

	SenderMode, SenderAction, SenderAllowed, SenderRewrite string
	RcptMode, RcptScope, RcptAllowed                       string
	LimMode, LimAction                                     string
	LimHour, LimDay, LimRcpts, LimSize, LimBlock           string
	ReplyTo, SubjectTag, Bcc                               string
	AttachMode, AttachKind, AttachExts                     string
	TLSMin                                                 string
	TLSPlain                                               bool
	OwnDomains                                             string
	BlockedUntil                                           time.Time
}

func listText(l []string) string { return strings.Join(l, "\n") }

func numText(n int) string {
	if n <= 0 {
		return ""
	}
	return strconv.Itoa(n)
}

func newEditData(c store.Client, own []string) editData {
	p := c.Policy
	return editData{
		Name: c.Name, Addr: c.AddrString(), Username: c.Username, Enabled: c.Enabled, LastSeen: c.LastSeen,
		SenderMode: string(p.Sender.Mode), SenderAction: p.Sender.Action, SenderAllowed: listText(p.Sender.Allowed), SenderRewrite: p.Sender.RewriteTo,
		RcptMode: string(p.Rcpt.Mode), RcptScope: p.Rcpt.Scope, RcptAllowed: listText(p.Rcpt.Allowed),
		LimMode: string(p.Limits.Mode), LimAction: p.Limits.Action,
		LimHour: numText(p.Limits.PerHour), LimDay: numText(p.Limits.PerDay), LimRcpts: numText(p.Limits.MaxRcpts),
		LimSize: numText(p.Limits.MaxSizeMB), LimBlock: numText(p.Limits.BlockMinutes),
		ReplyTo: p.Headers.ReplyTo, SubjectTag: p.Headers.SubjectTag, Bcc: listText(p.Headers.Bcc),
		TLSMin: p.TLS.MinVersion, TLSPlain: p.TLS.AllowPlain,
		AttachMode: string(p.Attach.Mode), AttachKind: p.Attach.Kind, AttachExts: strings.Join(p.Attach.Extensions, ", "),
		OwnDomains: strings.Join(own, ", "),
	}
}

// splitEntries splits a free-form list (one per line, or separated by commas,
// semicolons or spaces) into trimmed, non-empty entries.
func splitEntries(s string) []string {
	var out []string
	for _, e := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\r' || r == '\t' }) {
		if e = strings.TrimSpace(e); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func atoiLoose(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

func mode(s string) policy.Mode {
	switch s {
	case "log":
		return policy.Log
	case "enforce":
		return policy.Enforce
	}
	return policy.Off
}

func policyFromForm(r *http.Request) policy.Policy {
	f := r.PostFormValue
	return policy.Policy{
		Sender: policy.SenderRule{
			Mode: mode(f("sender_mode")), Action: f("sender_action"),
			Allowed: splitEntries(f("sender_allowed")), RewriteTo: strings.ToLower(strings.TrimSpace(f("sender_rewrite"))),
		},
		Rcpt: policy.RcptRule{Mode: mode(f("rcpt_mode")), Scope: f("rcpt_scope"), Allowed: splitEntries(f("rcpt_allowed"))},
		Limits: policy.LimitRule{
			Mode: mode(f("lim_mode")), Action: f("lim_action"),
			PerHour: atoiLoose(f("lim_hour")), PerDay: atoiLoose(f("lim_day")), MaxRcpts: atoiLoose(f("lim_rcpts")),
			MaxSizeMB: atoiLoose(f("lim_size")), BlockMinutes: atoiLoose(f("lim_block")),
		},
		Headers: policy.Headers{ReplyTo: strings.TrimSpace(f("reply_to")), SubjectTag: strings.TrimSpace(f("subject_tag")),
			Bcc: lowerAll(splitEntries(f("bcc")))},
		TLS:    policy.TLSRule{MinVersion: f("tls_min"), AllowPlain: f("tls_plain") == "1"},
		Attach: policy.AttachRule{Mode: mode(f("attach_mode")), Kind: f("attach_kind"), Extensions: policy.NormalizeExtensions(splitEntries(f("attach_exts")))},
	}
}

var editTabs = map[string]bool{"general": true, "sender": true, "recipients": true, "limits": true, "messages": true, "connection": true}

func tabOf(v string) string {
	if editTabs[v] {
		return v
	}
	return "general"
}

// backTo returns where a small action (enable/disable, change address) should
// return to: the device's edit page when it was started there, else the list.
func backTo(r *http.Request, flash string) string {
	if r.PostFormValue("back") == "edit" {
		return "/clients/edit?name=" + url.QueryEscape(r.PostFormValue("name")) + "&tab=general&" + flash
	}
	return "/clients?" + flash
}

// applyTab merges the submitted fields of one tab into the stored policy, so
// saving one tab never touches the rules of the others. Without a tab all
// rules are replaced (the old single-form behaviour).
func applyTab(cur policy.Policy, tab string, r *http.Request) policy.Policy {
	full := policyFromForm(r)
	switch tab {
	case "sender":
		cur.Sender = full.Sender
	case "recipients":
		cur.Rcpt = full.Rcpt
	case "limits":
		cur.Limits = full.Limits
	case "connection":
		cur.TLS = full.TLS
	case "messages":
		cur.Headers = full.Headers
		cur.Attach = full.Attach
	default:
		return full
	}
	return cur
}

func (s *Server) editView(r *http.Request, sd *session, c store.Client, tab string) view {
	d := newEditData(c, s.d.Store.OwnDomains())
	d.Tab = tabOf(tab)
	if s.d.Relay != nil {
		d.BlockedUntil = s.d.Relay.BlockedClients()[c.Name]
	}
	v := view{Nav: true, Active: "clients", CSRF: sd.csrf, Data: d}
	s.flashFromQuery(r, &v)
	return v
}

func (s *Server) clientEditPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	c, err := s.d.Store.ClientByName(r.URL.Query().Get("name"))
	if err != nil {
		http.Redirect(w, r, "/clients?err="+s.clientErrKey(err), http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "client_edit", s.editView(r, sd, c, r.URL.Query().Get("tab")))
}

func (s *Server) clientEditSave(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	name := r.PostFormValue("name")
	c, err := s.d.Store.ClientByName(name)
	if err != nil {
		http.Redirect(w, r, "/clients?err="+s.clientErrKey(err), http.StatusSeeOther)
		return
	}
	tab := r.PostFormValue("tab")
	p := applyTab(c.Policy, tab, r)
	if err := p.Validate(); err != nil {
		c.Policy = p // show what the user typed
		v := s.editView(r, sd, c, tab)
		v.Flash, v.FlashKind = s.tr(r, "policy.invalid", err.Error()), "err"
		s.render(w, r, http.StatusBadRequest, "client_edit", v)
		return
	}
	if err := s.d.Store.SetClientPolicy(name, p); err != nil {
		http.Redirect(w, r, "/clients?err="+s.clientErrKey(err), http.StatusSeeOther)
		return
	}
	s.d.Logger.Printf("web UI: rules of client %q changed", c.Name)
	http.Redirect(w, r, "/clients/edit?name="+url.QueryEscape(c.Name)+"&tab="+tabOf(tab)+"&ok=policy_saved", http.StatusSeeOther)
}

func (s *Server) clientUnblock(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	if s.d.Relay != nil {
		s.d.Relay.UnblockClient(r.PostFormValue("name"))
	}
	http.Redirect(w, r, "/clients/edit?name="+url.QueryEscape(r.PostFormValue("name"))+"&tab=general&ok=client_unblocked", http.StatusSeeOther)
}

// ---- emergency stop and internal domains --------------------------------------

func (s *Server) pauseToggle(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	pause := r.PostFormValue("pause") == "1"
	if err := s.d.Store.SetPaused(pause); err != nil {
		s.fail(w, err)
		return
	}
	s.d.Logger.Printf("web UI: sending paused=%v", pause)
	s.d.Notifier.NotifyPaused(pause)
	key := "ok=resumed"
	if pause {
		key = "ok=paused"
	}
	http.Redirect(w, r, "/?"+key, http.StatusSeeOther)
}

func (s *Server) domainsSave(w http.ResponseWriter, r *http.Request, _ *session, _ string) {
	if err := s.d.Store.SetOwnDomains(store.SplitDomains(r.PostFormValue("domains"))); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, "/settings?ok=domains_saved", http.StatusSeeOther)
}

// ---- general settings ---------------------------------------------------------

type settingsData struct {
	OwnDomains string
	// the administrator's overrides (empty = use the default) and the defaults
	Lang, Retention, MaxMB, Conns string
	DefLang                       string
	DefRetention, DefMaxMB        int
	Hostname, PublicPort          string
	EffLang                       string
}

func (s *Server) settingsData() settingsData {
	g := s.d.Store.General()
	return settingsData{
		OwnDomains: strings.Join(s.d.Store.OwnDomains(), ", "),
		Lang:       g.Lang, Retention: numText(g.RetentionDays), MaxMB: numText(g.MaxMessageMB), Conns: numText(g.MaxConnsPerIP),
		DefLang: s.d.Config.Lang, DefRetention: s.d.Config.EventRetentionDays, DefMaxMB: s.d.Config.MaxMessageMB,
		Hostname: s.d.Config.Hostname, PublicPort: s.d.Config.PublicSMTPPort,
	}
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	v := view{Nav: true, Active: "settings", CSRF: sd.csrf, Data: s.settingsData()}
	s.flashFromQuery(r, &v)
	s.render(w, r, http.StatusOK, "settings", v)
}

func (s *Server) generalSave(w http.ResponseWriter, r *http.Request, sd *session, _ string) {
	g := store.General{Lang: r.PostFormValue("lang"), RetentionDays: atoiLoose(r.PostFormValue("retention")),
		MaxMessageMB: atoiLoose(r.PostFormValue("max_mb")), MaxConnsPerIP: atoiLoose(r.PostFormValue("conns"))}
	if err := s.d.Store.SetGeneral(g); err != nil {
		d := s.settingsData()
		d.Lang, d.Retention, d.MaxMB, d.Conns = g.Lang, r.PostFormValue("retention"), r.PostFormValue("max_mb"), r.PostFormValue("conns")
		v := view{Nav: true, Active: "settings", CSRF: sd.csrf, Data: d}
		v.Flash, v.FlashKind = s.tr(r, "settings.general_invalid"), "err"
		s.render(w, r, http.StatusBadRequest, "settings", v)
		return
	}
	http.Redirect(w, r, "/settings?ok=general_saved", http.StatusSeeOther)
}
