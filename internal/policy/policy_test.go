package policy

import (
	"strings"
	"testing"
)

func TestZeroPolicyChangesNothing(t *testing.T) {
	var p Policy
	if v, _ := p.CheckSender("anyone@evil.example"); v != Allowed {
		t.Error("sender")
	}
	if p.CheckRecipient("x@y.example", nil) != Allowed || p.CheckRecipientCount(1000) != Allowed ||
		p.CheckSize(1<<30) != Allowed || p.CheckRate(1000000, 1000000) != Allowed {
		t.Error("an empty policy must allow everything")
	}
	if Parse("").JSON() != "{}" || Parse("not json").JSON() != "{}" {
		t.Error("empty or damaged policies must parse to the zero policy")
	}
}

func TestSenderRule(t *testing.T) {
	reject := Policy{Sender: SenderRule{Mode: Enforce, Allowed: []string{"printer@gbk.be", "@scan.gbk.be"}}}
	for from, want := range map[string]Verdict{
		"printer@gbk.be": Allowed, "PRINTER@GBK.BE": Allowed, "a@scan.gbk.be": Allowed,
		"boss@gbk.be": Refused, "printer@gbk.be.evil.example": Refused,
	} {
		if v, _ := reject.CheckSender(from); v != want {
			t.Errorf("%s = %v, want %v", from, v, want)
		}
	}
	rw := Policy{Sender: SenderRule{Mode: Enforce, Action: Rewrite, RewriteTo: "printer@gbk.be"}}
	if v, to := rw.CheckSender("scanner@kopieerder.local"); v != Rewritten || to != "printer@gbk.be" {
		t.Errorf("rewrite = %v %q", v, to)
	}
	if v, _ := rw.CheckSender("printer@gbk.be"); v != Allowed {
		t.Error("the target itself needs no rewrite")
	}
	logOnly := Policy{Sender: SenderRule{Mode: Log, Allowed: []string{"printer@gbk.be"}}}
	if v, _ := logOnly.CheckSender("x@y.example"); v != WouldFail {
		t.Error("test mode must not refuse")
	}
}

func TestRecipientRule(t *testing.T) {
	own := []string{"gbk.be", "@contoso.com"}
	internal := Policy{Rcpt: RcptRule{Mode: Enforce, Scope: ScopeInternal, Allowed: []string{"boekhouder@extern.example"}}}
	for to, want := range map[string]Verdict{
		"a@gbk.be": Allowed, "b@contoso.com": Allowed, "boekhouder@extern.example": Allowed,
		"x@gmail.com": Refused, "x@notgbk.be": Refused,
	} {
		if got := internal.CheckRecipient(to, own); got != want {
			t.Errorf("%s = %v, want %v", to, got, want)
		}
	}
	list := Policy{Rcpt: RcptRule{Mode: Enforce, Scope: ScopeList, Allowed: []string{"a@gbk.be"}}}
	if list.CheckRecipient("b@gbk.be", own) != Refused {
		t.Error("scope list ignores the own domains")
	}
}

func TestLimits(t *testing.T) {
	p := Policy{Limits: LimitRule{Mode: Enforce, PerHour: 5, PerDay: 20, MaxRcpts: 3, MaxSizeMB: 1}}
	if p.CheckRate(4, 10) != Allowed || p.CheckRate(5, 10) != Refused || p.CheckRate(1, 20) != Refused {
		t.Error("rate limit")
	}
	if p.CheckRecipientCount(3) != Allowed || p.CheckRecipientCount(4) != Refused {
		t.Error("recipient count")
	}
	if p.CheckSize(1<<20) != Allowed || p.CheckSize(1<<20+1) != Refused {
		t.Error("size")
	}
	if p.BlockDuration() != 0 {
		t.Error("default action is reject")
	}
	p.Limits.Action = LimitBlock
	if p.BlockDuration() != 30 {
		t.Error("default block time is 30 minutes")
	}
}

func TestValidate(t *testing.T) {
	bad := []Policy{
		{Sender: SenderRule{Mode: Enforce}},                                  // no allowed senders
		{Sender: SenderRule{Mode: Enforce, Action: Rewrite, RewriteTo: "x"}}, // bad address
		{Rcpt: RcptRule{Mode: Enforce, Scope: ScopeList}},                    // empty list
		{Rcpt: RcptRule{Mode: "weird"}},
		{Limits: LimitRule{PerHour: -1}},
		{Headers: Headers{ReplyTo: "a@b.c\r\nBcc: x@y.z"}},
		{Sender: SenderRule{Mode: Enforce, Allowed: []string{"not an address"}}},
	}
	for i, p := range bad {
		if p.Validate() == nil {
			t.Errorf("case %d should be invalid", i)
		}
	}
	good := FromPreset(PresetStrict, "printer@gbk.be")
	if err := good.Validate(); err != nil {
		t.Error(err)
	}
	if err := FromPreset(PresetRecommended, "").Validate(); err != nil {
		t.Error(err)
	}
	if FromPreset(PresetBasic, "printer@gbk.be").JSON() != "{}" {
		t.Error("the basic preset is the empty policy")
	}
}

func TestApplyHeaders(t *testing.T) {
	msg := "Received: from x\r\nFrom: \"Scan Bot\" <scanner@kopieerder.local>\r\nSender: scanner@kopieerder.local\r\nTo: a@gbk.be\r\n" +
		"Subject: Scan\r\n\t2024\r\nContent-Type: text/plain\r\n\r\nBody\r\nFrom: not a header\r\n"
	out := string(ApplyHeaders([]byte(msg), HeaderEdit{From: "printer@gbk.be", ReplyTo: "helpdesk@gbk.be", SubjectTag: "Printer"}))
	for _, want := range []string{
		"From: \"Scan Bot\" <printer@gbk.be>\r\n", "X-Original-From: \"Scan Bot\" <scanner@kopieerder.local>\r\n",
		"Reply-To: helpdesk@gbk.be\r\n", "Subject: [Printer] Scan 2024\r\n", "Received: from x\r\n", "\r\n\r\nBody\r\nFrom: not a header\r\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(out, "Sender: scanner") {
		t.Error("old Sender must be removed")
	}
	if again := string(ApplyHeaders([]byte(out), HeaderEdit{SubjectTag: "Printer"})); strings.Count(again, "[Printer]") != 1 {
		t.Error("the tag must not be added twice")
	}
	if string(ApplyHeaders([]byte("garbage without header"), HeaderEdit{From: "a@b.c"})) != "garbage without header" {
		t.Error("input that is not a message is returned unchanged")
	}
	noFrom := string(ApplyHeaders([]byte("To: a@b.c\r\n\r\nx"), HeaderEdit{From: "printer@gbk.be"}))
	if !strings.Contains(noFrom, "printer@gbk.be") {
		t.Errorf("a missing From must be added: %s", noFrom)
	}
}
