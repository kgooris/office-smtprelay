package policy

// ActiveRules counts the rules and header changes that are switched on.
func (p Policy) ActiveRules() int {
	n := 0
	for _, m := range []Mode{p.Sender.Mode, p.Rcpt.Mode, p.Limits.Mode, p.Attach.Mode} {
		if m.Active() {
			n++
		}
	}
	if p.Headers.ReplyTo != "" || p.Headers.SubjectTag != "" || len(p.Headers.Bcc) > 0 {
		n++
	}
	if p.TLS.MinVersion != "" || p.TLS.AllowPlain {
		n++
	}
	return n
}

// TestRules counts the rules that are in test mode (logged, not enforced).
func (p Policy) TestRules() int {
	n := 0
	for _, m := range []Mode{p.Sender.Mode, p.Rcpt.Mode, p.Limits.Mode, p.Attach.Mode} {
		if m == Log {
			n++
		}
	}
	return n
}
