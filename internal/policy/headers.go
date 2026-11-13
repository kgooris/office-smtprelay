package policy

import (
	"bytes"
	"net/mail"
	"strings"
)

// HeaderEdit lists the header changes ApplyHeaders performs. Empty fields are
// left alone.
type HeaderEdit struct {
	From       string // rewrite the From header to this address (keeps the display name)
	ReplyTo    string // set Reply-To
	SubjectTag string // prefix the subject with "[tag] "
}

// Empty reports whether nothing would change.
func (e HeaderEdit) Empty() bool { return e.From == "" && e.ReplyTo == "" && e.SubjectTag == "" }

type field struct {
	name  string // original case, without colon
	lines []string
}

func (f field) value() string {
	var parts []string
	for i, l := range f.lines {
		if i == 0 {
			l = l[strings.IndexByte(l, ':')+1:]
		}
		parts = append(parts, strings.TrimSpace(l))
	}
	return strings.TrimSpace(strings.Join(parts, " "))
}

// ApplyHeaders edits the top-level headers of a raw RFC 5322 message without
// touching the body or any MIME structure. It never fails: input it cannot
// understand is returned unchanged.
func ApplyHeaders(data []byte, e HeaderEdit) []byte {
	if e.Empty() {
		return data
	}
	hdr, body, sep, ok := splitMessage(data)
	if !ok {
		return data
	}
	var fields []field
	for _, line := range strings.Split(strings.ReplaceAll(string(hdr), "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && len(fields) > 0 {
			fields[len(fields)-1].lines = append(fields[len(fields)-1].lines, line)
			continue
		}
		i := strings.IndexByte(line, ':')
		if i <= 0 {
			return data // not a header block we understand
		}
		fields = append(fields, field{name: line[:i], lines: []string{line}})
	}

	drop := func(names ...string) (removed []field) {
		var kept []field
		for _, f := range fields {
			hit := false
			for _, n := range names {
				if strings.EqualFold(f.name, n) {
					hit = true
				}
			}
			if hit {
				removed = append(removed, f)
			} else {
				kept = append(kept, f)
			}
		}
		fields = kept
		return removed
	}
	add := func(name, value string) {
		fields = append(fields, field{name: name, lines: []string{name + ": " + value}})
	}

	if e.From != "" {
		old := drop("From", "Sender")
		name := ""
		for _, f := range old {
			if strings.EqualFold(f.name, "From") {
				if a, err := mail.ParseAddress(f.value()); err == nil {
					name = a.Name
				}
				v := f.value()
				if len(v) > 200 {
					v = v[:200]
				}
				add("X-Original-From", v)
			}
		}
		add("From", (&mail.Address{Name: name, Address: e.From}).String())
	}
	if e.ReplyTo != "" {
		drop("Reply-To")
		add("Reply-To", e.ReplyTo)
	}
	if e.SubjectTag != "" {
		tag := "[" + e.SubjectTag + "]"
		old := drop("Subject")
		subject := ""
		if len(old) > 0 {
			subject = old[0].value()
		}
		if !strings.HasPrefix(subject, tag) {
			subject = strings.TrimSpace(tag + " " + subject)
		}
		add("Subject", subject)
	}

	var out bytes.Buffer
	for _, f := range fields {
		for _, l := range f.lines {
			out.WriteString(l)
			out.WriteString("\r\n")
		}
	}
	out.WriteString(sep)
	out.Write(body)
	return out.Bytes()
}

// splitMessage separates header and body at the first blank line. sep is the
// blank line itself (always CRLF in the output).
func splitMessage(data []byte) (hdr, body []byte, sep string, ok bool) {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return data[:i], data[i+4:], "\r\n", true
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return data[:i], data[i+2:], "\r\n", true
	}
	return nil, nil, "", false
}
