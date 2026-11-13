package policy

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"path"
	"strings"
)

// Attachment kinds.
const (
	AttachBlock = "block" // refuse messages with one of the listed types (default)
	AttachAllow = "allow" // refuse messages with any type that is not listed
)

// AttachRule limits the attachment types a client may send.
type AttachRule struct {
	Mode       Mode     `json:"mode,omitempty"`
	Kind       string   `json:"kind,omitempty"`       // block (default) or allow
	Extensions []string `json:"extensions,omitempty"` // without dot, lower case: pdf, jpg
}

// DangerousExtensions is the block list used by the presets: file types that
// run code when opened.
var DangerousExtensions = []string{"exe", "bat", "cmd", "com", "scr", "js", "vbs", "ps1", "msi", "jar", "lnk", "hta", "iso"}

// NormalizeExtensions lower-cases entries and strips "*." and "." prefixes.
func NormalizeExtensions(in []string) []string {
	var out []string
	for _, e := range in {
		e = strings.ToLower(strings.TrimSpace(e))
		e = strings.TrimPrefix(strings.TrimPrefix(e, "*"), ".")
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

func validExtension(e string) bool {
	if e == "" || len(e) > 12 {
		return false
	}
	for _, r := range e {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// CheckAttachments evaluates the attachment rule for the file names found in a
// message. For a violation the second result is the offending file name.
func (p Policy) CheckAttachments(names []string) (Verdict, string) {
	r := p.Attach
	if !r.Mode.Active() || len(names) == 0 {
		return Allowed, ""
	}
	listed := map[string]bool{}
	for _, e := range r.Extensions {
		listed[e] = true
	}
	for _, n := range names {
		ext := strings.TrimPrefix(strings.ToLower(path.Ext(n)), ".")
		bad := false
		if r.Kind == AttachAllow {
			bad = !listed[ext]
		} else {
			bad = listed[ext]
		}
		if bad {
			return verdict(r.Mode, true), n
		}
	}
	return Allowed, ""
}

const maxMIMEDepth = 6

// AttachmentNames returns the file names of all attachments in a raw message,
// including those inside nested multiparts and forwarded messages. A message
// it cannot parse yields no names.
func AttachmentNames(data []byte) []string {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil
	}
	var names []string
	walkPart(msg.Header.Get("Content-Type"), msg.Header.Get("Content-Disposition"), msg.Body, 0, &names)
	return names
}

func partName(ct, cd string) string {
	if _, params, err := mime.ParseMediaType(cd); err == nil && params["filename"] != "" {
		return params["filename"]
	}
	if _, params, err := mime.ParseMediaType(ct); err == nil && params["name"] != "" {
		return params["name"]
	}
	return ""
}

func walkPart(ct, cd string, body io.Reader, depth int, names *[]string) {
	if n := partName(ct, cd); n != "" {
		*names = append(*names, n)
	}
	if depth >= maxMIMEDepth || ct == "" {
		return
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return
	}
	switch {
	case strings.HasPrefix(mt, "multipart/"):
		mr := multipart.NewReader(body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			walkPart(part.Header.Get("Content-Type"), part.Header.Get("Content-Disposition"), part, depth+1, names)
		}
	case mt == "message/rfc822":
		if inner, err := mail.ReadMessage(body); err == nil {
			walkPart(inner.Header.Get("Content-Type"), inner.Header.Get("Content-Disposition"), inner.Body, depth+1, names)
		}
	}
}
