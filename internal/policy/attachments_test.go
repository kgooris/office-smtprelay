package policy

import (
	"reflect"
	"testing"
)

const mixed = "From: a@b.c\r\nTo: d@e.f\r\nSubject: scan\r\nMIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=\"OUTER\"\r\n\r\n" +
	"--OUTER\r\nContent-Type: text/plain\r\n\r\nhello\r\n" +
	"--OUTER\r\nContent-Type: application/pdf; name=\"Scan 1.PDF\"\r\nContent-Disposition: attachment; filename=\"Scan 1.PDF\"\r\nContent-Transfer-Encoding: base64\r\n\r\nQUJD\r\n" +
	"--OUTER\r\nContent-Type: multipart/mixed; boundary=\"INNER\"\r\n\r\n" +
	"--INNER\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"setup.exe\"\r\n\r\nMZ\r\n" +
	"--INNER--\r\n" +
	"--OUTER--\r\n"

func TestAttachmentNames(t *testing.T) {
	got := AttachmentNames([]byte(mixed))
	want := []string{"Scan 1.PDF", "setup.exe"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("names = %q, want %q", got, want)
	}
	if n := AttachmentNames([]byte("From: a@b.c\r\n\r\njust text")); len(n) != 0 {
		t.Errorf("plain message has no attachments, got %q", n)
	}
	if n := AttachmentNames([]byte("garbage")); len(n) != 0 {
		t.Error("garbage yields no names")
	}
	single := "Content-Type: application/pdf; name=\"x.pdf\"\r\n\r\nbody"
	if n := AttachmentNames([]byte(single)); len(n) != 1 || n[0] != "x.pdf" {
		t.Errorf("single-part attachment = %q", n)
	}
}

func TestCheckAttachments(t *testing.T) {
	block := Policy{Attach: AttachRule{Mode: Enforce, Kind: AttachBlock, Extensions: []string{"exe", "js"}}}
	if v, bad := block.CheckAttachments([]string{"a.PDF", "Setup.EXE"}); v != Refused || bad != "Setup.EXE" {
		t.Errorf("block = %v %q", v, bad)
	}
	if v, _ := block.CheckAttachments([]string{"a.pdf"}); v != Allowed {
		t.Error("an unlisted type is allowed in block mode")
	}
	allow := Policy{Attach: AttachRule{Mode: Enforce, Kind: AttachAllow, Extensions: []string{"pdf", "jpg"}}}
	if v, _ := allow.CheckAttachments([]string{"a.pdf", "b.JPG"}); v != Allowed {
		t.Error("listed types pass in allow mode")
	}
	if v, bad := allow.CheckAttachments([]string{"a.pdf", "notes"}); v != Refused || bad != "notes" {
		t.Errorf("a file without extension is refused in allow mode: %v %q", v, bad)
	}
	logOnly := Policy{Attach: AttachRule{Mode: Log, Kind: AttachBlock, Extensions: []string{"exe"}}}
	if v, _ := logOnly.CheckAttachments([]string{"x.exe"}); v != WouldFail {
		t.Error("test mode must not refuse")
	}
	var off Policy
	if v, _ := off.CheckAttachments([]string{"x.exe"}); v != Allowed {
		t.Error("no rule, no check")
	}
}

func TestAttachAndBccValidation(t *testing.T) {
	bad := []Policy{
		{Attach: AttachRule{Mode: Enforce}},
		{Attach: AttachRule{Mode: Enforce, Extensions: []string{"p df"}}},
		{Attach: AttachRule{Kind: "weird"}},
		{Headers: Headers{Bcc: []string{"not an address"}}},
		{Headers: Headers{Bcc: []string{"a@b.c\r\nBcc: x@y.z"}}},
	}
	for i, p := range bad {
		if p.Validate() == nil {
			t.Errorf("case %d should be invalid", i)
		}
	}
	ok := Policy{Attach: AttachRule{Mode: Log, Extensions: NormalizeExtensions([]string{"*.PDF", ".Jpg"})}, Headers: Headers{Bcc: []string{"archive@gbk.be"}}}
	if err := ok.Validate(); err != nil {
		t.Error(err)
	}
	if got := ok.Attach.Extensions; got[0] != "pdf" || got[1] != "jpg" {
		t.Errorf("normalised = %v", got)
	}
	if ok.ActiveRules() != 2 || ok.TestRules() != 1 {
		t.Errorf("counts = %d active, %d test", ok.ActiveRules(), ok.TestRules())
	}
	if p := FromPreset(PresetStrict, ""); p.Attach.Mode != Enforce || p.Validate() != nil {
		t.Error("the strict preset blocks dangerous file types")
	}
}
