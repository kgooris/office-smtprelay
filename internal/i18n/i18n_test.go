package i18n

import (
	"regexp"
	"testing"
)

var verbs = regexp.MustCompile(`%[a-z]`)

func TestCatalogsHaveIdenticalKeys(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	en, nl := c.Keys("en", ""), c.Keys("nl", "")
	if len(en) == 0 {
		t.Fatal("empty catalog")
	}
	for _, k := range en {
		if !c.Has("nl", k) {
			t.Errorf("key %q is missing in nl.json", k)
		}
	}
	for _, k := range nl {
		if !c.Has("en", k) {
			t.Errorf("key %q is missing in en.json", k)
		}
	}
}

func TestFormatVerbsMatch(t *testing.T) {
	c, _ := Load()
	for _, k := range c.Keys("en", "") {
		en, nl := c.T("en", k), c.T("nl", k)
		a, b := verbs.FindAllString(en, -1), verbs.FindAllString(nl, -1)
		if len(a) != len(b) {
			t.Errorf("key %q: format verbs differ between en (%v) and nl (%v)", k, a, b)
		}
	}
}

func TestNoEmptyTexts(t *testing.T) {
	c, _ := Load()
	for _, lang := range Languages {
		for _, k := range c.Keys(lang, "") {
			if c.T(lang, k) == "" {
				t.Errorf("%s: key %q is empty", lang, k)
			}
		}
	}
}

func TestFallback(t *testing.T) {
	c, _ := Load()
	if got := c.T("xx", "nav.logout"); got != c.T("en", "nav.logout") {
		t.Errorf("unknown language must fall back to English, got %q", got)
	}
	if got := c.T("en", "no.such.key"); got != "no.such.key" {
		t.Errorf("missing key must render as the key, got %q", got)
	}
	if got := c.T("en", "dashboard.secret_soon", 5); got == "" || got == "dashboard.secret_soon" {
		t.Errorf("format arguments not applied: %q", got)
	}
}
