package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B test vectors (SHA-1, secret "12345678901234567890"), last 6 digits.
func TestRFC6238Vectors(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"} {
		got, err := Code(secret, time.Unix(unix, 0))
		if err != nil || got != want {
			t.Errorf("t=%d: got %s, want %s (%v)", unix, got, want, err)
		}
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	secret, err := NewSecret()
	if err != nil || len(secret) != 32 {
		t.Fatalf("secret = %q, %v", secret, err)
	}
	now := time.Unix(1_800_000_000, 0)
	c, _ := Code(secret, now)

	step1, ok := Verify(secret, c, now, 0)
	if !ok {
		t.Fatal("the current code must verify")
	}
	if _, ok := Verify(secret, c, now, step1); ok {
		t.Error("the same code must not be accepted twice")
	}
	if _, ok := Verify(secret, c[:3]+" "+c[3:], now, 0); !ok {
		t.Error("a code typed with a space is fine")
	}
	prev, _ := Code(secret, now.Add(-30*time.Second))
	if _, ok := Verify(secret, prev, now, 0); !ok {
		t.Error("one step of clock drift is allowed")
	}
	old, _ := Code(secret, now.Add(-120*time.Second))
	if _, ok := Verify(secret, old, now, 0); ok {
		t.Error("a code from two minutes ago must be refused")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef", "000000"} {
		if _, ok := Verify(secret, bad, now, 0); ok && bad != c {
			t.Errorf("%q must be refused", bad)
		}
	}
	if _, ok := Verify("not base32!!", c, now, 0); ok {
		t.Error("a broken secret never verifies")
	}
}

func TestURI(t *testing.T) {
	u := URI("office-smtprelay", "kristof", "ABC234")
	for _, want := range []string{"otpauth://totp/office-smtprelay:kristof?", "secret=ABC234", "issuer=office-smtprelay", "digits=6", "period=30"} {
		if !strings.Contains(u, want) {
			t.Errorf("%q lacks %q", u, want)
		}
	}
}
