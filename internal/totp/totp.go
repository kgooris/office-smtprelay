// Package totp implements time-based one-time passwords (RFC 6238, the codes
// shown by authenticator apps) with SHA-1, 6 digits and a 30 second step, which
// is what all common apps support.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	step   = 30 * time.Second
	digits = 6
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a random 160-bit secret in the base32 form apps expect.
func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b32.EncodeToString(b), nil
}

func counter(t time.Time) int64 { return t.Unix() / int64(step/time.Second) }

func code(secret []byte, c int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(c))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", digits, v%1000000)
}

func decode(secret string) ([]byte, error) {
	return b32.DecodeString(strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", "")))
}

// Code returns the code for the given moment (used by tests and the setup check).
func Code(secret string, t time.Time) (string, error) {
	key, err := decode(secret)
	if err != nil {
		return "", err
	}
	return code(key, counter(t)), nil
}

// Verify checks a code against the secret, allowing one step of clock drift
// either way. It returns the time step that matched, so the caller can refuse
// to accept the same code twice (pass the last accepted step as lastUsed).
func Verify(secret, input string, now time.Time, lastUsed int64) (int64, bool) {
	input = strings.ReplaceAll(strings.TrimSpace(input), " ", "")
	if len(input) != digits {
		return 0, false
	}
	key, err := decode(secret)
	if err != nil {
		return 0, false
	}
	cur := counter(now)
	for _, c := range []int64{cur - 1, cur, cur + 1} {
		if c <= lastUsed {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(code(key, c)), []byte(input)) == 1 {
			return c, true
		}
	}
	return 0, false
}

// URI returns the otpauth:// address that authenticator apps import.
func URI(issuer, account, secret string) string {
	v := url.Values{"secret": {secret}, "issuer": {issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}
