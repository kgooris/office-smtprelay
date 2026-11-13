package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

func TestWindowExpiresAndReset(t *testing.T) {
	l := New(2, time.Minute)
	ip := netip.MustParseAddr("192.0.2.10")
	now := time.Now()
	l.Fail(ip, now)
	l.Fail(ip, now)
	if !l.Blocked(ip, now) {
		t.Fatal("must be blocked after 2 failures")
	}
	if l.Blocked(netip.MustParseAddr("192.0.2.11"), now) {
		t.Fatal("other IPs are unaffected")
	}
	if l.Blocked(ip, now.Add(2*time.Minute)) {
		t.Fatal("block must expire after the window")
	}
	l.Fail(ip, now)
	l.Reset(ip)
	if l.Blocked(ip, now) {
		t.Fatal("reset must clear failures")
	}
}
