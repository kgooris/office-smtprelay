// Package ratelimit blocks a key (an IP address) for a while after too many
// failed attempts. It is used for SMTP logins and for the web UI login.
package ratelimit

import (
	"net/netip"
	"sync"
	"time"
)

// FailLimiter counts failures per IP inside a sliding window.
type FailLimiter struct {
	max    int
	window time.Duration

	mu      sync.Mutex
	entries map[netip.Addr]*entry
}

type entry struct {
	count int
	first time.Time
}

// New returns a limiter that blocks an IP after max failures within window.
func New(max int, window time.Duration) *FailLimiter {
	return &FailLimiter{max: max, window: window, entries: map[netip.Addr]*entry{}}
}

// Blocked reports whether ip has reached the failure limit inside the window.
func (l *FailLimiter) Blocked(ip netip.Addr, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	if e == nil {
		return false
	}
	if now.Sub(e.first) > l.window {
		delete(l.entries, ip)
		return false
	}
	return e.count >= l.max
}

// Fail records a failed attempt.
func (l *FailLimiter) Fail(ip netip.Addr, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[ip]
	if e == nil || now.Sub(e.first) > l.window {
		e = &entry{first: now}
		l.entries[ip] = e
	}
	e.count++
	if len(l.entries) > 10000 { // bound memory under a distributed attack
		for k, v := range l.entries {
			if now.Sub(v.first) > l.window {
				delete(l.entries, k)
			}
		}
	}
}

// Reset forgets the failures of ip (after a successful login).
func (l *FailLimiter) Reset(ip netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, ip)
}
