package ratelimit

import (
	"sync"
	"time"
)

// Counter counts events per key over the last day, so the relay can apply
// "messages per hour / per day" limits per client. It lives in memory: the
// counts start from zero after a restart.
type Counter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

// NewCounter returns an empty counter.
func NewCounter() *Counter { return &Counter{hits: map[string][]time.Time{}} }

// Add records one event for key.
func (c *Counter) Add(key string, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.hits[key] = append(c.prune(key, now), now)
}

// Counts returns the number of events in the last hour and the last 24 hours.
func (c *Counter) Counts(key string, now time.Time) (hour, day int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	list := c.prune(key, now)
	c.hits[key] = list
	for _, t := range list {
		if now.Sub(t) <= time.Hour {
			hour++
		}
	}
	return hour, len(list)
}

// prune drops events older than 24 hours. The caller holds the lock.
func (c *Counter) prune(key string, now time.Time) []time.Time {
	list := c.hits[key]
	i := 0
	for i < len(list) && now.Sub(list[i]) > 24*time.Hour {
		i++
	}
	if i == len(list) {
		delete(c.hits, key)
		return nil
	}
	return list[i:]
}

// Blocks holds temporary blocks per key (a client blocked for N minutes).
type Blocks struct {
	mu    sync.Mutex
	until map[string]time.Time
}

// NewBlocks returns an empty set of blocks.
func NewBlocks() *Blocks { return &Blocks{until: map[string]time.Time{}} }

// Block blocks key until now+d.
func (b *Blocks) Block(key string, now time.Time, d time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.until[key] = now.Add(d)
}

// Until returns the end of the block, or the zero time when key is not blocked.
func (b *Blocks) Until(key string, now time.Time) time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	t, ok := b.until[key]
	if !ok || !now.Before(t) {
		delete(b.until, key)
		return time.Time{}
	}
	return t
}

// Clear removes the block of key.
func (b *Blocks) Clear(key string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.until, key)
}

// Active lists the currently blocked keys with their end time.
func (b *Blocks) Active(now time.Time) map[string]time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := map[string]time.Time{}
	for k, t := range b.until {
		if now.Before(t) {
			out[k] = t
		} else {
			delete(b.until, k)
		}
	}
	return out
}
