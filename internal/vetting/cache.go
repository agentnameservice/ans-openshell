package vetting

import (
	"container/list"
	"time"
)

// refreshAheadDivisor places the refresh point in the last fraction of an
// entry's TTL, so a host that stays in use is re-looked-up before its verdict
// expires and the request path never sees the gap.
const refreshAheadDivisor = 10

type cacheEntry struct {
	verdict   Verdict
	expiresAt time.Time
	refreshAt time.Time
	elem      *list.Element
}

// verdictCache is a bounded TTL map that evicts the entry written least
// recently. It is not safe for concurrent use; Service serializes access.
type verdictCache struct {
	max     int
	entries map[string]*cacheEntry
	order   *list.List
}

func newVerdictCache(maxEntries int) *verdictCache {
	return &verdictCache{
		max:     maxEntries,
		entries: make(map[string]*cacheEntry),
		order:   list.New(),
	}
}

// get returns the entry for host whether or not it has expired.
func (c *verdictCache) get(host string) (*cacheEntry, bool) {
	e, ok := c.entries[host]
	return e, ok
}

func (c *verdictCache) put(host string, v Verdict, now time.Time, ttl time.Duration) {
	e, ok := c.entries[host]
	if !ok {
		e = &cacheEntry{}
		e.elem = c.order.PushBack(host)
		c.entries[host] = e
	} else {
		c.order.MoveToBack(e.elem)
	}
	e.verdict = v
	e.expiresAt = now.Add(ttl)
	e.refreshAt = now.Add(ttl - ttl/refreshAheadDivisor)
	for c.order.Len() > c.max {
		oldest := c.order.Front()
		delete(c.entries, oldest.Value.(string)) //nolint:errcheck // list values are host keys written by put
		c.order.Remove(oldest)
	}
}

func (c *verdictCache) len() int {
	return len(c.entries)
}
