package hscontrol

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	ipLimiterTTL     = 10 * time.Minute
	ipLimiterCleanup = 1 * time.Minute
)

type ipRateLimiter struct {
	mu      sync.Mutex
	entries map[netip.Addr]*limiterEntry
	r       rate.Limit
	burst   int
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		entries: make(map[netip.Addr]*limiterEntry),
		r:       rate.Limit(rps),
		burst:   burst,
	}
}

// allow returns true if the IP is within its rate limit.
func (l *ipRateLimiter) allow(ip netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[ip]
	if !ok {
		e = &limiterEntry{limiter: rate.NewLimiter(l.r, l.burst)}
		l.entries[ip] = e
	}

	e.lastSeen = time.Now()

	return e.limiter.Allow()
}

// startCleanup runs a periodic goroutine to evict stale per-IP entries.
func (l *ipRateLimiter) startCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(ipLimiterCleanup)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				l.mu.Lock()

				cutoff := time.Now().Add(-ipLimiterTTL)
				for ip, e := range l.entries {
					if e.lastSeen.Before(cutoff) {
						delete(l.entries, ip)
					}
				}

				l.mu.Unlock()
			}
		}
	}()
}
