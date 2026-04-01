package hscontrol

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestIPRateLimiterBasicAllow(t *testing.T) {
	limiter := newIPRateLimiter(10, 5)
	ip := netip.MustParseAddr("192.168.1.1")

	for i := 0; i < 5; i++ {
		result := limiter.allow(ip)
		assert.True(t, result, "should allow requests within burst limit")
	}

	result := limiter.allow(ip)
	assert.False(t, result, "should block requests exceeding burst limit")
}

func TestIPRateLimiterPerIPIsolation(t *testing.T) {
	limiter := newIPRateLimiter(10, 1)
	ip1 := netip.MustParseAddr("192.168.1.1")
	ip2 := netip.MustParseAddr("192.168.1.2")

	assert.True(t, limiter.allow(ip1), "first request for ip1 should be allowed")
	assert.False(t, limiter.allow(ip1), "second request for ip1 should be blocked")

	assert.True(t, limiter.allow(ip2), "ip2 should still be allowed (separate limit)")
	assert.False(t, limiter.allow(ip2), "ip2 should now be blocked")
}

func TestIPRateLimiterBurst(t *testing.T) {
	tests := []struct {
		name          string
		rate          float64
		burst         int
		allowCount    int
		expectedAllow bool
	}{
		{
			name:          "burst of 1",
			rate:          1,
			burst:         1,
			allowCount:    1,
			expectedAllow: false,
		},
		{
			name:          "burst of 5",
			rate:          1,
			burst:         5,
			allowCount:    5,
			expectedAllow: false,
		},
		{
			name:          "burst of 10",
			rate:          1,
			burst:         10,
			allowCount:    10,
			expectedAllow: false,
		},
		{
			name:          "burst of 5 with 6 requests",
			rate:          1,
			burst:         5,
			allowCount:    6,
			expectedAllow: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limiter := newIPRateLimiter(tt.rate, tt.burst)
			ip := netip.MustParseAddr("192.168.1.1")

			for i := 0; i < tt.allowCount; i++ {
				limiter.allow(ip)
			}

			result := limiter.allow(ip)
			assert.Equal(t, tt.expectedAllow, result)
		})
	}
}

func TestIPRateLimiterRefillOverTime(t *testing.T) {
	limiter := newIPRateLimiter(1, 1)
	ip := netip.MustParseAddr("192.168.1.1")

	assert.True(t, limiter.allow(ip), "first request should be allowed")
	assert.False(t, limiter.allow(ip), "second request should be blocked")

	time.Sleep(200 * time.Millisecond)

	assert.False(t, limiter.allow(ip), "request should still be blocked at rate 1")

	time.Sleep(1 * time.Second)

	assert.True(t, limiter.allow(ip), "request should be allowed after 1 second at rate 1")
}

func TestIPRateLimiterConcurrentAccess(t *testing.T) {
	limiter := newIPRateLimiter(100, 50)
	ip := netip.MustParseAddr("192.168.1.1")

	var wg sync.WaitGroup
	results := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- limiter.allow(ip)
		}()
	}

	wg.Wait()
	close(results)

	allowCount := 0
	blockCount := 0
	for result := range results {
		if result {
			allowCount++
		} else {
			blockCount++
		}
	}

	assert.LessOrEqual(t, allowCount, 50, "should not allow more than burst")
	assert.Greater(t, blockCount, 0, "should have blocked some requests")
}

func TestIPRateLimiterLowRate(t *testing.T) {
	limiter := newIPRateLimiter(0.5, 1)
	ip := netip.MustParseAddr("192.168.1.1")

	assert.True(t, limiter.allow(ip), "first request should be allowed")
	assert.False(t, limiter.allow(ip), "second request should be blocked immediately")

	time.Sleep(2 * time.Second)

	assert.True(t, limiter.allow(ip), "request should be allowed after 2 seconds at 0.5 rate")
}

func TestIPRateLimiterInvalidIP(t *testing.T) {
	limiter := newIPRateLimiter(10, 5)
	invalidIP := netip.Addr{}

	result := limiter.allow(invalidIP)
	assert.True(t, result, "invalid IP creates new limiter and is allowed (first token)")
}

func TestIPRateLimiterMultipleIPs(t *testing.T) {
	limiter := newIPRateLimiter(10, 2)

	ips := []netip.Addr{
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.2"),
		netip.MustParseAddr("192.168.1.3"),
		netip.MustParseAddr("192.168.1.4"),
		netip.MustParseAddr("192.168.1.5"),
	}

	for _, ip := range ips {
		assert.True(t, limiter.allow(ip), "first request for %s should be allowed", ip)
		assert.True(t, limiter.allow(ip), "second request for %s should be allowed (burst=2)", ip)
		assert.False(t, limiter.allow(ip), "third request for %s should be blocked", ip)
	}

	for _, ip := range ips {
		assert.False(t, limiter.allow(ip), "all IPs should still be rate limited")
	}
}

func TestIPRateLimiterCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode")
	}

	limiter := newIPRateLimiter(10, 5)
	ctx, cancel := context.WithCancel(context.Background())

	limiter.startCleanup(ctx)

	ip1 := netip.MustParseAddr("192.168.1.1")
	ip2 := netip.MustParseAddr("192.168.1.2")

	for i := 0; i < 5; i++ {
		limiter.allow(ip1)
		limiter.allow(ip2)
	}

	limiter.mu.Lock()
	initialEntries := len(limiter.entries)
	limiter.mu.Unlock()
	assert.Equal(t, 2, initialEntries, "should have 2 entries")

	limiter.mu.Lock()
	for ip := range limiter.entries {
		limiter.entries[ip].lastSeen = time.Now().Add(-15 * time.Minute)
	}
	limiter.mu.Unlock()

	limiter.mu.Lock()
	entriesBeforeCleanup := len(limiter.entries)
	limiter.mu.Unlock()
	assert.Equal(t, 2, entriesBeforeCleanup, "entries should still exist before cleanup")

	time.Sleep(70 * time.Second)

	limiter.mu.Lock()
	entriesAfterCleanup := len(limiter.entries)
	limiter.mu.Unlock()

	assert.Equal(t, 0, entriesAfterCleanup, "stale entries should be cleaned up after cleanup runs")

	cancel()
}

func TestIPRateLimiterIPv6(t *testing.T) {
	limiter := newIPRateLimiter(10, 2)

	ipv4 := netip.MustParseAddr("192.168.1.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")

	assert.True(t, limiter.allow(ipv4), "IPv4 first request should be allowed")
	assert.True(t, limiter.allow(ipv4), "IPv4 second request should be allowed")
	assert.False(t, limiter.allow(ipv4), "IPv4 third request should be blocked")

	assert.True(t, limiter.allow(ipv6), "IPv6 first request should be allowed")
	assert.True(t, limiter.allow(ipv6), "IPv6 second request should be allowed")
	assert.False(t, limiter.allow(ipv6), "IPv6 third request should be blocked")
}

func TestIPRateLimiterMapEntries(t *testing.T) {
	limiter := newIPRateLimiter(1, 1)

	ips := []netip.Addr{
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.2"),
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("172.16.0.1"),
	}

	for _, ip := range ips {
		limiter.allow(ip)
	}

	limiter.mu.Lock()
	entryCount := len(limiter.entries)
	limiter.mu.Unlock()

	assert.Equal(t, len(ips), entryCount, "should have separate entries for each IP")
}
