# Per-IP Rate Limiting for Noise Handshake

## Overview

Add rate limiting on a per-IP basis to the `/ts2021` noise handshake endpoint. This protects against attackers exhausting the server's private key by forcing repeated noise handshake attempts.

## Motivation

The existing registration rate limit (`/machine/register`, `/register/{id}`, `/oidc/callback`) is applied AFTER the noise protocol handshake completes. The noise handshake involves expensive cryptographic operations using the server's private key. An attacker could potentially flood the server with connection attempts to the `/ts2021` endpoint, causing CPU exhaustion or private key wear.

## Configuration

Rate limiting is configured under the `noise` section:

```yaml
noise:
  private_key_path: /var/lib/headscale/noise_private.key

  # Rate limiting for noise handshake attempts per IP address.
  # This helps protect against attackers exhausting the server's private key
  # by forcing repeated noise handshake attempts.
  # Set to 0 to disable (default).
  rate_limit:
    requests_per_second: 1
    burst: 3
```

- `requests_per_second`: Sustained rate of noise handshakes allowed per source IP. Set to 0 to disable (default is 1). Supports fractional values (e.g., 0.5 for 1 request every 2 seconds).
- `burst`: Maximum number of noise handshakes allowed in an initial burst (default is 3).

When disabled (`requests_per_second: 0`), the rate limiter is not created, maintaining backward compatibility.

## Client IP Detection

The client IP is determined using the `X-Real-IP` header, which should be set by a reverse proxy (e.g., Caddy, Nginx).

The IP extraction logic (in `hscontrol/noise.go:extractClientIP`):
1. First checks `X-Real-IP` header
2. Falls back to parsing `req.RemoteAddr`

## Response Behavior

When rate limited:
- Returns HTTP 429 (Too Many Requests) with body: "rate limit exceeded"
- Logs at info level: `log.Info().Str("ip", ip.String()).Msg("noise handshake rate limit exceeded")`

## Implementation Details

### Files Modified

1. `hscontrol/ip_rate_limiter.go` - Renamed from `registration_rate_limiter.go`, struct renamed to `ipRateLimiter` to reflect reusable nature
2. `hscontrol/app.go` - Added `noiseHandshakeLimiter` field, initialization, cleanup startup
3. `hscontrol/handlers.go` - Updated type reference to `ipRateLimiter`
4. `hscontrol/noise.go` - Added rate limit check BEFORE noise handshake in `NoiseUpgradeHandler`
5. `hscontrol/types/config.go` - Added `NoiseRateLimitConfig` struct, added to Config, viper mapping
6. `config-example.yaml` - Added `noise.rate_limit` configuration section

### Rate Limiter

The rate limiter is implemented in `hscontrol/ip_rate_limiter.go`:
- Uses token bucket algorithm (`golang.org/x/time/rate`)
- Per-IP tracking with automatic cleanup of stale entries
- Created in `app.go` when configuration enables it
- Cleanup goroutine started in `app.go` (same timing as registration limiter: 10min TTL, 1min cleanup)

### Request Flow

```
Client → /ts2021 (NoiseUpgradeHandler)
              ↓
       Rate limit check (NEW - before handshake)
              ↓
       Noise handshake with private key (controlhttpserver.AcceptHTTP)
              ↓
       /machine/register (after successful handshake)
```

### Configuration Type

Both `RegistrationRateLimitConfig` and `NoiseRateLimitConfig` use `float64` for `RequestsPerSecond` to support fractional rates (e.g., 0.5 for 1 request every 2 seconds).

## Caddy Configuration

If using Caddy as a reverse proxy, ensure it forwards the client IP:

```Caddyfile
reverse_proxy localhost:8080 {
    header_up X-Real-IP {remote_host}
}
```

Or use the `trusted_proxies` directive which automatically sets X-Real-IP.
