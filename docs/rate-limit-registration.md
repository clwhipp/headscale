# Per-IP Rate Limiting for Registration APIs

## Overview

Add rate limiting on a per-IP basis to Headscale's registration endpoints. This feature works with a Caddy reverse proxy sitting in front of Headscale.

## Configuration

Rate limiting is configured under the `registration` section:

```yaml
registration:
  rate_limit:
    # requests_per_second is the sustained rate of registration attempts
    # allowed per source IP. Set to > 0 to enable.
    # Supports fractional values (e.g., 0.5 for 1 request every 2 seconds).
    # Default: 0 (disabled)
    requests_per_second: 1
    # burst is the maximum number of registration attempts allowed in an
    # initial burst. Must be >= 1 when requests_per_second > 0.
    # Default: 5
    burst: 5
```

When `requests_per_second` is 0, rate limiting is disabled (backward compatible).

## Client IP Detection

The client IP is determined using the `X-Real-IP` header, which Caddy sets by default when proxying to the backend.

The IP extraction logic (in `hscontrol/noise.go:extractClientIP`):
1. First checks `X-Real-IP` header
2. Falls back to `req.RemoteAddr`

## Rate Limited Endpoints

The following endpoints are rate limited:

| Endpoint | Handler | Path |
|----------|---------|------|
| Registration | `handleRegister` | `/machine/register` |
| Web Register | `RegisterHandler` | `/register/{id}` |
| OIDC Callback | `OIDCCallbackHandler` | `/oidc/callback` |

## Response Behavior

When rate limited:
- Returns HTTP 429 (Too Many Requests) with empty body
- Logs at info level: `log.Info().Str("ip", ip.String()).Msg("registration rate limit exceeded")`

## Implementation Details

### Files Modified

1. `hscontrol/auth.go` - Add rate limit check in `handleRegister()`
2. `hscontrol/handlers.go` - Add rate limit checks in `RegisterHandler` (via `AuthProviderWeb`)
3. `hscontrol/oidc.go` - Add rate limit check in `OIDCCallbackHandler`
4. `hscontrol/app.go` - Pass rate limiter to auth providers

### Rate Limiter

The rate limiter is implemented in `hscontrol/registration_rate_limiter.go`:
- Uses token bucket algorithm (`golang.org/x/time/rate`)
- Per-IP tracking with automatic cleanup of stale entries
- Created in `app.go` when configuration enables it
- Cleanup goroutine started in `app.go:578`

### Caddy Configuration

Caddy should be configured to send the client IP via the `X-Real-IP` header:

```Caddyfile
reverse_proxy localhost:8080 {
    header_up X-Real-IP {remote_host}
}
```

Or use the `trusted_proxies` directive which automatically sets X-Real-IP:
