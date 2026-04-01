# Registration IP Limitation

## Objective

Mitigate F1 (Unauthenticated Node Registration) by restricting which IP addresses can register new nodes without a PreAuthKey.

## Approach

Block new node registrations (without PreAuthKey) from untrusted IP ranges. Only IPs in the configured `interactive_cidrs_whitelist` can register without a PreAuthKey via interactive registration.

## Security Warning: Reverse Proxy Required

!!! warning "X-Real-IP Header Requirement"

    The IP-based registration restriction **requires a properly configured reverse proxy** that sets the `X-Real-IP` header. Without this:

    - Headscale trusts the `X-Real-IP` header unconditionally
    - An attacker can bypass the IP restriction by setting `X-Real-IP: <trusted-ip>` in their request
    - The feature is **only effective when deployed behind a reverse proxy**

    Your reverse proxy **must**:
    1. Set the `X-Real-IP` header to the actual client IP
    2. Overwrite any existing `X-Real-IP` header from incoming requests (prevent spoofing)

## Configuration

### New Config Section (types/config.go)

```go
type RegistrationConfig struct {
    // InteractiveCIDRsWhitelist contains CIDR blocks that are allowed to register
    // without a PreAuthKey via interactive registration (browser-based flow).
    // IPs outside these ranges must provide a PreAuthKey.
    // If empty, all IPs are allowed to register without PreAuthKey (backward compatible).
    InteractiveCIDRsWhitelist []netip.Prefix `mapstructure:"interactive_cidrs_whitelist"`
}
```

### Viper Key

```
registration.interactive_cidrs_whitelist
```

### config-example.yaml

```yaml
registration:
  # CIDR blocks that can use interactive registration (without PreAuthKey).
  # IPs outside these ranges require a PreAuthKey.
  # Example:
  #   - 10.0.0.0/8
  #   - 192.168.0.0/16
  interactive_cidrs_whitelist: []
```

---

## Implementation

### 1. Add Config to types/config.go

**Location**: Around line 103 (after `Tuning Tuning` in Config struct)

```go
type Config struct {
    // ... existing fields ...
    
    Registration RegistrationConfig
    Tuning Tuning
}
```

**Add Viper parsing** around line 1050:

```go
registrationInteractiveCIDRsWhitelist := viper.GetStringSlice("registration.interactive_cidrs_whitelist")
var interactiveCIDRsWhitelist []netip.Prefix
for _, cidr := range registrationInteractiveCIDRsWhitelist {
    prefix, err := netip.ParsePrefix(cidr)
    if err != nil {
        return nil, fmt.Errorf("parsing registration.interactive_cidrs_whitelist: %w", err)
    }
    interactiveCIDRsWhitelist = append(interactiveCIDRsWhitelist, prefix)
}

config.Registration = RegistrationConfig{
    InteractiveCIDRsWhitelist: interactiveCIDRsWhitelist,
}
```

### 2. Update auth.go

#### 2.1 Add isInteractiveRegistrationAllowed helper

**Location**: After `isAuthKey()` function (~line 233)

```go
// isInteractiveRegistrationAllowed checks if the given IP is in the configured
// InteractiveCIDRsWhitelist. If no ranges are configured, all IPs are considered
// allowed (backward compatible).
func (h *Headscale) isInteractiveRegistrationAllowed(ip netip.Addr) bool {
    if len(h.cfg.Registration.InteractiveCIDRsWhitelist) == 0 {
        return true // Empty config = all allowed
    }

    for _, prefix := range h.cfg.Registration.InteractiveCIDRsWhitelist {
        if prefix.Contains(ip) {
            return true
        }
    }

    return false
}
```

#### 2.2 Update handleRegister signature

**Location**: Line 27

```go
func (h *Headscale) handleRegister(
    ctx context.Context,
    req tailcfg.RegisterRequest,
    machineKey key.MachinePublic,
    clientIP netip.Addr,  // NEW
) (*tailcfg.RegisterResponse, error) {
```

#### 2.3 Add IP check in handleRegisterInteractive

**Location**: Around line 127 (before creating registration)

```go
// handleRegisterInteractive handles the registration of a node without a PreAuthKey.
// Only apply IP check to NEW nodes (not existing node re-registration).
if clientIP.IsValid() && !h.isInteractiveRegistrationAllowed(clientIP) {
    log.Warn().
        Str("client_ip", clientIP.String()).
        Str("node_key", req.NodeKey.ShortString()).
        Msg("Interactive registration denied: untrusted IP without PreAuthKey")

    return &tailcfg.RegisterResponse{
        Error: "Registration from untrusted networks requires a PreAuthKey",
    }, nil
}
```

#### 2.4 Pass clientIP through followup path

If there's a followup path (line 105-106), also pass clientIP:

```go
// In handleRegister, update the waitForFollowup call
if req.Followup != "" {
    return h.waitForFollowup(ctx, req, machineKey, clientIP)  // Pass through
}
```

Then update `waitForFollowup` signature to accept and pass clientIP.

### 3. Update noise.go

#### 3.1 Add extractClientIP helper

**Location**: At top of file or near NoiseRegistrationHandler

```go
import "net"

// extractClientIP extracts the client IP from X-Real-IP header (set by reverse proxy)
// or falls back to parsing from req.RemoteAddr.
func extractClientIP(req *http.Request) netip.Addr {
    // Priority: X-Real-IP header (set by Caddy/reverse proxy)
    if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
        if ip, err := netip.ParseAddr(realIP); err == nil {
            return ip
        }
    }

    // Fallback: parse from RemoteAddr
    if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
        if ip, err := netip.ParseAddr(host); err == nil {
            return ip
        }
    }

    return netip.Addr{}
}
```

#### 3.2 Update NoiseRegistrationHandler call

**Location**: Line 257

```go
clientIP := extractClientIP(req)
resp, err = ns.headscale.handleRegister(req.Context(), regReq, ns.conn.Peer(), clientIP)
```

### 4. Update auth_test.go

#### 4.1 Update existing test calls (~25 places)

For each call to `handleRegister`, add `nil` as the last parameter:

```go
// Before
_, err = app.handleRegister(context.Background(), req, machineKey)

// After
_, err = app.handleRegister(context.Background(), req, machineKey, nil)
```

#### 4.2 Add new test cases

Add to `TestAuthenticationFlows`:

```go
// TEST: Registration from untrusted IP without PreAuthKey should be denied
{
    name: "untrusted_ip_no_preauth_rejected",
    clientIP: netip.MustParseAddr("203.0.113.1"),
    setupFunc: func(t *testing.T, app *Headscale) (string, error) {
        // Set untrusted IP in config
        app.cfg.Registration.InteractiveCIDRsWhitelist = []netip.Prefix{
            netip.MustParsePrefix("10.0.0.0/8"),
        }
        return "", nil
    },
    request: func(authKey string) tailcfg.RegisterRequest {
        return tailcfg.RegisterRequest{
            NodeKey: nodeKey1.Public(),
            Version: 5,
        }
    },
    machineKey: func() key.MachinePublic { return machineKey1.Public() },
    wantError: true,
    expectedError: "Registration from untrusted networks requires a PreAuthKey",
}

// TEST: Registration from trusted IP without PreAuthKey should succeed
{
    name: "trusted_ip_no_preauth_allowed",
    clientIP: netip.MustParseAddr("10.0.0.1"),
    setupFunc: func(t *testing.T, app *Headscale) (string, error) {
        app.cfg.Registration.InteractiveCIDRsWhitelist = []netip.Prefix{
            netip.MustParsePrefix("10.0.0.0/8"),
        }
        return "", nil
    },
    request: func(authKey string) tailcfg.RegisterRequest {
        return tailcfg.RegisterRequest{
            NodeKey: nodeKey1.Public(),
            Version: 5,
        }
    },
    machineKey: func() key.MachinePublic { return machineKey1.Public() },
    wantAuthURL: true, // Expects interactive auth flow
}

// TEST: Registration from untrusted IP with PreAuthKey should succeed
{
    name: "untrusted_ip_with_preauth_allowed",
    clientIP: netip.MustParseAddr("203.0.113.1"),
    setupFunc: func(t *testing.T, app *Headscale) (string, error) {
        app.cfg.Registration.InteractiveCIDRsWhitelist = []netip.Prefix{
            netip.MustParsePrefix("10.0.0.0/8"),
        }
        user := app.state.CreateUserForTest("test-user")
        pak, err := app.state.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
        if err != nil {
            return "", err
        }
        return pak.Key, nil
    },
    request: func(authKey string) tailcfg.RegisterRequest {
        return tailcfg.RegisterRequest{
            NodeKey:       nodeKey1.Public(),
            Auth:          &tailcfg.RegisterRequestAuth{AuthKey: authKey},
            Version:       5,
        }
    },
    machineKey: func() key.MachinePublic { return machineKey1.Public() },
    wantAuth: true,
}
```

Note: The test framework will need to be updated to accept `clientIP` parameter in the test struct.

### 5. Add config_test.go tests

```go
func TestRegistrationInteractiveCIDRsWhitelist(t *testing.T) {
    originalViper := viper.GetViper()
    defer viper.Set("config", originalViper)

    // Test valid CIDRs
    viper.Set("registration.interactive_cidrs_whitelist", []string{
        "10.0.0.0/8",
        "192.168.0.0/16",
    })

    cfg, err := types.GetConfig()
    require.NoError(t, err)
    assert.Len(t, cfg.Registration.InteractiveCIDRsWhitelist, 2)

    // Test IP matching
    assert.True(t, cfg.Registration.InteractiveCIDRsWhitelist[0].Contains(netip.MustParseAddr("10.5.5.5")))
    assert.False(t, cfg.Registration.InteractiveCIDRsWhitelist[0].Contains(netip.MustParseAddr("172.16.0.1")))

    // Test empty config
    viper.Set("registration.interactive_cidrs_whitelist", []string{})
    cfg2, err := types.GetConfig()
    require.NoError(t, err)
    assert.Len(t, cfg2.Registration.InteractiveCIDRsWhitelist, 0)
}
```

### 6. Update config-example.yaml

Add under the registration section (around line 40):

```yaml
# Node registration settings
registration:
  # CIDR blocks that can use interactive registration without PreAuthKey.
  # This is useful for trusted networks (e.g., corporate VPN, admin network).
  # Clients from IPs outside these ranges must provide a valid PreAuthKey.
  # Leave empty to allow registration from any IP without PreAuthKey.
  # Examples:
  #   - 10.0.0.0/8      # RFC1918 private
  #   - 192.168.0.0/16 # RFC1918 private
  interactive_cidrs_whitelist: []
```

---

## Reverse Proxy Configuration

### Caddy

Update Caddyfile to pass X-Real-IP header:

```caddy
reverse_proxy localhost:8080 {
    header_up X-Real-IP {remote_ip}
}
```

Caddy automatically overwrites the `X-Real-IP` header with the actual client IP, preventing spoofing attacks.

### nginx

Ensure your nginx configuration overwrites (not just adds) the X-Real-IP header:

```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

Note: nginx appends to `X-Forwarded-For` rather than overwriting it. Ensure your configuration replaces any existing `X-Real-IP` header from incoming requests.

---

## Backward Compatibility

- **Empty config** (`interactive_cidrs_whitelist: []` or not set) → All IPs allowed to use interactive registration, no change from current behavior
- **Existing deployments** → Won't break
- **Tests** → Pass `nil` for clientIP to skip IP check

---

## Files to Modify

| File | Changes |
|------|---------|
| `hscontrol/types/config.go` | Add RegistrationConfig struct, add to Config, add Viper parsing |
| `hscontrol/auth.go` | Update handleRegister signature, add isInteractiveRegistrationAllowed(), add IP check in handleRegisterInteractive |
| `hscontrol/noise.go` | Add extractClientIP(), update handleRegister call |
| `hscontrol/auth_test.go` | Update ~25 test calls, add 3 new test cases |
| `hscontrol/types/config_test.go` | Add config parsing tests |
| `config-example.yaml` | Document new option |

---

## Tradeoffs

| Aspect | Consideration |
|--------|---------------|
| Header spoofing | Caddy overwrites X-Real-IP, so clients can't spoof if Caddy is the only entry point |
| No Caddy | If headscale is directly exposed, this won't work (need different approach) |
| Re-registration | Existing nodes can re-register without PreAuthKey regardless of IP (per Option B) |
| Test complexity | Need to add clientIP to test framework and update ~25 test calls |

---

## Configuration Example

```yaml title="config.yaml"
registration:
  # CIDR blocks that can use interactive registration without PreAuthKey.
  # This is useful for trusted networks (e.g., corporate VPN, admin network).
  # Clients from IPs outside these ranges must provide a PreAuthKey.
  # Leave empty to allow registration from any IP without PreAuthKey.
  # WARNING: Requires reverse proxy to set X-Real-IP header (see above)
  interactive_cidrs_whitelist:
    - 10.0.0.0/8      # RFC1918 private
    - 192.168.0.0/16  # RFC1918 private
```