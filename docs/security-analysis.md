# Headscale Security Analysis

## API Risk Assessments

---

### TS2021 — Noise Protocol Endpoint

**Endpoints involved**
- `GET/POST /ts2021` — WebSocket upgrade (`NoiseUpgradeHandler`)
- `POST /machine/register` — Node registration (over Noise, `NoiseRegistrationHandler`)
- `GET/POST /machine/map` — Network map long-poll (over Noise, `NoisePollNetMapHandler`)

These three are inseparable: `/ts2021` establishes the encrypted channel, and `register` and `map` only exist inside it.

---

#### Authentication

The Noise protocol (specifically Tailscale's `controlbase` / Noise_IK variant) provides the transport-layer authentication for everything in this surface.

**Handshake mechanics** (`noise.go:74`):
1. Client connects via WebSocket upgrade to `/ts2021`
2. `controlhttpserver.AcceptHTTP()` performs the Noise handshake using the server's long-term `key.MachinePrivate`
3. On success, `ns.machineKey = ns.conn.Peer()` — the client's `key.MachinePublic` is now cryptographically authenticated; it cannot be forged without the corresponding private key
4. An **EarlyNoise** payload is sent immediately after handshake containing a `NodeKeyChallenge` (ephemeral `key.ChallengePrivate.Public()`), used by the client to prove ownership of its node key
5. All subsequent HTTP/2 traffic flows inside the encrypted Noise channel

**What this means in practice**: any client that successfully completes the handshake has proven possession of a specific machine private key. The server authenticates itself to clients using its own private key, whose public counterpart clients retrieve from `/key`. There are no bearer tokens, cookies, or sessions — the Noise session *is* the authentication.

**Version enforcement** (`noise.go:157`): clients with `CapabilityVersion < MinSupportedCapabilityVersion` are rejected before any registration or map handling begins. This is checked in `earlyNoise()` (at handshake time) and again in `rejectUnsupported()` in both `NoiseRegistrationHandler` and `NoisePollNetMapHandler`.

**MachineKey ↔ NodeKey binding** (`noise.go:294-305`): for every `/machine/map` request, `getAndValidateNode()` looks up the node by the `NodeKey` from the `MapRequest`, then asserts `ns.machineKey == nv.MachineKey()`. If they don't match, the request is rejected with 404. This prevents a node that knows another node's `NodeKey` from impersonating it on the map endpoint.

---

#### `/machine/register` — Data Accepted

The `RegisterRequest` body (JSON over Noise HTTP/2):

| Field | Type | Client-controlled | Notes |
|---|---|---|---|
| `NodeKey` | `key.NodePublic` | Yes | The node's current public key |
| `OldNodeKey` | `key.NodePublic` | Yes | Previous key for rotation |
| `Auth.AuthKey` | `string` | Yes | PreAuthKey string (if using key-based auth) |
| `Hostinfo` | `tailcfg.Hostinfo` | Yes | OS, hostname, services, routable IPs — entirely client-supplied |
| `Expiry` | `time.Time` | Yes | Used to signal logout (past = expire/logout) |
| `Followup` | `string` | Yes | URL for polling an in-progress interactive registration |
| `Version` | `CapabilityVersion` | Yes | Client version |

**`Hostinfo` is fully client-controlled** and propagated into the database. It includes: `Hostname`, `OS`, `OSVersion`, `Package`, `DeviceModel`, `GoArch`, `IPNVersion`, `FrontendLogID`, `BackendLogID`, `RoutableIPs`, `RequestTags`, `Services`, `NetInfo`, `SSH_HostKeys`, and more. None of these fields are validated for content — only format. A malicious client can supply arbitrary values for all of them.

**`req.Hostinfo.RoutableIPs`** in particular feeds directly into the route advertisement system and is used during auto-approval checks in `HandleNodeFromPreAuthKey`. If the policy auto-approves routes, a client that lies about its routable IPs could get unexpected routes approved.

**`req.Followup`** is a URL parsed at `auth.go:263`. Only the path component is used (`strings.ReplaceAll(fu.Path, "/register/", "")`), and the result is validated as a `RegistrationID`. This is not obviously exploitable but is worth noting as an attacker-supplied URL is parsed.

---

#### `/machine/register` — Data Returned

`RegisterResponse`:

| Field | Significance |
|---|---|
| `MachineAuthorized` | Always `true` — headscale has no machine authorization concept |
| `NodeKeyExpired` | Whether the node's key has expired |
| `AuthURL` | URL for interactive auth (contains `RegistrationID`) — returned for unauthenticated registrations |
| `User` | `tailcfg.UserProfile` for the owning user or `TaggedDevices` |
| `Login` | `tailcfg.Login` for the owning user |
| `Error` | Error string if registration failed |

The `AuthURL` field is particularly sensitive — it contains the registration ID that, if obtained by an attacker (e.g., via MITM of an unencrypted followup polling channel), would allow them to steal the registration and associate the node with a different user. However, since all traffic is inside Noise, this is only a concern if the server itself is compromised or if the registration cache is accessible.

---

#### `/machine/map` — Data Accepted

The `MapRequest` body (JSON over Noise HTTP/2):

| Field | Type | Client-controlled | Notes |
|---|---|---|---|
| `NodeKey` | `key.NodePublic` | Yes | Must match session's MachineKey in DB |
| `Version` | `CapabilityVersion` | Yes | |
| `Hostinfo` | `tailcfg.Hostinfo` | Yes | Updated host info — fully client-controlled, written to DB |
| `Endpoints` | `[]tailcfg.Endpoint` | Yes | Node's network endpoints — written to DB |
| `Stream` | `bool` | Yes | Whether to hold the long-poll connection open |
| `OmitPeers` | `bool` | Yes | If true + no stream: lite endpoint-only update |
| `ReadOnly` | `bool` | Yes | If true: no state updates (informational only) |
| `DERPMap` | `*tailcfg.DERPMap` | Yes | Client's view of DERP map |
| `DebugFlags` | `[]string` | Yes | Client-requested debug settings |
| `TKAHead` | `tkatype.AUMHash` | Yes | Tailnet key authority state |

`UpdateNodeFromMapRequest()` (`state/state.go:2074`) processes this. Key operations:
- Updates `Hostinfo` in the NodeStore and DB if changed
- Updates `Endpoints` (network addresses) in NodeStore
- Triggers auto-approval evaluation for any newly advertised `RoutableIPs`
- Triggers policy re-evaluation if routes changed

A node can use repeated MapRequests to continuously update its `Hostinfo`, including `RoutableIPs`. Each update runs `policy.ApproveRoutesWithPolicy()` — meaning a node that gradually changes its advertised routes will have those routes checked against auto-approval policy on every update.

---

#### `/machine/map` — Data Returned

This is the most security-sensitive response in the entire system. The `MapResponse` contains:

| Field | Content |
|---|---|
| `Node` | The requesting node's full `tailcfg.Node` — its IPs, keys, capabilities |
| `Peers` | **All visible peers** — their IPs, `NodeKey`, `MachineKey`, `DiscoKey`, `Endpoints`, `Hostinfo`, `AllowedIPs`, `Capabilities`, `Online` status |
| `PacketFilters` | ACL filter rules scoped to this node — determines which traffic the node will allow |
| `DERPMap` | Full DERP relay server map with hostnames and IPs |
| `DNSConfig` | DNS resolvers, MagicDNS domains, split-DNS configuration |
| `SSHPolicy` | SSH access rules — which users/nodes can SSH into this node |
| `UserProfiles` | Display names, email addresses, profile picture URLs for all visible users |
| `Domain` | The tailnet domain name |
| `PeersChanged` / `PeersRemoved` | Incremental peer updates |
| `Debug` | Debug configuration (log tail settings) |

**The MapResponse is the crown jewel of this API surface.** It reveals the complete topology and access control configuration of the tailnet to each enrolled node. Peer `MachineKey`, `NodeKey`, `DiscoKey`, and `Endpoints` are all present — enough for a compromised node to attempt direct connection to any peer. Filter rules reveal exactly what traffic is permitted between nodes. `SSHPolicy` reveals who can SSH into what. `UserProfiles` leaks email addresses and display names for all users with visible nodes.

Critically, **policy-based peer filtering (`ReduceNodes`) is the only mechanism that limits what a node sees**. If a node's ACL policy is overly permissive, it will receive data about peers it shouldn't need to know about.

---

#### Ramifications if Compromised

**Scenario 1: Server's `noisePrivateKey` is stolen**
This is the highest-severity scenario. The key is loaded from disk at startup (`cfg.NoisePrivateKeyPath`, mode `0600`). If an attacker obtains this key:
- They can impersonate the headscale control server to any Tailscale client
- Clients have no way to detect the substitution — they trust whoever holds the private key corresponding to the public key at `/key`
- The attacker can send arbitrary `MapResponse`s to nodes: injecting peers, modifying ACLs, redirecting DNS, changing DERP relays, injecting SSH access rules
- The attacker can intercept registrations and steal `AuthURL` registration IDs
- **The entire tailnet is fully compromised.** There is no recovery path short of re-rolling the key and re-enrolling every node (since clients cache the server's public key)

**Scenario 2: A node's `key.MachinePrivate` is stolen**
- Attacker can authenticate as that node's machine identity
- They can re-register with a new `NodeKey`, effectively taking over the node's identity
- They receive the node's MapResponse — full peer list, ACLs, SSH policies for that node's visibility scope
- They can advertise arbitrary routes from that node's identity, potentially becoming a MITM for traffic if auto-approval is enabled
- Scope is limited to what that one node is permitted to see/do per ACL policy

**Scenario 3: A PreAuthKey is stolen before use**
- Attacker can enroll a new node into the tailnet with whatever identity the key grants
- If the key has tags, the attacker's node gets those tags and the access that comes with them
- If the key is reusable, the attacker can enroll multiple nodes
- The legitimate user's node enrollment will fail (if single-use key) or succeed (if reusable, both nodes exist)

**Scenario 4: MapResponse MITM / injection**
Not possible under normal operation due to Noise encryption, but if the server is compromised:
- Injecting fake peers into MapResponses can redirect traffic
- Replacing `PacketFilters` can open or close firewall rules on all nodes simultaneously
- Injecting SSH policies can grant attacker-controlled SSH access to any node
- Replacing `DERPMap` can route all relay traffic through attacker-controlled infrastructure
- Replacing `DNSConfig` can redirect DNS resolution across the entire tailnet

**Scenario 5: Client sends malicious `Hostinfo`**
- `Hostinfo.RoutableIPs` can manipulate route advertisement → if auto-approval is configured, can cause unintended routes to be approved across the network
- `Hostinfo.SSH_HostKeys` can inject fake SSH host keys into headscale's records
- `Hostinfo.Hostname` is sanitized by `util.EnsureHostname()` but the raw value is stored; any downstream processing trusting the stored hostname without sanitization could be affected
- `RequestTags` in `Hostinfo` — **MITIGATED**: `validateRequestTags()` (`state/state.go:1417`) now validates each requested tag against `PolicyManager.NodeCanHaveTag()` before applying. Unauthorized tags are rejected at both initial registration and re-auth (`state.go:1335-1349`, `state.go:1165`). `RoutableIPs` and `SSH_HostKeys` remain unvalidated.

---

#### Required for Steady-State Operation

**Yes — this is the only endpoint that enrolled nodes require for ongoing operation.**

Once a device is enrolled:
- `/ts2021` + `/machine/map` (streaming) must remain accessible at all times for the node to maintain its network map, receive peer updates, and stay in the tailnet
- `/machine/register` is only used at initial enrollment, re-authentication (when node key expires), and logout — not during normal steady-state polling
- The long-poll stream from `/machine/map` (with `Stream: true`) is kept open continuously; it is the primary channel through which all network topology changes, ACL updates, DNS changes, and SSH policy changes are pushed to nodes
- If `/machine/map` becomes inaccessible, enrolled nodes continue operating with their last-known network map but will not receive updates (new peers, ACL changes, etc.) until the connection is restored. Connectivity to already-known peers over direct WireGuard connections will continue working
- Keep-alive messages are sent every ~50–59 seconds (randomized jitter) to maintain the stream

---

### Noise Protocol Sub-Route Detail

The `/ts2021` upgrade creates a private HTTP/2 multiplexed channel. Only two routes are mounted on that internal router (`noise.go:97-103`):

```
POST /machine/register   → NoiseRegistrationHandler
*    /machine/map        → NoisePollNetMapHandler
```

Everything below runs within the Noise tunnel. The outer TLS/HTTP layer has no visibility into these requests.

---

#### `POST /machine/register` — Sub-Path Dispatch

`NoiseRegistrationHandler` passes every request to `handleRegister()` (`auth.go:27`), which dispatches to one of four sub-paths based on the request content:

**Sub-path 1 — Logout / expiry (checked first)**

Trigger: `req.Expiry` is non-zero and in the past, OR `req.Auth == nil` with a matching existing node.

`handleLogout()` (`auth.go:137`):
- **MachineKey check**: `node.MachineKey() != machineKey` → 401. This is the only server-side proof that the Noise session belongs to the node being logged out. It is correctly enforced.
- **Expiry check**: `node.IsExpired()` → returns `{NodeKeyExpired: true, MachineAuthorized: false}` immediately. A client that is already expired cannot silently re-register via the logout path.
- **Extension block**: `req.Expiry.After(time.Now())` → 400. Clients cannot extend their own key via this endpoint.
- Ephemeral nodes are deleted; non-ephemeral nodes have their expiry set to `req.Expiry`.

**Sub-path 2 — Followup poll (interactive / OIDC)**

Trigger: `req.Followup != ""`.

`waitForFollowup()` (`auth.go:258`):
- Parses `req.Followup` as a URL; only the path component is used.
- Extracts the `RegistrationID` from the path via `strings.ReplaceAll(fu.Path, "/register/", "")`.
- The ID is validated as a `RegistrationID` type (format-validated). An invalid ID returns 401.
- Blocks on a channel `reg.Registered` until the admin-side (`RegisterNode` gRPC or OIDC callback) sends the result, or the request context times out.
- **No MachineKey verification** at this point — the followup path relies on the caller holding the correct `RegistrationID`. The RegistrationID is random and unguessable, but is transmitted in the `AuthURL` field of the previous `RegisterResponse`. Since that response travels inside the Noise channel, it is protected in transit, but it is stored in an in-memory cache on the server for up to 15 minutes.
- If the cache entry is not found or is expired, a new registration flow is started and a new `AuthURL` is returned.

**Sub-path 3 — PreAuthKey registration**

Trigger: `req.Auth != nil && req.Auth.AuthKey != ""`.

`handleRegisterWithAuthKey()` → `state.HandleNodeFromPreAuthKey()`:
- PreAuthKey is looked up by prefix, then bcrypt-compared against the stored hash.
- Key must not be expired, and if single-use, must not have been used before.
- For existing nodes re-registering with the same MachineKey+NodeKey (e.g., container restart), PAK validation is **skipped** — the server trusts that the same Noise session (same MachineKey) establishing the connection is proof enough.
- For new nodes or NodeKey rotations, full PAK validation is always required.
- Tags from the PAK are applied to the node at registration time.

**Sub-path 4 — Interactive registration**

Trigger: none of the above conditions matched.

`handleRegisterInteractive()`:
- Generates a new `RegistrationID`.
- Stores a `RegisterNode` cache entry (with the node-to-register, MachineKey, NodeKey, Hostinfo) in the in-memory cache with a 15-minute TTL.
- Returns `{AuthURL: "<server>/register/<id>"}` to the client.
- **No user identity or authorization check occurs at this stage.** The node is not yet in the database. The `AuthURL` must be visited by an authenticated user (via CLI+gRPC or OIDC) before the registration completes.
- `reqToNewRegisterResponse()` calls `util.EnsureHostname()` to sanitize the hostname from client-supplied `Hostinfo`.

**`MachineAuthorized` in register responses**

`nodeToRegisterResponse()` (`auth.go:235`) hardcodes `MachineAuthorized: true` with the comment: *"Headscale does not implement the concept of machine authorization — revisit if #2176 gets implemented."*

The exception is the expired-node path in `handleLogout()` (line 163-167), which returns `MachineAuthorized: false` when the node's key is detected as expired during a logout/re-auth attempt.

---

#### `/machine/map` — Full Request Flow

`NoisePollNetMapHandler` (`noise.go:195`):

1. Reads and JSON-decodes the `MapRequest` body.
2. Calls `rejectUnsupported()` — checks `mapRequest.Version >= MinSupportedCapabilityVersion`. Rejects with 400 if too old.
3. Calls `getAndValidateNode(mapRequest)`.
4. Creates a `mapSession` and routes to `serve()` (non-streaming) or `serveLongPoll()` (streaming).

**`getAndValidateNode()` — what is and is NOT checked** (`noise.go:294-306`):

```go
func (ns *noiseServer) getAndValidateNode(mapRequest tailcfg.MapRequest) (types.NodeView, error) {
    nv, ok := ns.headscale.state.GetNodeByNodeKey(mapRequest.NodeKey)
    if !ok {
        return types.NodeView{}, NewHTTPError(http.StatusNotFound, "node not found", nil)
    }
    if ns.machineKey != nv.MachineKey() {
        return types.NodeView{}, NewHTTPError(http.StatusNotFound, "...", nil)
    }
    return nv, nil
}
```

| Check | Performed? | Notes |
|---|---|---|
| Node exists in DB/NodeStore | **Yes** | 404 if NodeKey not found |
| MachineKey ↔ NodeKey binding | **Yes** | 404 if mismatch — prevents cross-node impersonation |
| Node expiry (`IsExpired()`) | **No** | Expired nodes pass this check |
| Node deleted / soft-deleted | **No** | Relies on NodeStore cache not containing deleted nodes |
| `MachineAuthorized` state | **No** | Not implemented; always considered authorized |
| CapabilityVersion | **Yes** | Checked via `rejectUnsupported()` before this call |

**Confirmed: `IsExpired` has zero occurrences in both `poll.go` and `noise.go` (as of current review).** An expired node can successfully pass `getAndValidateNode()` and receive a full MapResponse.

**Non-streaming mode (`serve()`, `poll.go:100`)**:
- Calls `UpdateNodeFromMapRequest()` to process Hostinfo/Endpoints/route advertisements.
- If `OmitPeers && !Stream` (endpoint-only "lite" update): writes 200 with no body.
- No MapResponse with peer data is sent in this mode.
- No expiry check.

**Streaming mode (`serveLongPoll()`, `poll.go:132`)**:
- Calls `UpdateNodeFromMapRequest()` to sync initial state.
- Calls `state.Connect()` to mark the node online in the NodeStore.
- Registers the session channel with `mapBatcher.AddNode()`.
- Enters the main loop: reads `MapResponse` messages from the channel and writes them to the client via `writeMap()`.
- Keep-alive frames sent every ~50–59 seconds.
- **No expiry gate anywhere in this loop.** The session runs until the client disconnects or the context is cancelled.

**How expiry is communicated in the streaming path**:

1. `state.ExpireExpiredNodes()` runs on a 5-second ticker.
2. When a node's expiry timestamp passes, it emits a `change.KeyExpiryFor(node.ID, node.Expiry)` event.
3. The batcher translates this into a `MapResponse` where `Node.Expired = true` and `Node.MachineAuthorized = false` (set in `TailNode()` at `types/node.go:1093-1094`).
4. The expired node's map session channel receives this response and `writeMap()` delivers it to the client.
5. A **well-behaved Tailscale client** that receives `Expired: true` in its own node entry will stop routing traffic and re-initiate registration.

**The enforcement gap**: This mechanism is advisory and cooperative. The server never forcibly tears down the Noise connection or rejects subsequent `MapRequest`s from an expired node. A modified or compromised Tailscale client that ignores the `Expired` flag will continue to receive full `MapResponse` updates — including peer lists, IP addresses, packet filter rules, SSH policies, and DNS configuration — for as long as it keeps the connection open.

There is no server-side hard gate that checks expiry before serving a MapResponse. The security invariant relies on the client self-enforcing its own expiry signal.

**Comparison of expiry handling across endpoints**:

| Endpoint | Expiry enforced server-side? | Mechanism |
|---|---|---|
| `/machine/register` (logout path) | **Yes** — hard gate | `handleLogout()` checks `IsExpired()` → returns `NodeKeyExpired: true, MachineAuthorized: false`, blocks re-auth |
| `/machine/map` (streaming + non-streaming) | **No** — advisory only | Expired flag is sent in MapResponse; client expected to self-enforce |
| Admin gRPC `ExpireNode` | Sets the expiry in DB; triggers scheduler notification | Indirect — still relies on client response |

---

#### Node Authorization: Summary of Database Checks

The following table summarizes every authorization-related check that occurs before data is served on the Noise surface:

| Gate | Where | What it checks | What it does NOT check |
|---|---|---|---|
| Noise handshake | `noise.go:74-88` | Client possesses the private key corresponding to `MachineKey` | Whether `MachineKey` is registered, banned, or belongs to an expired node |
| `rejectUnsupported()` | `noise.go:161-184` | `CapabilityVersion >= min` | Any node-specific state |
| `getAndValidateNode()` | `noise.go:294-306` | NodeKey in NodeStore; MachineKey matches | Expiry, deletion, admin authorization flag |
| `handleLogout()` | `auth.go:137-227` | MachineKey matches node; node not expired; expiry not being extended | Only reached on register path, not map path |
| `UpdateNodeFromMapRequest()` | `state/state.go:2074` | Node exists by ID | Expiry, authorization state |
| `ReduceNodes()` (peer filter) | `policy/v2/policy.go` | ACL policy peer visibility | Whether the requesting node itself is expired |

**Notable absence**: There is no point in the `/machine/map` handling path that queries the database to verify the node is in good standing (non-expired, non-deleted, authorized). The lookup in `getAndValidateNode()` uses the in-memory `NodeStore` cache (not a fresh DB read), and checks only the key-binding invariant.

The practical consequence: the window between a node being administratively expired (via `ExpireNode` gRPC) and the expired node losing access to MapResponse data is bounded by:
1. The next `ExpireExpiredNodes()` tick (~5 seconds) to detect and emit the change
2. The time for the change to propagate through the batcher to the node's session channel
3. **The client choosing to act on the `Expired: true` signal**

Steps 1 and 2 are server-controlled and bounded. Step 3 is not.

---

# Headscale Security Architecture

Headscale is a self-hosted Tailscale control server. All Tailscale client communications use the **TS2021 / Noise protocol** (not the older HTTPS-based protocol).

---

## 1. Transport Layer & Key Infrastructure

### Noise Protocol (TS2021)
- **Entry point**: `hscontrol/noise.go` — `/ts2021` WebSocket upgrade path
- The server holds a long-term `key.MachinePrivate` (stored at `cfg.NoisePrivateKeyPath`, mode `0600`)
- The server also holds a separate `key.MachinePrivate` for the embedded DERP server (must differ from noise key — enforced at startup)
- Clients connect via `controlhttpserver.AcceptHTTP()` using Tailscale's upstream `controlbase` library
- After the Noise handshake, `noiseServer.machineKey` holds the authenticated peer's `key.MachinePublic`
- An **EarlyNoise** payload sends a `NodeKeyChallenge` (ephemeral `key.ChallengePrivate`) to the client immediately after handshake — used for key ownership proofs

### Public Key Exposure
- `GET /key?v={capver}` — unauthenticated endpoint that returns the server's Noise public key (`OverTLSPublicKeyResponse`)

### TLS
- Supports Let's Encrypt (ACME) or manual TLS certs
- `cfg.TLS` holds TLS settings; configured via `getTLSSettings()`

---

## 2. API Surfaces

### Surface A: Noise-encrypted client API (TS2021)
All Tailscale client traffic goes here. No HTTP-level auth — the Noise session itself is the authentication.

| Endpoint | Handler | Auth |
|---|---|---|
| `POST /machine/register` | `NoiseRegistrationHandler` | Noise session (machineKey) |
| `/machine/map` | `NoisePollNetMapHandler` | Noise session + `getAndValidateNode()` |

**Critical**: `getAndValidateNode()` (`noise.go:294`) validates that the `NodeKey` in the MapRequest belongs to the same `MachineKey` that established the Noise session. This prevents one machine from impersonating another.

### Surface B: Admin gRPC + REST API
Dual-access pattern — same service, two transports:

**Unix socket** (`cfg.UnixSocket`, `cfg.UnixSocketPermission`):
- gRPC server with **NO authentication** (relies on filesystem permissions)
- grpc-gateway connects to this socket internally to serve REST
- The CLI (`headscale` command) uses this

**TCP gRPC** (`cfg.GRPCAddr`):
- Protected by `grpcAuthenticationInterceptor` — requires `Authorization: Bearer <apikey>`
- Only active if TLS is configured OR `cfg.GRPCAllowInsecure = true`
- When `GRPCAllowInsecure`, logs a warning "gRPC is running without security"

**REST HTTP** (`/api/v1/...`):
- Protected by `httpAuthenticationMiddleware` — same API key check as gRPC
- grpc-gateway proxies these to the unix socket gRPC (which has no auth)
- The auth check is done at the HTTP layer before hitting the gateway

**No authorization granularity**: Any valid API key grants full admin access. There are no roles or scopes.

### Surface C: Unauthenticated HTTP
| Endpoint | Purpose | Notes |
|---|---|---|
| `GET /key` | Server's Noise public key | Required for client bootstrap |
| `GET /health` | DB connectivity check | Returns JSON |
| `GET /version` | Version info | Leaks version string |
| `GET /register/{registration_id}` | Interactive auth flow | RegistrationID validated |
| `GET /oidc/callback` | OIDC callback | State/nonce cookie validation |
| `POST /verify` | DERP client admission | Checks NodeKey membership |
| `GET /apple`, `/windows` | Platform config pages | Static content |
| `GET /swagger` | Swagger UI | |
| `/derp`, `/derp/probe`, `/bootstrap-dns` | DERP relay | If embedded DERP enabled |

---

## 3. Authentication Flows

### 3a. PreAuthKey Registration (`hscontrol/auth.go` + `db/preauth_keys.go`)
1. Client sends `RegisterRequest` with `Auth.AuthKey` over Noise
2. `handleRegisterWithAuthKey()` calls `state.HandleNodeFromPreAuthKey()`
3. Key lookup: prefix extracted, DB query, then `bcrypt.CompareHashAndPassword`
4. Validation: not expired, not used (if single-use), tags valid
5. Node created/updated in DB; if ephemeral+reused, old node deleted first

**Key format**: `hskey-auth-{12-char-prefix}-{64-char-secret}` (bcrypt of secret stored in DB)
**Legacy format**: plaintext key stored directly (backward compat)
**Security**: bcrypt at default cost; prefix used for indexed DB lookup

### 3b. Interactive / Web Auth (`hscontrol/auth.go`)
1. Client sends `RegisterRequest` with no auth key → gets `RegisterResponse.AuthURL`
2. URL contains a `RegistrationID` (opaque random ID) stored in an in-memory cache (15 min TTL)
3. User visits URL in browser; for web auth: shows CLI command to run
4. CLI calls `RegisterNode` gRPC with the registration key and desired username
5. Cache entry resolved → node registered

### 3c. OIDC Authentication (`hscontrol/oidc.go`)
1. `GET /register/{registration_id}` — generates CSRF state + nonce cookies, redirects to IdP
2. PKCE optionally supported (S256 or plain method)
3. `GET /oidc/callback` — validates state cookie, exchanges code, verifies ID token signature
4. Nonce validated from cookie vs ID token claim
5. Userinfo endpoint queried for groups/email
6. **Authorization checks** (`doOIDCAuthorization`):
   - `AllowedGroups` — checked regardless of email verification
   - `AllowedDomains` / `AllowedUsers` — only checked if email is verified (or `EmailVerifiedRequired=false`)
7. User created/updated in DB; node registered

**CSRF protection**: State and nonce stored as HttpOnly cookies, validated on callback. Cookie name uses first 6 chars of value (`getCookieName`).
**Notable edge**: If `AllowedGroups` is non-empty but `AllowedDomains`/`AllowedUsers` are empty with unverified email — groups check passes, domain/user checks skipped.

### 3d. API Key Authentication (`db/api_key.go`)
**Key format**: `hskey-api-{12-char-prefix}-{64-char-secret}` (bcrypt of secret stored in DB)
**Legacy format**: `{7-char-prefix}.{secret}` (dot-separated)
- Prefix used for indexed DB lookup
- `bcrypt.CompareHashAndPassword` for verification
- Expiration checked after hash verification
- All admin gRPC/REST endpoints require a valid non-expired key

---

## 4. Authorization Model

### Admin API (gRPC/REST)
- **All-or-nothing**: valid API key = full admin access
- No per-user, per-resource, or per-operation controls
- The unix socket bypasses all auth (OS-level protection only)

### Node API (Noise)
- MachineKey ↔ NodeKey binding enforced in `getAndValidateNode()`
- Logout prevents key extension (`req.Expiry.After(time.Now())` rejected)
- MachineKey must match stored node's MachineKey for logout operations

### Policy / ACL (`hscontrol/policy/v2/`)
- HuJSON ACL policy evaluated by `PolicyManager`
- Controls peer visibility, route approval, SSH access
- Supports `tag:` based identities, `autogroup:self`, users, groups
- Tag ownership validated via IP-based ACL rules (not UserID)

---

## 5. Tags-as-Identity Security Model

A core invariant: nodes are **either** tagged **or** user-owned, never both (XOR).
- `SetTags` gRPC prevents setting tags on user-owned nodes (`grpcv1.go:340-347`)
- Tagged nodes use `TaggedDevices` special user ID in MapResponse protocol
- `UserID` on tagged nodes is informational ("created by"), not ownership
- Always use `node.IsTagged()` to determine ownership, not `node.UserID().Valid()`

---

## 6. Notable Security Properties & Observations

### Positive
- Noise protocol provides mutual authentication for all client communications
- bcrypt used for both API keys and PreAuthKeys (not plain hash)
- OIDC CSRF protection via state + nonce cookies (HttpOnly)
- PKCE support for OIDC
- Key format includes prefix for indexed lookup + bcrypt for verification (avoids timing attacks on full-table scans)
- MachineKey↔NodeKey binding prevents session hijacking
- Expiry extension blocked at logout (can't extend your own key)
- DERP server key must differ from Noise key (enforced at startup)
- Registration IDs validated before use (prevents XSS via unvalidated path params)

### Areas of Interest for Security Review (Continued in Section 8)
- **No authorization granularity on admin API**: any API key = full admin. No scopes, no roles.
- **Unix socket auth bypass**: The grpc-gateway connects to unix socket with `insecure.NewCredentials()`. OS filesystem permissions are the only protection. Comment in code: "This is not secure, but it is to maintain maintainability"
- **`GRPCAllowInsecure` flag**: can run gRPC over plaintext TCP with auth in headers (credentials in plaintext)
- **`/verify` endpoint**: unauthenticated, leaks whether a NodeKey is registered (though only yes/no)
- **`/version` endpoint**: unauthenticated, leaks exact server version
- **`/health` endpoint**: unauthenticated, confirms DB connectivity
- **OIDC group bypass**: If only `AllowedGroups` is set (no domain/user filters), unverified emails could pass
- **DebugCreateNode** gRPC endpoint exposed in production builds — creates fake nodes in registration cache
- **Legacy PreAuthKey format**: plaintext keys still supported for backward compat (`key = ?` query)
- **`ListPreAuthKeys`** returns all keys across all users — no user-scoping
- **`ListApiKeys`** returns all keys — no owner concept
- **`BackfillNodeIPs`** is a potentially destructive admin operation requiring only `confirmed: true`
- **`SetPolicy`** can push arbitrary ACL policy that affects all nodes' peer visibility and routing
- **Metrics server** (`cfg.MetricsAddr`) — separate listener, no auth mentioned; exposes Prometheus metrics

### Key Storage
- Noise private key: file at `cfg.NoisePrivateKeyPath`, mode `0600`
- DERP private key: separate file, same permissions
- API key secrets: bcrypt hash in DB (prefix in plaintext for lookup)
- PreAuthKey secrets: bcrypt hash in DB (prefix in plaintext for lookup)
- OIDC client secret: in config file (`cfg.OIDC.ClientSecret` or `ClientSecretPath`)

---

## 8. In-Depth /ts2021 Security Analysis

### Route-by-Route Authentication and Node Validation

| Route | Handler | Authentication | Node In Network Check | Expiry Check |
|-------|---------|----------------|----------------------|--------------|
| `/ts2021` | `NoiseUpgradeHandler` | ✅ Noise handshake | ❌ None | N/A |
| `POST /machine/register` | `NoiseRegistrationHandler` | ✅ Noise session | ❌ **NO** | ❌ No new nodes |
| `POST /machine/map` | `NoisePollNetMapHandler` | ✅ Noise session | ✅ `getAndValidateNode()` | ❌ **NO** |

### Critical Finding: `/machine/register` Has No Node Validation

**Location**: `noise.go:234-290`

Unlike `/machine/map`, the `/machine/register` endpoint does NOT call `getAndValidateNode()`. This means:

- **ANY client** that completes the Noise handshake can attempt registration
- There is **NO check** that the node exists in the database before processing
- There is **NO check** that the node is pre-authorized (e.g., via PreAuthKey or pending registration)
- A new client can register ANY `NodeKey`/`MachineKey` pair and create a node in the system
- The node is created but requires admin intervention (via `RegisterNode` gRPC) to become fully enrolled

This is the **intended design** for interactive registration, but creates an attack surface.

### Attack Vectors for Security Assessment

#### Attack 1: Unauthenticated Node Registration

**Severity: HIGH**
**Location**: `noise.go:234`, `auth.go:27-133`

The `/machine/register` endpoint accepts ANY client with a valid Noise handshake. An attacker can:

1. Generate a new `MachineKey`/`NodeKey` pair
2. Complete the Noise handshake (proving possession of the private key)
3. Send a `RegisterRequest` with arbitrary `Hostinfo`
4. Receive a `RegisterResponse` with `MachineAuthorized: true`

```go
// NoiseRegistrationHandler does NOT validate node exists before processing
// From noise.go:234-290
registerRequest, registerResponse := func() {
    // ... reads and parses request ...
    resp, err = ns.headscale.handleRegister(req.Context(), regReq, ns.conn.Peer())
    // NO check that node is pre-authorized here
}
```

**Impact**:
- Attacker can create nodes in the registration cache
- Can poll with `Followup` URL to wait for admin approval
- Can see if registration was completed via followup response
- Node not fully enrolled until admin calls `RegisterNode` gRPC
- **No rate limit** — attacker can flood registration cache with unlimited entries (only time-based eviction)
- **No IP restriction by default** — `interactive_cidrs_whitelist` is opt-in; if not configured, any source IP can register interactively

**Mitigations**:
1. Pre-authorization check — require valid PreAuthKey or RegistrationID before accepting registration
2. **IP allowlisting** (`interactive_cidrs_whitelist`) — restrict `/machine/register` to trusted IP ranges (e.g., corporate VPN, admin network) — registrations from untrusted IPs require PreAuthKey
3. Rate limiting — throttle registration attempts per IP/client

**Implemented**: The `registration.interactive_cidrs_whitelist` config option is now in the codebase (`auth.go:131`, `types/config.go:245`). When configured, `isInteractiveRegistrationAllowed()` rejects interactive registration from IPs outside the specified CIDRs with an error requiring a PreAuthKey.

**Limitations of the implemented mitigation**:
- **Opt-in, not default**: When `InteractiveCIDRsWhitelist` is empty (default), `isInteractiveRegistrationAllowed()` returns `true` for all IPs (`auth.go:254`) — backward-compatible but leaves the original attack surface intact unless the operator explicitly configures the option.
- **Followup path not gated**: The `Followup` check at `auth.go:107-109` runs **before** the IP restriction check at `auth.go:131`. An attacker from an untrusted IP who somehow obtains a `RegistrationID` (e.g., from server logs or cache inspection) can still poll the followup endpoint from any IP. The RegistrationID is random and protected in transit by Noise, so the practical impact is low, but the IP restriction does not cover this path.
- **X-Real-IP spoofing**: `extractClientIP()` (`noise.go:237`) trusts the `X-Real-IP` header unconditionally. If headscale is exposed directly (no reverse proxy), an attacker can set `X-Real-IP: <trusted-IP>` to bypass the CIDR check. The mitigation is only effective when a properly configured reverse proxy is in place that strips or overwrites this header.
- No rate limiting is implemented.

---

#### Attack 2: Expired Node Persistence

**Severity: MEDIUM-HIGH**
**Location**: `noise.go:294-306`, `poll.go:132-269`

The `/machine/map` endpoint does NOT check node expiry in `getAndValidateNode()`. Confirmed: `IsExpired` has **zero occurrences** in both `poll.go` and `noise.go`.

**How it works**:
1. Admin expires node via `ExpireNode` gRPC
2. `ExpireExpiredNodes()` runs on 5-second ticker, detects expiry, emits change
3. Change propagates to node's map session channel
4. Node receives `MapResponse` with `Node.Expired = true`
5. **A modified client ignores this and keeps the connection open**
6. Server continues sending full MapResponse (peers, ACLs, SSH policies, DNS)

**Code path** (`poll.go` doesn't check expiry anywhere):
```go
// serveLongPoll() - no expiry gate
func (m *mapSession) serveLongPoll() {
    // ... main loop runs until client disconnects ...
    for {
        select {
        case update, ok := <-m.ch:
            // Just writes whatever comes from channel
            m.writeMap(update)
        }
    }
}
```

**Impact**:
- Expired nodes continue receiving complete network topology
- Peer IPs, ACLs, SSH policies, DNS config all exposed
- Server-side enforcement relies entirely on client cooperation

**Mitigation**: Add expiry check in `getAndValidateNode()`:
```go
func (ns *noiseServer) getAndValidateNode(mapRequest tailcfg.MapRequest) (types.NodeView, error) {
    nv, ok := ns.headscale.state.GetNodeByNodeKey(mapRequest.NodeKey)
    if !ok {
        return types.NodeView{}, NewHTTPError(http.StatusNotFound, "node not found", nil)
    }
    if ns.machineKey != nv.MachineKey() {
        return types.NodeView{}, NewHTTPError(http.StatusNotFound, "...", nil)
    }
    // ADD THIS CHECK
    if nv.IsExpired() {
        return types.NodeView{}, NewHTTPError(http.StatusForbidden, "node expired", nil)
    }
    return nv, nil
}
```

---

#### Attack 3: Deleted Node Persistence

**Severity: MEDIUM**
**Location**: `noise.go:294-306`

Similarly, `getAndValidateNode()` does NOT check if the node has been deleted from the NodeStore.

- When a node is deleted via `DeleteNode()`, it's removed from NodeStore
- If a client maintains an open connection, they could theoretically continue receiving updates
- **Practical protection**: NodeStore deletion is immediate and the node won't be found by `GetNodeByNodeKey()`

**Difference from expiry**: Deletion removes the node entirely from NodeStore, so the lookup fails. But if the connection stays open and the node isn't immediately purged from the batcher, there could be a race condition.

---

#### Attack 4: Hostinfo Manipulation

**Severity: LOW-MEDIUM**
**Location**: `auth.go:303`, `state.go`, `UpdateNodeFromMapRequest()`

- `Hostinfo` is **fully client-controlled** and written to database
- `Hostname` is sanitized by `EnsureHostname()` but raw value stored
- `RoutableIPs` feeds into route advertisement system
- `SSH_HostKeys` injects fake SSH host keys
- `RequestTags` — **MITIGATED**: now validated against `tagOwners` via `validateRequestTags()` (`state/state.go:1417`) before being applied. Unauthorized tags are rejected at both initial registration (`state.go:1335`) and re-auth (`state.go:1165`).

**Code** (`auth.go:303-307`):
```go
hostname := util.EnsureHostname(
    req.Hostinfo,
    machineKey.String(),
    req.NodeKey.String(),
)
hostinfo.Hostname = hostname  // Only hostname sanitized
```

**Remaining gap**: `RoutableIPs` and `SSH_HostKeys` remain unvalidated. A node can still inject arbitrary routes (subject to auto-approval policy) and arbitrary SSH host keys.

---

#### Attack 5: Registration Cache Timing

**Severity: LOW**
**Location**: `auth.go:258-288`, `state.go:1050-1062`

- Registration cache stores pending registrations for 15 minutes
- `RegistrationID` is random and unguessable
- But: An attacker with a valid `RegistrationID` can poll the followup endpoint
- Can see if registration was completed (different response)
- Can race with admin to complete registration first

**Code** (`auth.go:273-283`):
```go
if reg, ok := h.state.GetRegistrationCacheEntry(followupReg); ok {
    select {
    case <-ctx.Done():
        return nil, NewHTTPError(http.StatusUnauthorized, "registration timed out", err)
    case node := <-reg.Registered:
        if node == nil {
            return h.reqToNewRegisterResponse(req, machineKey)
        }
        return nodeToRegisterResponse(node.View()), nil
    }
}
```

**Impact**: Limited - requires knowing a valid `RegistrationID`, which is random.

---

### Security Gaps Summary (Updated)

| Gap | Location | Severity | Status | Risk |
|-----|----------|----------|--------|------|
| No node-in-network check on `/machine/register` | `noise.go:234` | HIGH | **PARTIALLY MITIGATED** (opt-in `interactive_cidrs_whitelist`) | Unauthenticated node creation; IP check bypassable without reverse proxy |
| No expiry check on `/machine/map` | `noise.go:294` | MEDIUM-HIGH | **NOT MITIGATED** | Expired nodes pass `getAndValidateNode()` |
| No deletion check on `/machine/map` | `noise.go:294` | MEDIUM | **EFFECTIVELY MITIGATED** | NodeStore deletion removes node from cache; `GetNodeByNodeKey()` returns false |
| Hostinfo `RequestTags` not validated | `auth.go`, `state.go` | LOW-MEDIUM | **MITIGATED** (`validateRequestTags()`) | Tags now validated against policy before applying |
| Hostinfo other fields not validated (`RoutableIPs`, `SSH_HostKeys`) | `state.go` | LOW-MEDIUM | **NOT MITIGATED** | Arbitrary route/key injection possible |
| Followup URL parsing | `auth.go:263` | LOW | **NOT MITIGATED** | Attacker-supplied URL processed; IP restriction bypassed on this path |
| No server-side hard block on expired nodes | `poll.go` | MEDIUM-HIGH | **NOT MITIGATED** | Client cooperation required; modified client continues receiving full MapResponse |
| `X-Real-IP` trusted without verification | `noise.go:237` | MEDIUM | **NOT MITIGATED** | IP allowlist bypassable when headscale is directly internet-exposed (no reverse proxy) |

### Additional Findings from Code Review (2026)

| Gap | Location | Severity | Status | Risk |
|-----|----------|----------|--------|------|
| MapRequest `ReadOnly` flag not enforced | `poll.go`, `noise.go` | MEDIUM | **NOT MITIGATED** | Clients claiming read-only can still update state (endpoints, hostinfo, routes) |
| Rate limiting disabled by default | `config-example.yaml` | HIGH | **NOT MITIGATED** | Registration rate limiting defaults to 0 (disabled), vulnerable to DoS |
| No endpoint validation | `types/node.go:533` | LOW | **NOT MITIGATED** | Endpoints stored without validating IP:port format |
| No Hostinfo size limits | `state/state.go` | LOW | **NOT MITIGATED** | Unbounded Hostinfo data could lead to DoS via large payloads |
| Client DERPMap storage not validated | `poll.go` | LOW | **NOT MITIGATED** | DERPMap from client stored without validation |
| DebugFlags not sanitized | `poll.go` | INFO | **NOT MITIGATED** | Debug flags from client processed without validation |

#### N1: MapRequest ReadOnly Flag Not Enforced

**Severity: MEDIUM**
**Location**: `poll.go`, `noise.go`

The `MapRequest` struct includes a `ReadOnly` field that clients can set to indicate they want a read-only session. However, the server never checks this flag and always processes state updates:

```go
// In poll.go:serve() and serveLongPoll()
// No check for: if m.req.ReadOnly { ... }
c, err := m.h.state.UpdateNodeFromMapRequest(m.node.ID, m.req)
```

**Impact**:
- Clients can claim to be read-only but still update their endpoints, hostinfo, and routes
- Could bypass audit requirements if ReadOnly is used for auditing purposes
- Confusion in network debugging scenarios

**Mitigation**: Add check at the beginning of `serve()` and `serveLongPoll()` to skip state updates when `ReadOnly` is true.

---

#### N2: Rate Limiting Disabled by Default

**Severity: HIGH**
**Location**: `config-example.yaml`, `types/config.go`

Both registration and noise handshake rate limiting default to disabled:

```yaml
registration:
  rate_limit:
    requests_per_second: 0  # DISABLED by default!

noise:
  rate_limit:
    requests_per_second: 1  # Only noise handshake defaults to 1 RPS
```

**Impact**:
- Registration endpoint is vulnerable to DoS attacks
- Attackers can flood the in-memory registration cache with unlimited entries
- No protection against brute-force registration attempts

**Mitigation**: Enable rate limiting by default or document prominently as a required security hardening step.

---

#### N3: No Endpoint Validation

**Severity: LOW**
**Location**: `types/node.go:533`

Endpoints are stored directly from client input without validation:

```go
// In types/node.go:PeerChangeFromMapRequest
if EndpointsChanged(node.Endpoints, req.Endpoints) {
    ret.Endpoints = req.Endpoints
}
```

No validation that endpoints are valid `IP:port` combinations.

**Impact**:
- Malformed endpoint data could be stored in database
- Potential for parsing errors in downstream processing

---

#### N4: No Hostinfo Size Limits

**Severity: LOW**
**Location**: `state/state.go`

The Hostinfo structure can contain arbitrarily large amounts of data:
- Long lists of `RoutableIPs`
- Large `SSH_HostKeys` arrays
- Extensive `Services` lists

**Impact**:
- DoS via large payload submissions
- Database bloat from large stored Hostinfo

**Mitigation**: Add size limits on Hostinfo fields during MapRequest processing.

---

#### N5: Client DERPMap Storage Not Validated

**Severity: LOW**
**Location**: `poll.go`

The `MapRequest.DERPMap` field from clients is stored but not validated. Clients can send arbitrary DERP configurations.

**Impact**:
- Could potentially manipulate client's view of DERP servers
- Limited impact as DERPMap is client-provided and transient

---

#### N6: DebugFlags Not Sanitized

**Severity: INFO**
**Location**: `poll.go`

Debug flags from clients are processed without validation. The `MapRequest.DebugFlags` field is passed through to the MapResponse.

**Impact**: Minimal - debug flags are for development/diagnostics only.

## Architecture-Mitigated Vulnerabilities

> **Applies to deployments where a reverse proxy (e.g., Caddy, Nginx) exposes only `/key` and `/ts2021` to the internet, with all admin API endpoints restricted to internal networks or localhost.**

The following vulnerabilities are **not applicable** or **significantly reduced** in such deployments:

| Finding | Original Severity | Mitigated By |
|---------|-------------------|--------------|
| F5: No authorization granularity | HIGH | gRPC/REST endpoints not internet-exposed |
| F6: Unix socket auth bypass | CRITICAL | Socket not accessible from internet |
| F7: DebugCreateNode in production | CRITICAL | Debug endpoints not internet-exposed |
| F8: SetPolicy affects all nodes | CRITICAL | Policy endpoint not internet-exposed |
| F9: OIDC group bypass | MEDIUM | OIDC endpoints not internet-exposed |
| F10: /verify leaks NodeKey status | LOW-MEDIUM | `/verify` not internet-exposed |
| F11: ListPreAuthKeys no scoping | HIGH | PreAuthKey endpoints not internet-exposed |
| F12: ListApiKeys no owner concept | HIGH | API key endpoints not internet-exposed |
| F13: BackfillNodeIPs destructive | HIGH | Node endpoints not internet-exposed |

The **remaining internet-facing vulnerabilities** (F1-F4) are inherent to the Noise protocol endpoint and should still be considered:

- **F1** (No node validation on `/machine/register`): Any client can register — but the node won't be fully enrolled until admin approval
- **F2/F3** (Expired node persistence): Requires modified client to ignore expiry
- **F4** (Hostinfo manipulation): Client can supply arbitrary host info

---

## Recommendations

1. **`interactive_cidrs_whitelist` — strengthen the implementation** *(PARTIALLY DONE)*
   - The CIDR-based IP restriction is implemented but opt-in. Consider documenting it prominently as a security-hardening step.
   - Fix the `X-Real-IP` trust model: only honor the header when a trusted proxy is configured, or document that the feature requires a reverse proxy to be effective.
   - Gate the `Followup` polling path with the same IP check, or require the caller to have the Noise session that initiated the registration.

2. **Check expiry in `getAndValidateNode()`** *(NOT DONE)* — Reject expired nodes at the authentication gate before serving any MapResponse. A one-line `nv.IsExpired()` check prevents the cooperative-client reliance entirely.

3. **Check deletion state in `getAndValidateNode()`** *(EFFECTIVELY DONE by NodeStore design)* — NodeStore deletion removes the node from cache so `GetNodeByNodeKey()` returns false. No code change needed; document as mitigated.

4. **Rate limit registration attempts** *(NOT DONE)* — Prevent registration spam from compromised clients flooding the in-memory registration cache.

5. **Validate remaining Hostinfo fields** *(PARTIALLY DONE)* — `RequestTags` are now validated against policy. Still needed: validate `RoutableIPs` format/range before route auto-approval decisions; restrict or strip `SSH_HostKeys` if SSH integration is not in use.

6. **Force-close Noise connection on expiry** *(NOT DONE)* — Instead of relying on the `Expired` flag in MapResponse, the server should forcibly cancel the `serveLongPoll` context when it emits a `KeyExpiryFor` change event. This eliminates the cooperative-client dependency.

7. **Proxy configuration review** — Ensure the reverse proxy correctly restricts to only `/key` and `/ts2021` — any misconfiguration exposing additional endpoints reintroduces the mitigated vulnerabilities in the Architecture-Mitigated section above. The `X-Real-IP` trust in `extractClientIP()` makes this a hard dependency for the IP-allowlist feature.

8. **Enforce MapRequest ReadOnly flag** *(NOT DONE)* — Add check in `serve()` and `serveLongPoll()` to skip state updates when `MapRequest.ReadOnly` is true.

9. **Enable rate limiting by default** *(NOT DONE)* — Change the default value for registration rate limiting from 0 to a sensible default (e.g., 1 RPS) to protect against DoS attacks.

10. **Add Hostinfo size limits** *(NOT DONE)* — Add validation to limit the size of Hostinfo fields during MapRequest processing to prevent DoS via large payloads.

---

## 9. Security Issue Scoring System

### CVSS-Based Scoring Framework

Each security issue is scored using a modified CVSS 3.1 approach adapted for headscale:

**Severity Ratings:**
- **Critical (9.0-10.0)**: Immediate remote compromise, data breach, or complete system takeover
- **High (7.0-8.9)**: Significant impact requiring urgent attention
- **Medium (4.0-6.9)**: Moderate impact, should be addressed
- **Low (0.1-3.9)**: Limited impact, can be addressed in future releases
- **Info (0.0)**: Informational, no direct security impact

**Scoring Dimensions:**

| Dimension | Weight | Description |
|-----------|--------|-------------|
| **Exploitability** | 30% | How easy is it to exploit? (network access, skill required, tools needed) |
| **Impact** | 30% | What can an attacker achieve? (data confidentiality, integrity, availability) |
| **Authentication** | 20% | What authentication is required? (none, valid key, admin key) |
| **Privilege Level** | 10% | What privileges does the attacker gain? (none, user, admin, system) |
| **Remediation Difficulty** | 10% | How hard is it to fix? (trivial, requires code change, requires config change) |

---

## 10. Complete API Endpoint Security Assessment

### Endpoint Inventory

| # | Endpoint | Surface | Auth Method | Score | Severity | Finding |
|---|----------|---------|-------------|-------|----------|---------|
| 1 | `POST /ts2021` | Noise | Noise handshake | 3.5 | LOW | WebSocket upgrade, no sensitive data |
| 2 | `POST /machine/register` | Noise | Noise session | **6.0** | **MEDIUM** | Partially mitigated by opt-in `interactive_cidrs_whitelist`; bypassable via X-Real-IP spoofing without reverse proxy |
| 3 | `POST /machine/map` | Noise | Noise + getAndValidateNode | **6.5** | **MEDIUM** | No expiry check |
| 4 | `GET /key?v={capver}` | HTTP | None | 2.0 | LOW | Exposes server public key (required) |
| 5 | `GET /health` | HTTP | None | 2.5 | LOW | Exposes DB connectivity status |
| 6 | `GET /version` | HTTP | None | 3.0 | LOW | Exposes server version |
| 7 | `GET /register/{id}` | HTTP | None | 4.0 | LOW | Starts OIDC flow, validates ID |
| 8 | `GET /oidc/callback` | HTTP | None | 5.0 | MEDIUM | CSRF protection present but complex |
| 9 | `POST /verify` | HTTP | None | 4.5 | LOW-MEDIUM | Leaks NodeKey registration status |
| 10 | `GET /apple`, `/apple/{platform}` | HTTP | None | 2.0 | LOW | Static config response |
| 11 | `GET /windows` | HTTP | None | 2.0 | LOW | Static config response |
| 12 | `GET /swagger` | HTTP | None | 2.5 | LOW | API documentation |
| 13 | `GET /derp`, `/derp/probe`, `/derp/latency-check` | HTTP | None | 3.0 | LOW | DERP functionality |
| 14 | `GET /bootstrap-dns` | HTTP | None | 3.0 | LOW | DNS configuration |
| 15 | `POST /api/v1/user` | gRPC/REST | API key | **8.5** | **HIGH** | Full admin - creates users |
| 16 | `POST /api/v1/user/{name}/rename` | gRPC/REST | API key | **8.5** | **HIGH** | Full admin - renames users |
| 17 | `DELETE /api/v1/user/{name}` | gRPC/REST | API key | **8.5** | **HIGH** | Full admin - deletes users |
| 18 | `GET /api/v1/user` | gRPC/REST | API key | **7.0** | HIGH | Lists all users (no scoping) |
| 19 | `POST /api/v1/preauthkey` | gRPC/REST | API key | **7.5** | HIGH | Creates PreAuthKey, can have tags |
| 20 | `POST /api/v1/preauthkey/expire` | gRPC/REST | API key | **7.5** | HIGH | Expires PreAuthKey |
| 21 | `DELETE /api/v1/preauthkey` | gRPC/REST | API key | **7.5** | HIGH | Deletes PreAuthKey |
| 22 | `GET /api/v1/preauthkey` | gRPC/REST | API key | **7.0** | HIGH | Lists all keys (no user scoping) |
| 23 | `POST /api/v1/node/register` | gRPC/REST | API key | **8.0** | HIGH | Completes node registration |
| 24 | `GET /api/v1/node` | gRPC/REST | API key | **7.5** | HIGH | Lists all nodes |
| 25 | `POST /api/v1/node/{id}/tags` | gRPC/REST | API key | **7.5** | HIGH | Sets tags on nodes |
| 26 | `POST /api/v1/node/{id}/routes` | gRPC/REST | API key | **7.5** | HIGH | Sets approved routes |
| 27 | `DELETE /api/v1/node/{id}` | gRPC/REST | API key | **8.5** | HIGH | Deletes any node |
| 28 | `POST /api/v1/node/{id}/expire` | gRPC/REST | API key | **7.5** | HIGH | Expires node key |
| 29 | `POST /api/v1/node/{id}/rename` | gRPC/REST | API key | **7.5** | HIGH | Renames node |
| 30 | `POST /api/v1/node/ip` | gRPC/REST | API key | **8.0** | HIGH | Potentially destructive IP backfill |
| 31 | `POST /api/v1/apikey` | gRPC/REST | API key | **8.5** | HIGH | Creates new API key (full admin) |
| 32 | `POST /api/v1/apikey/expire` | gRPC/REST | API key | **7.5** | HIGH | Expires API key |
| 33 | `GET /api/v1/apikey` | gRPC/REST | API key | **7.5** | HIGH | Lists all keys (no owner) |
| 34 | `DELETE /api/v1/apikey` | gRPC/REST | API key | **8.0** | HIGH | Deletes API key |
| 35 | `GET /api/v1/policy` | gRPC/REST | API key | **7.5** | HIGH | Reads ACL policy |
| 36 | `POST /api/v1/policy` | gRPC/REST | API key | **9.0** | CRITICAL | Sets ACL policy (affects all nodes) |
| 37 | `GET /api/v1/health` | gRPC/REST | API key | 4.0 | LOW | Database health check |
| 38 | `POST /api/v1/debug/node` | gRPC/REST | API key | **9.0** | CRITICAL | DebugCreateNode in production |
| 39 | Unix Socket | gRPC | None | **9.0** | CRITICAL | Filesystem-only protection |

### Detailed Endpoint Assessments

#### Surface A: Noise Protocol (TS2021)

##### 1. POST /ts2021
- **Handler**: `NoiseUpgradeHandler` (`noise.go:50`)
- **Auth**: Noise handshake (mutual TLS-like)
- **Score**: 3.5 (LOW)
- **Findings**: WebSocket upgrade endpoint, performs Noise handshake, no sensitive data exposed

##### 2. POST /machine/register
- **Handler**: `NoiseRegistrationHandler` (`noise.go:256`)
- **Auth**: Noise session + machineKey
- **Score**: 6.0 (MEDIUM) — reduced from 7.5 due to partial mitigation
- **Findings**:
  - **PARTIALLY MITIGATED**: `interactive_cidrs_whitelist` config option (`auth.go:131`) restricts interactive registration to trusted CIDRs when configured; requires PreAuthKey from other IPs
  - **Opt-in only**: Default config allows all IPs (backward compat). Mitigation is inert until operator configures the option.
  - **Followup path not gated**: The `Followup` branch (`auth.go:107`) runs before the IP check; any IP can poll an in-progress registration by ID
  - **X-Real-IP spoofing**: `extractClientIP()` (`noise.go:237`) trusts `X-Real-IP` header; without a properly configured reverse proxy, the IP check is bypassable
  - Hostinfo `RequestTags` are now validated against policy; `RoutableIPs` and `SSH_HostKeys` remain unvalidated

##### 3. POST /machine/map
- **Handler**: `NoisePollNetMapHandler` (`noise.go:195`)
- **Auth**: Noise session + getAndValidateNode()
- **Score**: 6.5 (MEDIUM)
- **Findings**:
  - No expiry check in getAndValidateNode
  - No deletion state check
  - Relies on client cooperation for expiry enforcement

#### Surface B: Unauthenticated HTTP

##### 4. GET /key
- **Handler**: `KeyHandler` (`handlers.go:140`)
- **Auth**: None (required for client bootstrap)
- **Score**: 2.0 (LOW)
- **Findings**: Exposes server Noise public key - required for operation

##### 5. GET /health
- **Handler**: `HealthHandler` (`handlers.go:164`)
- **Auth**: None
- **Score**: 2.5 (LOW)
- **Findings**: Confirms DB connectivity, no sensitive data

##### 6. GET /version
- **Handler**: `VersionHandler` (`handlers.go:213`)
- **Auth**: None
- **Score**: 3.0 (LOW)
- **Findings**: Exposes server version string

##### 7. GET /register/{id}
- **Handler**: `RegisterHandler` (`handlers.go:252` or `oidc.go:110`)
- **Auth**: None
- **Score**: 4.0 (LOW)
- **Findings**: Validates RegistrationID format, starts auth flow

##### 8. GET /oidc/callback
- **Handler**: `OIDCCallbackHandler` (`oidc.go:182`)
- **Auth**: None (state cookie)
- **Score**: 5.0 (MEDIUM)
- **Findings**:
  - CSRF protection via state/nonce cookies
  - OIDC group bypass if only AllowedGroups configured
  - No email verification check if EmailVerifiedRequired=false

##### 9. POST /verify
- **Handler**: `VerifyHandler` (`handlers.go:120`)
- **Auth**: None
- **Score**: 4.5 (LOW-MEDIUM)
- **Findings**: Leaks whether a NodeKey is registered (yes/no)

##### 10-13. Static/DERP Endpoints
- **Handlers**: Various static handlers
- **Auth**: None
- **Score**: 2.0-3.0 (LOW)
- **Findings**: Static content, DERP functionality, no sensitive data

#### Surface C: Admin gRPC/REST API

##### 15-22. User & PreAuthKey Management
- **Handlers**: `grpcv1.go:45-230`
- **Auth**: API key
- **Score**: 7.0-8.5 (HIGH)
- **Findings**:
  - All-or-nothing admin access
  - ListPreAuthKeys returns all keys across all users
  - No user scoping on list operations

##### 23-30. Node Management
- **Handlers**: `grpcv1.go:231-560`
- **Auth**: API key
- **Score**: 7.5-8.5 (HIGH)
- **Findings**:
  - BackfillNodeIPs is potentially destructive
  - DeleteNode can remove any node
  - SetTags can modify node identity

##### 31-34. API Key Management
- **Handlers**: `grpcv1.go:563-655`
- **Auth**: API key
- **Score**: 7.5-8.5 (HIGH)
- **Findings**:
  - ListApiKeys returns all keys (no owner concept)
  - Creates new full-privilege keys

##### 35-36. Policy Management
- **Handlers**: `grpcv1.go:658-755`
- **Auth**: API key
- **Score**: 7.5-9.0 (HIGH-CRITICAL)
- **Findings**:
  - SetPolicy can push arbitrary ACLs affecting all nodes
  - GetPolicy exposes current ACL rules

##### 38. Debug Endpoints
- **Handler**: `DebugCreateNode` (`grpcv1.go:757`)
- **Auth**: API key
- **Score**: 9.0 (CRITICAL)
- **Findings**: Creates fake nodes in registration cache, exposed in production builds

##### 39. Unix Socket
- **Auth**: None (filesystem permissions)
- **Score**: 9.0 (CRITICAL)
- **Findings**: No authentication, relies on OS filesystem permissions

### Detailed Security Findings with Scores

> **Architecture Note**: This analysis assumes a deployment where Caddy (or similar reverse proxy) exposes only `/key` and `/ts2021` to the internet, with all admin gRPC/REST endpoints and other HTTP endpoints accessible only from the internal network or localhost.

| ID | Finding | Endpoint | Exposed to Internet? | Mitigated by Proxy? | Original Score | Adjusted Score | Adjusted Severity |
|----|---------|----------|:--------------------:|:-------------------:|:--------------:|:---------------:|:-----------------:|
| F1 | No node validation on registration | `/machine/register` | Yes (`/ts2021`) | No | 7.5 | 7.5 | HIGH |
| F2 | Expired nodes can persist | `/machine/map` | Yes (`/ts2021`) | No | 6.5 | 6.5 | MEDIUM |
| F3 | No server-side expiry enforcement | Streaming loop | Yes (`/ts2021`) | No | 6.5 | 6.5 | MEDIUM |
| F4 | Hostinfo manipulation | All Noise endpoints | Yes (`/ts2021`) | No | 4.5 | 4.5 | LOW-MEDIUM |
| F5 | No authorization granularity | All gRPC/REST | **No** | **Yes** | 8.5 | 3.0 | LOW |
| F6 | Unix socket auth bypass | Unix socket | **No** (local only) | **Yes** | 9.0 | 3.0 | LOW |
| F7 | DebugCreateNode in production | `/api/v1/debug/node` | **No** | **Yes** | 9.0 | 3.0 | LOW |
| F8 | SetPolicy affects all nodes | `/api/v1/policy` | **No** | **Yes** | 9.0 | 3.0 | LOW |
| F9 | OIDC group bypass | `/oidc/callback` | **No** | **Yes** | 5.0 | 1.5 | INFO |
| F10 | /verify leaks NodeKey status | `/verify` | **No** | **Yes** | 4.5 | 1.5 | INFO |
| F11 | ListPreAuthKeys no scoping | `/api/v1/preauthkey` | **No** | **Yes** | 7.0 | 3.0 | LOW |
| F12 | ListApiKeys no owner concept | `/api/v1/apikey` | **No** | **Yes** | 7.5 | 3.0 | LOW |
| F13 | BackfillNodeIPs destructive | `/api/v1/node/ip` | **No** | **Yes** | 8.0 | 3.0 | LOW |

### Attack Chain Scenarios

#### Scenario 1: Full Network Compromise via API Key
1. Attacker obtains valid API key (via phishing, insider, or breach)
2. Score: 8.5 → Attack succeeds with full admin access
3. Attacker can:
   - Create new admin API keys
   - Modify ACL policy to allow all traffic
   - Delete nodes or create fake nodes
   - Exfiltrate all node information

#### Scenario 2: Node Persistence After Expiry
1. Admin expires malicious node via gRPC
2. Score: 6.5 → Node continues receiving updates
3. Attacker-modified client ignores Expired flag
4. Node persists with full network visibility

#### Scenario 3: Unauthorized Node Registration
1. Attacker connects to /ts2021 with new key pair
2. Score: 7.5 → Registration accepted
3. Node created in registration cache
4. Waits for admin approval - can poll status

---

## 11. File Reference Map
