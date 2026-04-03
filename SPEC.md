# SPEC.md — libtor

A pure-Python implementation of the Tor protocol following the specification at https://spec.torproject.org/tor-spec/

## Purpose

A pure-Python implementation of the Tor protocol — not a wrapper around the Tor binary, but the actual protocol speaking directly to relays using TLS, ntor/CREATE_FAST handshakes, and onion-encrypted relay cells. Also includes a SOCKS4/5 proxy server to route arbitrary applications through Tor.

## Scope

### What IS in scope

- TLS connection to Tor relays (OR connections)
- Link protocol negotiation (VERSIONS, CERTS, NETINFO) per tor-spec §4
- Circuit creation using CREATE_FAST for the first hop (tor-spec §5.1)
- Circuit extension using ntor handshake (EXTEND2) for subsequent hops (tor-spec §5.1.4)
- ntor-v3 handshake (Curve25519 + SHA3-256) for modern circuit creation (tor-spec §5.1.5)
- Onion-encrypted relay cells (AES-128-CTR + SHA-1 running digests) per tor-spec §5.2
- Stream multiplexing (RELAY_BEGIN / RELAY_DATA / RELAY_END) per tor-spec §6
- Flow control with SENDME windows (tor-spec §7.4)
- Directory client fetching v3 consensus and microdescriptors (dir-spec)
- DNS-over-Tor resolution (RELAY_RESOLVE)
- HTTP convenience methods on streams
- Guard-state persistence (tor-spec §2.3)
- ntor key cache with TTL-based eviction and stale key cooldown (SQLite)
- SOCKS4/5 proxy server for routing arbitrary applications through Tor
- Configuration via YAML file or environment variables

### What is NOT in scope

- Hidden service (.onion) client or server support
- HTTPS transparent proxying (port 443)
- Relay descriptor verification (accepts TLS without cert verification)
- Pluggable transport support
- Relay-side functionality (only implements client behavior)
- Tor daemon compatibility (this is a client library, not Tor)

## Protocol Compliance

### Cell Format (tor-spec §3)

**Fixed-length cell:**
| Field | Size (v1-3) | Size (v4+) |
|-------|-------------|------------|
| CircID | 2 bytes | 4 bytes |
| Command | 1 byte | 1 byte |
| Body | 509 bytes | 509 bytes |

**Variable-length cell:**
| Field | Size |
|-------|------|
| CircID | 2 or 4 bytes |
| Command | 1 byte |
| Length | 2 bytes (big-endian) |
| Body | Length bytes |

- `CELL_SIZE`: 512 bytes (v1-3), 514 bytes (v4+)
- `PAYLOAD_LEN`: 509 bytes
- Variable-length cells: Command >= 128 or Command == 7 (VERSIONS)
- VERSIONS always sent with circ_id=0 (no version negotiated yet)

### Cell Commands (tor-spec §3.3)

| Code | Name | CircID | Protocol | Description | Variable-Length |
|------|------|--------|----------|-------------|-----------------|
| 0 | PADDING | N | - | Link padding | No |
| 1 | CREATE | Y | - | Create circuit (deprecated) | No |
| 2 | CREATED | Y | - | Acknowledge CREATE (deprecated) | No |
| 3 | RELAY | Y | - | End-to-end data | No |
| 4 | DESTROY | Y | - | Stop using a circuit | No |
| 5 | CREATE_FAST | Y | - | Create circuit, no public key | No |
| 6 | CREATED_FAST | Y | - | Acknowledge CREATE_FAST | No |
| 7 | VERSIONS | N | - | Negotiate link protocol | Yes |
| 8 | NETINFO | N | - | Time and address info | No |
| 9 | RELAY_EARLY | Y | - | End-to-end data; limited | No |
| 10 | CREATE2 | Y | - | Extended CREATE cell | No |
| 11 | CREATED2 | Y | - | Extended CREATED cell | No |
| 12 | PADDING_NEGOTIATE | Y | 5 | Padding negotiation | No |
| 128 | VPADDING | N | - | Variable-length padding | Yes |
| 129 | CERTS | N | - | Certificates | Yes |
| 130 | AUTH_CHALLENGE | N | - | Challenge value | Yes |
| 131 | AUTHENTICATE | N | - | Client authentication | Yes |
| 132 | AUTHORIZE | N | - | (Reserved) | Yes |

- CircID column: Y = nonzero required, N = must be zero

### Relay Commands (tor-spec §6.1)

| Code | Name | Type | Description |
|------|------|------|-------------|
| 1 | BEGIN | F | Open a stream |
| 2 | DATA | F/B | Transmit data |
| 3 | END | F/B | Close a stream |
| 4 | CONNECTED | B | Stream has successfully opened |
| 5 | SENDME | F/B, C | Acknowledge traffic |
| 6 | EXTEND | F, C | Extend a circuit with TAP (obsolete) |
| 7 | EXTENDED | B, C | Finish extending a circuit with TAP (obsolete) |
| 8 | TRUNCATE | F, C | Remove nodes from a circuit |
| 9 | TRUNCATED | B, C | Circuit truncated |
| 10 | DROP | F/B, C | Long-range padding |
| 11 | RESOLVE | F | Hostname lookup |
| 12 | RESOLVED | B | Hostname resolved |
| 13 | BEGIN_DIR | F | Open a directory stream |
| 14 | EXTEND2 | F, C | Extend a circuit with ntor |
| 15 | EXTENDED2 | B, C | Finish extending a circuit with ntor |
| 16-18 | Reserved | - | Reserved for UDP |
| 19 | CONFLUX_LINK | F, C | Link circuits into a bundle |
| 20 | CONFLUX_LINKED | B, C | Acknowledge link request |
| 21 | CONFLUX_LINKED_ACK | F, C | Acknowledge CONFLUX_LINKED message |
| 22 | CONFLUX_SWITCH | F/B, C | Switch between circuits in a bundle |
| 32 | ESTABLISH_INTRO | F, C | Create introduction point |
| 33 | ESTABLISH_RENDEZVOUS | F, C | Create rendezvous point |
| 34 | INTRODUCE1 | F, C | Introduction request (to intro point) |
| 35 | INTRODUCE2 | B, C | Introduction request (to service) |
| 36 | RENDEZVOUS1 | F, C | Rendezvous request (to rendezvous point) |
| 37 | RENDEZVOUS2 | B, C | Rendezvous request (to client) |
| 38 | INTRO_ESTABLISHED | B, C | Acknowledge ESTABLISH_INTRO |
| 39 | RENDEZVOUS_ESTABLISHED | B, C | Acknowledge ESTABLISH_RENDEZVOUS |
| 40 | INTRODUCE_ACK | B, C | Acknowledge INTRODUCE1 |
| 41 | PADDING_NEGOTIATE | F, C | Negotiate circuit padding |
| 42 | PADDING_NEGOTIATED | B, C | Negotiate circuit padding |
| 43 | XOFF | F/B | Stream-level flow control |
| 44 | XON | F/B | Stream-level flow control |

Type key: F=Forward, B=Backward, C=Control (stream_id=0)

### Destroy Reasons (tor-spec §5.4)

| Code | Name |
|------|------|
| 0 | NONE |
| 1 | PROTOCOL |
| 2 | INTERNAL |
| 3 | REQUESTED |
| 4 | HIBERNATING |
| 5 | RESOURCELIMIT |
| 6 | CONNECTFAILED |
| 7 | OR_IDENTITY |
| 8 | CHANNEL_CLOSED | The OR connection died |
| 9 | FINISHED | Circuit expired for being dirty or old |
| 10 | TIMEOUT | Circuit construction took too long |
| 11 | DESTROYED | Circuit destroyed w/o client TRUNCATE |
| 12 | NOSUCHSERVICE | Request for unknown hidden service |
| 13 | MEASUREMENT | |
| 14 | RELAYDESC_NOTFOUND | |
| 15 | RELAYEARLY_CLOSE | |

### End Reasons (tor-spec §6.3)

| Code | Name |
|------|------|
| 1 | MISC |
| 2 | RESOLVEFAILED |
| 3 | CONNECTREFUSED |
| 4 | EXITPOLICY |
| 5 | DESTROY |
| 6 | DONE |
| 7 | TIMEOUT |
| 8 | NOROUTE |
| 9 | HIBERNATING |
| 10 | INTERNAL |
| 11 | RESOURCELIMIT |
| 12 | CONNRESET |
| 13 | TORPROTOCOL |
| 14 | NOTDIRECTORY |
| 15 | ALREADY_SOCKS_REPLIED |
| 16 | CANT_ATTACH |
| 17 | NET_UNREACHABLE |
| 18 | SOCKS_PROTOCOL |
| 19 | DOMAIN_NOT_FOUND |

### Flow Control (tor-spec §7.4)

| Parameter | Value | Description |
|-----------|-------|-------------|
| CIRCUIT_WINDOW_START | 1000 | Circuit-level package/deliver window |
| CIRCUIT_WINDOW_INCREMENT | 100 | SENDME increment for circuit |
| STREAM_WINDOW_START | 500 | Stream-level window |
| STREAM_WINDOW_INCREMENT | 50 | SENDME increment for streams |
| MAX_DATA_LEN | 498 | Max bytes per RELAY_DATA cell |

### SENDME Message Format

- VERSION field (1 byte): 0x00 = ignore body, 0x01 = authenticated SENDME
- DATA_LEN field (2 bytes): Length of DATA
- DATA field (DATA_LEN bytes): Contains 20-byte rolling digest (version 1)
- Circuit-level SENDME has stream_id=0
- Stream-level SENDME has nonzero stream_id
- Stream SENDME is empty (DATA_LEN may be 0)

### DNS-over-Tor Resolution

- RELAY_RESOLVE: Contains hostname + NUL terminator
- RELAY_RESOLVED: Multiple answers with Type, Length, Value, TTL
- Answer types: 0x00 (Hostname), 0x04 (IPv4), 0x06 (IPv6), 0xF0 (Error transient), 0xF1 (Error nontransient)
- For reverse lookup: in-addr.arpa address
- RELAY_RESOLVE must use nonzero distinct streamID

### Stream Opening (RELAY_BEGIN)

- ADDRPORT format: `ADDRESS:PORT` with NUL terminator
- ADDRESS can be: DNS hostname, IPv4 (dotted-quad), or IPv6 (bracket notation `[ipv6]`)
- Should be sent in lowercase (to avoid fingerprinting)
- FLAGS (optional 4 bytes, big-endian):
  - Bit 1 (LSB): IPv6 okay
  - Bit 2: IPv4 not okay
  - Bit 3: IPv6 preferred
  - Bits 4-32: Reserved (MUST NOT set, servers MUST ignore)

**Exit node processing:**
1. Check if first node in circuit (CREATE_FAST or unauthenticated/non-consensus key)
2. If one-hop circuit: MUST decline with DESTROY (protocol violation)
3. Resolve address, open TCP connection to target
4. On failure: send RELAY_END with reason
5. On success: send RELAY_CONNECTED

### RELAY_CONNECTED Response

- IPv4 format: 4-byte address + 4-byte TTL
- IPv6 format: 4 zero bytes + 1 byte type (6) + 16-byte address + 4-byte TTL
- Empty body is acceptable (MUST accept)
- Address should NOT be cached with other circuits (exit may have lied)

### Data Transmission (RELAY_DATA)

- Packaged in RELAY_DATA messages up to 498 bytes
- Client MAY send RELAY_DATA immediately after RELAY_BEGIN (optimistic data)
- Before RELAY_CONNECTED/RELAY_END: exit queues RELAY_DATA
  - On success: process queue immediately
  - On failure: delete queued data
- To closed streams: drop
- To unrecognized streams: error, close circuit

### RELAY_DROP

- Long-range dummy messages
- Upon receipt: must drop (no action)

### Directory Streams (RELAY_BEGIN_DIR)

- Same as RELAY_BEGIN but connects to directory port
- Ignores exit policy (local to Tor process)
- Clients MUST send empty body; relays MUST ignore body
- Response: RELAY_CONNECTED (empty body) or RELAY_END (REASON_NOTDIRECTORY)

### Circuit Tearing Down

**Triggers:**
- Unrecoverable error along circuit
- All streams closed and circuit lifetime over
- Relay receives RELAY_BEGIN or ESTABLISH_RENDEZVOUS to first hop (SHOULD decline)

**First hop detection:**
- Circuit created with CREATE_FAST
- Responder: initiator didn't authenticate, or authenticated key not in consensus

**Complete teardown:**
- Send DESTROY cell to adjacent nodes
- Relay frees resources, propagates DESTROY to next relay
- After processing DESTROY, ignore all data/DESTROY for that circuit

**Hop-by-hop teardown (TRUNCATE):**
- Client sends RELAY_TRUNCATE (Stream ID zero)
- Relay sends DESTROY to next node, replies with RELAY_TRUNCATED
- Note: Queued cells may be dropped (non-conformant)
- Current Tor sends DESTROY instead of TRUNCATED towards client

**DESTROY propagation (v0.4.5.13+, 0.4.6.11+, 0.4.7.9+):**
- Propagates in both directions to stop queuing pressure

**Reason handling:**
- RELAY_TRUNCATED and DESTROY towards client: Use actual reason
- DESTROY cell: Use DESTROYED reason (don't propagate actual reason - side channel risk)
- Client's own DESTROY cells: Use NONE reason

### Key Derivation (tor-spec §5.2)

- **ntor-v3** (modern): SHA3-256 with protoid `ntor3-curve25519-sha3_256-1`, uses KDF-RFC5869 with SHA3-256 (SHAKE_256)
- **ntor**: HKDF-SHA256 with protoid `ntor-curve25519-sha256-1`, uses KDF-RFC5869 with SHA256
- **CREATE_FAST**: KDF-TOR using iterated SHA-1
- **Key material**: 72 bytes (Df 20 + Db 20 + Kf 16 + Kb 16)
- **ntor-v3 extra**: Additional message support via AES-256-CTR encryption

### KDF-TOR (CREATE_FAST / TAP)

- Base key material: K0 = X|Y (CREATE_FAST) or K0 = g^xy (TAP)
- Key derivation: K = SHA1(K0 | [00]) | SHA1(K0 | [01]) | SHA1(K0 | [02]) | ...
- Maximum output: SHA1_LEN * 256 = 5120 bytes
- Key partition (72 bytes):
  - KH (20 bytes): Handshake response proof
  - Df (20 bytes): Forward digest seed
  - Db (20 bytes): Backward digest seed
  - Kf (16 bytes): Forward encryption key
  - Kb (16 bytes): Backward encryption key

### KDF-RFC5869 (ntor / ntor-v3)

- Uses HKDF-SHA256 (or HKDF-SHA3-256 for ntor-v3)
- K = K_1 | K_2 | K_3 | ...
- K_1 = H(m_expand | INT8(1), KEY_SEED)
- K_(i+1) = H(K_i | m_expand | INT8(i+1), KEY_SEED)
- m_expand: PROTOID | ":key_expand"
- Key partition: Df, Db, Kf, Kb, nonce (for HS protocol)

### CREATE2/CREATED2 Cell Format

**CREATE2 cell:**
| Field | Size |
|-------|------|
| HTYPE | 2 bytes |
| HLEN | 2 bytes |
| HDATA | HLEN bytes |

**CREATED2 cell:**
| Field | Size |
|-------|------|
| HLEN | 2 bytes |
| HDATA | HLEN bytes |

**HTYPE values:**
| Value | Description |
|-------|-------------|
| 0x0000 | TAP (obsolete) |
| 0x0001 | reserved |
| 0x0002 | ntor |
| 0x0003 | ntor-v3 |

### ntor Handshake Details

**Client sends:**
- NODEID (20 bytes): SHA1(DER(KP_relayid_id))
- KEYID (32 bytes): KEYID(B)
- CLIENT_KP (32 bytes): X (Curve25519 public key)

**Server replies:**
- SERVER_KP (32 bytes): Y
- AUTH (32 bytes): HMAC-SHA256

**Key derivation:**
- secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
- KEY_SEED = H(secret_input, t_key)
- verify = H(secret_input, t_verify)
- auth_input = verify | ID | B | Y | X | PROTOID | "Server"

### ntor-v3 Handshake Details

**Additional defines:**
- ENCAP(s) = htonll(len(s)) | s
- H(s,t) = SHA3_256(ENCAP(t) | s)
- MAC(k,msg,t) = SHA3_256(ENCAP(t) | ENCAP(k) | s)
- KDF(s,t) = SHAKE_256(ENCAP(t) | s)
- ENC(k,m) = AES_256_CTR(k, m)

**Client sends (CREATE2):**
| Field | Size |
|-------|------|
| NODEID | 32 bytes (Ed25519 ID) |
| KEYID | 32 bytes (B) |
| CLIENT_PK | 32 bytes (X) |
| MSG | encrypted |
| MAC | 32 bytes |

**Server replies (CREATED2):**
| Field | Size |
|-------|------|
| Y | 32 bytes |
| AUTH | 32 bytes |
| MSG | encrypted |

### CREATE_FAST Cell Format

**CREATE_FAST:**
| Field | Size |
|-------|------|
| X | 20 bytes (random key material) |

**CREATED_FAST:**
| Field | Size |
|-------|------|
| Y | 20 bytes (random key material) |
| Derivative key data | 20 bytes (KDF-TOR) |

### EXTEND2 Message Format

| Field | Description |
|-------|-------------|
| NSPEC | Number of link specifiers |
| NSPEC times: LSTYPE, LSLEN, LSPEC | Link specifiers |
| HTYPE | Client Handshake Type |
| HLEN | Client Handshake Data Len |
| HDATA | Client Handshake Data |

**Link specifiers:**
| Type | Description |
|------|-------------|
| 00 | IPv4 address + ORPort (4 + 2 bytes) |
| 01 | IPv6 address + ORPort (16 + 2 bytes) |
| 02 | Legacy identity (20 bytes SHA-1) |
| 03 | Ed25519 identity (32 bytes) |

### Circuit Extension Handshake Extensions

Format: N_EXTENSIONS + (EXT_FIELD_TYPE, EXT_FIELD_LEN, EXT_FIELD)*

| Type | Sent by | Name | Purpose |
|------|---------|------|---------|
| 1 | Client | CC_FIELD_REQUEST | Congestion control request |
| 2 | Server | CC_FIELD_RESPONSE | Congestion control response (sendme_inc) |
| 2 | Client | POW | Proof of work (INTRODUCE only) |
| 3 | Client | SUBPROTO | Subprotocol capability negotiation |

**Subprotocol Request (EXT_TYPE=3):**
- Format: (protocol_id, cap_number)* pairs
- Example: [02 06] = Relay=6 (RELAY_CRYPTO_CGO)
- Requires target supports RELAY_NEGOTIATE_SUBPROTO (Relay=5)

### Cryptographic Primitives

- **Stream cipher**: AES-128-CTR with IV of all 0 bytes (also requires AES256)
- **Public key**: RSA 1024-bit with exponent 65537, OAEP-MGF1 padding with SHA-1
- **Diffie-Hellman**: Generator g=2, 1024-bit safe prime (RFC 2409 §6.2)
- **DH private key**: SHOULD be 320 bits, never reuse
- **Hash functions**: SHA-1, SHA-256, SHA3-256
- **Identity keys**: Ed25519 (modern), RSA 1024-bit (legacy)
- **TLS support**: TLS 1.3 preferred, TLS 1.2 supported

### Relay Keys and Identities

**Identity Keys:**
- `KP_relayid_ed`, `KS_relayid_ed`: Ed25519 identity key (never expires, signs relaysign_ed)
- `KP_relayid_rsa`, `KS_relayid_rsa`: Legacy RSA 1024-bit identity key (deprecated)

**Online Signing Keys:**
- `KP_relaysign_ed`, `KS_relaysign_ed`: Medium-term Ed25519 signing key, signed by identity key

**Circuit Extension Keys:**
- `KP_ntor`, `KS_ntor`: Curve25519 key for ntor/ntor-v3 handshakes
- `KP_onion_tap`, `KS_onion_tap`: RSA 1024-bit for obsolete TAP handshake

**Channel Authentication Keys:**
- `KP_link_ed`, `KS_link_ed`: Short-term Ed25519 link authentication key (rotated frequently)

### Link Protocol

- Supported versions: 3, 4, 5
- Version 4: Increases circuit ID width to 4 bytes
- Version 5: Adds support for link padding and negotiation
- Default negotiation: highest mutually supported
- VERSIONS cell sent first with circ_id=0
- CERTS and NETINFO required before data

### Circuit Creation Process

1. Choose end node R_N (N=1 for directory, N>=3 for anonymous)
2. Choose path of (N-1) routers R_1...R_N-1
3. Open connection to first router if needed
4. Choose unused circID, send CREATE/CREATE2 cell
5. Wait for CREATED/CREATED2, extract Kf_1, Kb_1
6. For each subsequent router, extend the circuit

**Extend circuit by single router R_M:**
1. Create onion skin encrypted to R_M's public key
2. Send EXTEND/EXTEND2 in RELAY_EARLY message
3. Receive EXTENDED/EXTENDED2, verify handshake, calculate keys

**Special failure cases:**
- EXTEND to zero/empty identity: circuit fails
- EXTEND to relay that sent the EXTEND: circuit fails
- All-zero Ed25519 key SHOULD be accepted if not in consensus

### Canonical Connections

To prevent MITM attacks, when relay receives extend request:
- Use existing connection if ID matches AND (IP matches OR IP is canonical from NETINFO OR IP matches consensus)
- Canonical IP from NETINFO: relay knows it's the address it actually used

### RELAY_EARLY Cells

- Used to limit circuit length
- Clients MUST send EXTEND/EXTEND2 in RELAY_EARLY cells (link v2+)
- Clients SHOULD send first ~8 non-first-hop cells as RELAY_EARLY
- Relays MUST close circuit if >8 RELAY_EARLY cells received
- Relays MUST close circuit immediately if any inbound RELAY_EARLY received

### Circuit ID Selection

- In link protocol v4+: initiator MUST set MSB to 1, responder sets MSB to 0
- In link protocol v3 or lower: MSB based on public key comparison to avoid collisions
- Client with no public key may choose any CircID
- Value 0 is reserved (no circuit)
- Choose randomly from available unused values
- May stop after 64 failed attempts to find unused CircID

### TLS Requirements

- All implementations SHOULD support TLS 1.3
- Relay implementations SHOULD support TLS 1.2 and TLS 1.3
- With TLS 1.2: ECDHE_RSA_WITH_AES_128_GCM_SHA256, ECDHE_RSA_WITH_CHACHA20_POLY1305, NIST P-256, Curve25519
- With TLS 1.3: AES_128_GCM_SHA256, CHACHA20_POLY1305_SHA256, NIST P-256, X25519
- Session resumption SHOULD NOT be allowed
- Compression SHOULD NOT be allowed

### Authentication Methods

- AuthType 0x0003: Ed25519-SHA256-RFC5705 (modern)
- RSA-SHA256-TLSSecret (AuthType 0x0001) is obsolete

### Link Specifiers (EXTEND2)

| Type | Description |
|------|-------------|
| 00 | TLS-over-TCP, IPv4 address (4 bytes + 2 byte ORPort) |
| 01 | TLS-over-TCP, IPv6 address (16 bytes + 2 byte ORPort) |
| 02 | Legacy identity (20-byte SHA-1 fingerprint) |
| 03 | Ed25519 identity (32 bytes) |

Order for indistinguishability: [00], [02], [03], [01]

### Subprotocol Versioning

| Protocol | Numeric ID | Description |
|----------|------------|-------------|
| Link | 0 | Link protocol versions |
| LinkAuth | 1 | AUTHENTICATE cell types |
| Relay | 2 | CREATE/CREATE2 and relay messages |
| DirCache | 3 | Directory cache documents |
| HSDir | 4 | Hidden service documents |
| HSIntro | 5 | Introduction points |
| HSRend | 6 | Rendezvous points |
| Desc | 7 | Server descriptor features |
| Microdesc | 8 | Microdescriptor features |
| Cons | 9 | Consensus document features |
| Padding | 10 | Padding capabilities |
| FlowCtrl | 11 | Flow control protocol |
| Conflux | 12 | Circuit bundling |

#### Link Subprotocol Capabilities

| Value | Name | Description |
|-------|------|-------------|
| 1 | LINKAUTH_RSA_SHA256_TLSSecret | RSA link authentication (obsolete) |
| 3 | LINKAUTH_ED25519_SHA256_EXPORTER | Ed25519 link authentication (modern) |

#### Relay Subprotocol Capabilities

| Value | Name | Description |
|-------|------|-------------|
| 1 | RELAY_BASE | TAP key exchange |
| 2 | RELAY_NTOR | ntor key exchange, IPv6 support |
| 3 | RELAY_EXTEND_IPV6 | Extend over IPv6 connections |
| 4 | RELAY_NTORV3 | ntor-v3 key exchange (0.4.7.3+) |
| 5 | RELAY_NEGOTIATE_SUBPROTO | Subprotocol request extension |
| 6 | RELAY_CRYPT_CGO | Counter Galois Onion encryption |

#### FlowCtrl Subprotocol Capabilities

| Value | Name | Description |
|-------|------|-------------|
| 1 | FLOWCTRL_AUTH_SENDME | Authenticated SENDME (0.4.1.1+) |
| 2 | FLOWCTRL_CC | Congestion control (0.4.7.3+) |

#### HSIntro Subprotocol Capabilities

| Value | Name | Description |
|-------|------|-------------|
| 3 | HSINTRO_V2 | RSA-based introduction points |
| 4 | HSINTRO_V3 | Ed25519-based HS v3 introduction |
| 5 | HSINTRO_RATELIM | DoS parameters extension |

#### HSRend Subprotocol Capabilities

| Value | Name | Description |
|-------|------|-------------|
| 1 | HSREND_V2 | Original rendezvous protocol |
| 2 | HSREND_V3 | RENDEZVOUS2 arbitrary length |

#### Current Required Protocols (Feb 2026)

**Required Client Protocols:** Cons=2 Desc=2 FlowCtrl=1 Link=4 Microdesc=2 Relay=2

**Required Relay Protocols:** Cons=2 Desc=2 DirCache=2 FlowCtrl=1-2 HSDir=2 HSIntro=4-5 HSRend=2 Link=4-5 LinkAuth=3 Microdesc=2 Relay=2-4

## SOCKS Proxy Server

Implements RFC 1928 (SOCKS Protocol Version 5) and SOCKS4/4A:

### Supported Protocols

| Version | Authentication | Host Resolution |
|---------|----------------|-----------------|
| SOCKS4 | None | Client must provide IP |
| SOCKS4A | None | Proxy resolves hostname |
| SOCKS5 | None (GSSAPI optional, not implemented) | Client provides IP or domain |

### SOCKS Commands

| Command | Code | Description |
|---------|------|-------------|
| CONNECT | 0x01 | Connect to remote host |
| BIND | 0x02 | Not supported |
| UDP_ASSOC | 0x03 | Not supported |

### Address Types

| Type | Code | Format |
|------|------|--------|
| IPv4 | 0x01 | 4 bytes |
| Domain | 0x03 | Length + domain string |
| IPv6 | 0x04 | 16 bytes |

### Reply Codes

| Code | Name |
|------|------|
| 0x00 | SUCCESS |
| 0x01 | GENERAL_FAILURE |
| 0x02 | CONNECTION_NOT_ALLOWED |
| 0x03 | NETWORK_UNREACHABLE |
| 0x04 | HOST_UNREACHABLE |
| 0x05 | CONNECTION_REFUSED |
| 0x06 | TTL_EXPIRED |
| 0x07 | COMMAND_NOT_SUPPORTED |
| 0x08 | ADDRESS_TYPE_NOT_SUPPORTED |

## Configuration

### YAML Config File

Default search paths (in order):
1. `./config.yml` or `./config.yaml`
2. `~/.libtor/config.yml` or `~/.libtor/config.yaml`
3. `/etc/libtor/config.yml`
4. Path in `LIBTOR_CONFIG` environment variable

### Configuration Schema

```yaml
tor:
  hops: int              # Circuit hop count (default: 3)
  timeout: float         # Operation timeout in seconds (default: 30.0)
  directory_timeout: float  # Directory fetch timeout (default: 30.0)
  # guard_state_file is now stored in libtor.db (no config needed)

socks:
  enabled: bool          # Enable SOCKS proxy server
  host: str              # Listen host (default: "127.0.0.1")
  port: int              # Listen port (default: 1080)

directory:
  min_bandwidth_guard: int    # Minimum guard bandwidth (default: 100)
  min_bandwidth_exit: int     # Minimum exit bandwidth (default: 50)
  require_stable_exits: bool  # Require stable flag for exits (default: false)

logging:
  level: str            # Log level: DEBUG, INFO, WARNING, ERROR
  file: str | None      # Optional log file path
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| LIBTOR_HOPS | Circuit hop count | 3 |
| LIBTOR_TIMEOUT | Operation timeout | 30.0 |
| LIBTOR_DIRECTORY_TIMEOUT | Directory timeout | 30.0 |
| LIBTOR_SOCKS_ENABLED | Enable SOCKS proxy | false |
| LIBTOR_SOCKS_HOST | SOCKS listen host | "127.0.0.1" |
| LIBTOR_SOCKS_PORT | SOCKS listen port | 1080 |
| LIBTOR_LOG_LEVEL | Log level | "INFO" |
| LIBTOR_CONFIG | Config file path | - |

## Public API / Interface

### TorClient

```python
class TorClient:
    def __init__(
        self,
        hops: int = 3,
        timeout: float = 30.0,
        directory_timeout: float = 30.0,
        # guard_state_file is now stored in libtor.db (no config needed)
    ) -> None
    async def bootstrap() -> None
    async def close() -> None
    @asynccontextmanager async def create_circuit(
        hops: Optional[int] = None,
        guard: Optional[RouterInfo] = None,
        middle: Optional[RouterInfo] = None,
        exit_: Optional[RouterInfo] = None,
    ) -> AsyncIterator[Circuit]
    async def fetch(url: str, timeout: float = 30.0, extra_headers: Optional[dict] = None) -> bytes
    async def resolve(hostname: str) -> list[str]
    @property def guard_selection(self) -> Optional[GuardSelection]
```

### Circuit

```python
class Circuit:
    def __init__(self, conn: ORConnection, timeout: float = 30.0) -> None
    async def create(guard: RouterInfo) -> None
    async def extend(router: RouterInfo, ntor_key: bytes) -> None
    async def open_stream(host: str, port: int) -> TorStream
    async def open_dir_stream() -> TorStream
    async def destroy(reason: int = DestroyReason.REQUESTED) -> None
```

### TorStream

```python
class TorStream:
    async def send(data: bytes) -> int
    async def sendall(data: bytes) -> None
    async def recv(n: int = 65536, timeout: Optional[float] = None) -> bytes
    async def recv_all(timeout: Optional[float] = None) -> bytes
    async def http_get(
        host: str,
        path: str = "/",
        extra_headers: Optional[dict] = None,
        timeout: float = 30.0,
    ) -> bytes
    async def close() -> None
```

### SOCKSProxy

```python
class SOCKSProxy:
    def __init__(
        self,
        tor_client: TorClient,
        listen_host: str = "127.0.0.1",
        listen_port: int = 1080,
    ) -> None
    async def start() -> None
    async def stop() -> None
```

### Config

```python
class Config:
    tor: TorConfig
    socks: SOCKSConfig
    directory: DirectoryConfig
    log_level: str
    log_file: Optional[str]
    
    @classmethod def from_file(path: str | Path) -> Config
    @classmethod def from_env() -> Config
    @classmethod def from_default_locations() -> Config
    def to_dict() -> dict
    def save(path: str | Path) -> None
```

### GuardState & GuardSelection

```python
@dataclass
class GuardState:
    guards: list[str]          # List of identity_hex
    timestamp: datetime
    USE_SECONDS: int           # 2592000 (30 days)
    TOTAL_TIMEOUT: int         # 900 (15 minutes)
    FAIL_TIMEOUT: int          # 900 (15 minutes)
    
    def add_guard(identity_hex: str) -> None
    def remove_guard(identity_hex: str) -> None
    def save(conn: Optional[sqlite3.Connection] = None, path: Optional[str] = None) -> None
    @classmethod def load(conn: Optional[sqlite3.Connection] = None, path: Optional[str] = None) -> GuardState

class GuardSelection:
    state: GuardState
    
    def __init__(self, state: Optional[GuardState] = None, conn: Optional[sqlite3.Connection] = None, state_file: Optional[str] = None) -> None
    def select(routers: list[RouterInfo]) -> Optional[RouterInfo]
    def record_failure(identity_hex: str) -> None
    def save() -> None
```

### Data Classes

```python
@dataclass
class RouterInfo:
    nickname: str
    identity: bytes           # 20-byte SHA-1 fingerprint
    digest: bytes            # 20-byte descriptor digest
    address: str
    or_port: int
    dir_port: int
    flags: List[str]
    bandwidth: int
    ntor_onion_key: Optional[bytes]  # 32-byte Curve25519
    version: str
    
    @property def identity_hex(self) -> str
    @property def is_guard(self) -> bool
    @property def is_exit(self) -> bool
    @property def is_fast(self) -> bool
    @property def is_stable(self) -> bool
    @property def is_valid(self) -> bool

@dataclass
class Cell:
    circ_id: int
    command: int              # CellCommand
    payload: bytes
    
    def to_bytes(link_version: int = 4) -> bytes
    @staticmethod def from_bytes(data: bytes, link_version: int = 4) -> Cell

@dataclass
class RelayCell:
    relay_command: int        # RelayCommand
    stream_id: int
    recognized: int
    digest: bytes
    data: bytes
    
    def to_payload() -> bytes
    @classmethod def from_payload(payload: bytes) -> RelayCell

@dataclass
class CachedDescriptor:
    identity: bytes           # 20-byte identity
    ntor_onion_key: bytes     # 32-byte Curve25519
    fetched_at: float         # Unix timestamp
```

### DescriptorCache

```python
class DescriptorCache:
    CACHE_TTL = 12 * 60 * 60        # 12 hours
    STALE_COOLDOWN = 60 * 60        # 1 hour
    DEFAULT_CACHE_DB = "ntor_key_cache.db"

    def __init__(self, timeout: float = 10.0, cache_file: str | None = None)
    
    def get_ntor_key(identity: bytes) -> bytes | None
    def set_ntor_key(identity: bytes, ntor_key: bytes) -> None
    def mark_stale(identity: bytes) -> None
    def is_stale(identity: bytes) -> bool
    def get_stale_count() -> int
    def get_key_count() -> int
    def is_fresh() -> bool
    def close() -> None
    
    async def fetch_all_descriptors(
        routers: list[RouterInfo],
        directory_servers: list[tuple[str, str, int]],
    ) -> None
    
    async def get_fresh_ntor_key(
        router: RouterInfo,
        directory_servers: list[tuple[str, str, int]],
    ) -> bytes | None
    
    async def refresh_if_needed(
        routers: list[RouterInfo],
        directory_servers: list[tuple[str, str, int]],
    ) -> None
```

### Enums

```python
class CellCommand(IntEnum): ...
class RelayCommand(IntEnum): ...
class DestroyReason(IntEnum): ...
class EndReason(IntEnum): ...

class SOCKSVersion(IntEnum): SOCKS4 = 4, SOCKS5 = 5
class SOCKSCommand(IntEnum): CONNECT = 1, BIND = 2, UDP_ASSOCIATE = 3
class SOCKSAddressType(IntEnum): IPv4 = 1, DOMAIN = 3, IPv6 = 4
class SOCKSReply(IntEnum): SUCCESS = 0, GENERAL_FAILURE = 1, ...
class SOCKSAuthMethod(IntEnum): NO_AUTH = 0, GSSAPI = 1, USERNAME_PASSWORD = 2
```

### Exceptions

```python
class TorError(Exception): ...
class HandshakeError(TorError): ...
class CircuitError(TorError): ...
class StreamError(TorError): ...
class DirectoryError(TorError): ...
class CellError(TorError): ...
class RelayError(TorError): ...
class DestroyedError(TorError): ...
```

## Data Formats

- **Consensus document**: v3 network-status, parsed via ConsensuParser
- **Microdescriptors**: Plain text, ntor-onion-key extracted via MicrodescParser
- **Cell format**: Fixed 514-byte cells (link protocol v4+) with 4-byte circ_id + 1-byte command + 509-byte payload
- **Relay cells**: 11-byte header + up to 498-byte data payload, onion-encrypted per-hop

## Edge Cases

1. **No relays available**: `DirectoryError` raised when consensus fetch fails from all authorities
2. **Insufficient relays for path**: `CircuitError` raised when not enough guards/exits/middles
3. **Connection timeout**: Raises `asyncio.TimeoutError` on cell operations
4. **Circuit destroyed**: `DestroyedError` raised on operations after DESTROY cell
5. **Stream ended by exit**: `RelayError` with EndReason when exit sends RELAY_END
6. **Link protocol version mismatch**: `TorError` if no mutually supported version
7. **Invalid ntor key**: `HandshakeError` if ntor key is wrong length or auth fails
8. **CREATE_FAST KH mismatch**: `HandshakeError` if key derivative hash doesn't match
9. **Empty consensus response**: Parser returns empty list, triggers fallback attempts
10. **HTTPS fetch not supported**: `TorError` with clear message about limitation
11. **SENDME window exhausted**: Send blocks until SENDME received from exit
12. **Circuit ID wrap**: IDs use high bit for client-initiated, wrap at 0xFFFFFFFF
13. **Cell decryption failure**: `recognized` field not zero after all layers peeled
14. **SOCKS unsupported command**: Returns `COMMAND_NOT_SUPPORTED`
15. **SOCKS unsupported address type**: Returns `ADDRESS_TYPE_NOT_SUPPORTED`

## Performance & Constraints

- Python 3.11+ with `cryptography` and `pyyaml` as dependencies
- Async I/O using asyncio
- Default 3-hop circuits; supports 2-hop for lower latency
- Memory: O(relays) for consensus storage, O(streams) per circuit
- No persistent state between runs (except guard state)

## Version

`0.1.0`
