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
- Onion-encrypted relay cells (AES-128-CTR + SHA-1 running digests) per tor-spec §5.2
- Stream multiplexing (RELAY_BEGIN / RELAY_DATA / RELAY_END) per tor-spec §6
- Flow control with SENDME windows (tor-spec §7.4)
- Directory client fetching v3 consensus and microdescriptors (dir-spec)
- DNS-over-Tor resolution (RELAY_RESOLVE)
- HTTP convenience methods on streams
- Guard-state persistence (tor-spec §2.3)
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

| Field | Size (v1-3) | Size (v4+) |
|-------|-------------|------------|
| CircID | 2 bytes | 4 bytes |
| Command | 1 byte | 1 byte |
| Body | 509 bytes | 509 bytes |

- `CELL_SIZE`: 512 bytes (v1-3), 514 bytes (v4+)
- `PAYLOAD_LEN`: 509 bytes

### Cell Commands (tor-spec §3.3)

| Code | Name | Description |
|------|------|-------------|
| 0 | PADDING | Link padding |
| 1 | CREATE | Create circuit (deprecated) |
| 2 | CREATED | Acknowledge CREATE (deprecated) |
| 3 | RELAY | End-to-end data |
| 4 | DESTROY | Stop using a circuit |
| 5 | CREATE_FAST | Create circuit, no public key |
| 6 | CREATED_FAST | Acknowledge CREATE_FAST |
| 7 | VERSIONS | Negotiate link protocol |
| 8 | NETINFO | Time and address info |
| 9 | RELAY_EARLY | End-to-end data; limited |
| 10 | CREATE2 | Extended CREATE cell |
| 11 | CREATED2 | Extended CREATED cell |
| 128 | VPADDING | Variable-length padding |
| 129 | CERTS | Certificates |
| 130 | AUTH_CHALLENGE | Challenge value |
| 131 | AUTHENTICATE | Client authentication |

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
| 8 | OR_CONN_CLOSED |
| 9 | FINISHED |
| 10 | TIMEOUT |
| 11 | DESTROYED |
| 12 | NOSUCHSERVICE |

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

### Flow Control (tor-spec §7.4)

| Parameter | Value | Description |
|-----------|-------|-------------|
| CIRCUIT_WINDOW_START | 1000 | Circuit-level package/deliver window |
| CIRCUIT_WINDOW_INCREMENT | 100 | SENDME increment for circuit |
| STREAM_WINDOW_START | 500 | Stream-level window |
| STREAM_WINDOW_INCREMENT | 50 | SENDME increment for streams |
| MAX_DATA_LEN | 498 | Max bytes per RELAY_DATA cell |

### Key Derivation (tor-spec §5.2)

- **ntor**: HKDF-SHA256 with protoid `ntor-curve25519-sha256-1`
- **CREATE_FAST**: KDF-TOR using iterated SHA-1
- **Key material**: 72 bytes (Df 20 + Db 20 + Kf 16 + Kb 16)

### Link Protocol

- Supported versions: 3, 4, 5
- Default negotiation: highest mutually supported
- VERSIONS cell sent first with circ_id=0
- CERTS and NETINFO required before data

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
  guard_state_file: str  # Guard state persistence file

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
| LIBTOR_GUARD_STATE_FILE | Guard state file | "guard_state.json" |
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
        guard_state_file: str = "guard_state.json",
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
    def save(path: Optional[str] = None) -> None
    @classmethod def load(path: Optional[str] = None) -> GuardState

class GuardSelection:
    state: GuardState
    
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
