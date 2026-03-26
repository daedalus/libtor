# SPEC.md — libtor

## Purpose

A pure-Python implementation of the Tor protocol — not a wrapper around the Tor binary, but the actual protocol speaking directly to relays using TLS, ntor/CREATE_FAST handshakes, and onion-encrypted relay cells.

## Scope

### What IS in scope

- TLS connection to Tor relays (OR connections)
- Link protocol negotiation (VERSIONS, CERTS, NETINFO)
- Circuit creation using CREATE_FAST for the first hop
- Circuit extension using ntor handshake (EXTEND2) for subsequent hops
- Onion-encrypted relay cells (AES-128-CTR + SHA-1 running digests)
- Stream multiplexing (RELAY_BEGIN / RELAY_DATA / RELAY_END)
- Flow control with SENDME windows
- Directory client fetching v3 consensus and microdescriptors
- DNS-over-Tor resolution (RELAY_RESOLVE)
- HTTP convenience methods on streams

### What is NOT in scope

- Hidden service (.onion) client or server support
- HTTPS transparent proxying (port 443)
- Guard-state persistence between runs
- Relay descriptor verification (accepts TLS without cert verification)
- Pluggable transport support

## Public API / Interface

### `TorClient`

```python
class TorClient:
    def __init__(self, hops: int = 3, timeout: float = 30.0, directory_timeout: float = 30.0) -> None
    async def bootstrap() -> None
    async def close() -> None
    @asynccontextmanager async def create_circuit(...) -> AsyncIterator[Circuit]
    async def fetch(url: str, timeout: float = 30.0, extra_headers: Optional[dict] = None) -> bytes
    async def resolve(hostname: str) -> List[str]
```

### `Circuit`

```python
class Circuit:
    def __init__(self, conn: ORConnection, timeout: float = 30.0) -> None
    async def create(guard: RouterInfo) -> None
    async def extend(router: RouterInfo, ntor_key: Optional[bytes] = None) -> None
    async def open_stream(host: str, port: int) -> TorStream
    async def open_dir_stream() -> TorStream
    async def destroy(reason: int = DestroyReason.REQUESTED) -> None
```

### `TorStream`

```python
class TorStream:
    async def send(data: bytes) -> int
    async def sendall(data: bytes) -> None
    async def recv(n: int = 65536, timeout: Optional[float] = None) -> bytes
    async def recv_all(timeout: Optional[float] = None) -> bytes
    async def http_get(host: str, path: str = "/", extra_headers: Optional[dict] = None, timeout: float = 30.0) -> bytes
    async def close() -> None
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
- **Cell format**: Fixed 514-byte cells (link protocol v3+) with 4-byte circ_id + 1-byte command + 509-byte payload
- **Relay cells**: 11-byte header + up to 498-byte data payload, onion-encrypted per-hop

## Edge Cases

1. **No relays available**: `DirectoryError` raised when consensus fetch fails from all authorities
2. **Insufficient relays for path**: `CircuitError` raised when not enough guards/exits/middles
3. **Connection timeout**: Raises asyncio.TimeoutError on cell operations
4. **Circuit destroyed**: `DestroyedError` raised on operations after DESTROY cell
5. **Stream ended by exit**: `RelayError` with EndReason when exit sends RELAY_END
6. **Link protocol version mismatch**: `TorError` if no mutually supported version
7. **Invalid ntor key**: `HandshakeError` if ntor key is wrong length or auth fails
8. **CREATE_FAST KH mismatch**: `HandshakeError` if key derivative hash doesn't match
9. **Empty consensus response**: Parser returns empty list, triggers fallback attempts
10. **HTTPS fetch not supported**: `TorError` with clear message about limitation

## Performance & Constraints

- Pure Python with `cryptography` as only required dependency
- Async I/O using asyncio
- Default 3-hop circuits; supports 2-hop for lower latency
- Memory: O(relays) for consensus storage, O(streams) per circuit
- No persistent state between runs
