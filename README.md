# libtor

A pure-Python implementation of the Tor protocol — not a wrapper around the Tor binary, but the actual protocol speaking directly to relays using TLS, ntor/CREATE_FAST handshakes, and onion-encrypted relay cells.

[![PyPI](https://img.shields.io/pypi/v/libtor.svg)](https://pypi.org/project/libtor/)
[![Python](https://img.shields.io/pypi/pyversions/libtor.svg)](https://pypi.org/project/libtor/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Features

- **Actual Tor protocol** — TLS to ORs, link-protocol negotiation (v3–v5), VERSIONS/NETINFO handshake
- **ntor-v3 handshake** (Curve25519 + SHA3-256) for modern circuit creation
- **ntor handshake** (Curve25519 + HKDF-SHA256) for legacy compatibility
- **CREATE_FAST** for the first hop (safe because TLS provides forward secrecy)
- **AES-128-CTR onion encryption** with SHA-1 running digests
- **Circuit building** — guard → middle → exit path selection, weighted by bandwidth
- **Stream multiplexing** — RELAY_BEGIN / RELAY_DATA / RELAY_END
- **Flow control** — per-stream SENDME windows
- **Directory client** — fetches the v3 consensus from directory authorities
- **ntor key cache** — SQLite-based persistent cache with TTL and stale key cooldown
- **SOCKS4/5 proxy server** — run a local SOCKS proxy to route any application through Tor
- **Guard state persistence** — maintain consistent guards across sessions
- **Configuration file support** — YAML config file and environment variables
- **Importable library** — clean async API, no global state, no subprocess

## Install

```bash
pip install libtor
```

Or for development:

```bash
git clone https://github.com/dclavijo/libtor.git
cd libtor
pip install -e ".[test]"
```

## Quick start

```python
import asyncio
from libtor import TorClient

async def main():
    async with TorClient() as tor:
        # Bootstrap fetches the consensus (takes a few seconds)
        await tor.bootstrap()

        # Build a 3-hop circuit and open a TCP stream
        async with tor.create_circuit() as circuit:
            async with await circuit.open_stream("check.torproject.org", 80) as stream:
                body = await stream.http_get("check.torproject.org", "/")
                print(body[:500])

asyncio.run(main())
```

## Usage Guide

### Basic HTTP Fetch

The simplest way to fetch content over Tor:

```python
import asyncio
from libtor import TorClient

async def fetch_example():
    async with TorClient() as tor:
        await tor.bootstrap()
        # fetch() creates a circuit, opens a stream, sends request, returns body
        body = await tor.fetch("http://check.torproject.org/")
        print(f"Got {len(body)} bytes")
        
asyncio.run(fetch_example())
```

### DNS Resolution

Resolve hostnames through Tor's RELAY_RESOLVE:

```python
import asyncio
from libtor import TorClient

async def resolve_example():
    async with TorClient() as tor:
        await tor.bootstrap()
        ips = await tor.resolve("example.com")
        print(f"Resolved to: {ips}")
        
asyncio.run(resolve_example())
```

### Custom Circuit Building

For more control, use `create_circuit()` directly:

```python
import asyncio
from libtor import TorClient

async def custom_circuit():
    async with TorClient() as tor:
        await tor.bootstrap()
        
        # Create a circuit with specific hop count
        async with tor.create_circuit(hops=3) as circuit:
            # Open a stream to a specific host:port
            stream = await circuit.open_stream("example.com", 80)
            
            # Send raw data
            await stream.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
            
            # Receive response
            response = await stream.recv(4096)
            
            # Or use the convenience HTTP method
            async with await circuit.open_stream("example.com", 80) as stream2:
                body = await stream2.http_get("example.com", "/")
                
            # Close when done (or use async with)
            await stream.close()
            
asyncio.run(custom_circuit())
```

### Pin Specific Relays

Select specific guard, middle, or exit relays:

```python
import asyncio
from libtor import TorClient

async def pin_relays():
    async with TorClient() as tor:
        await tor.bootstrap()
        
        # Access directory client to get relays
        dir_client = tor._dir
        guards = dir_client.get_guards(min_bandwidth=5000)
        exits = dir_client.get_exits(min_bandwidth=5000)
        
        # Use specific relays
        my_guard = guards[0]
        my_exit = exits[0]
        
        async with tor.create_circuit(
            guard=my_guard,
            exit_=my_exit
        ) as circuit:
            # ... use circuit
            
asyncio.run(pin_relays())
```

### Two-Hop Circuit (Faster, Less Anonymous)

```python
import asyncio
from libtor import TorClient

async def fast_circuit():
    async with TorClient() as tor:
        await tor.bootstrap()
        
        # 2-hop: guard → exit (faster but less anonymous)
        async with tor.create_circuit(hops=2) as circuit:
            stream = await circuit.open_stream("example.com", 80)
            body = await stream.http_get("example.com", "/")
            
asyncio.run(fast_circuit())
```

### Raw TCP Streams

For non-HTTP protocols:

```python
import asyncio
from libtor import TorClient

async def raw_stream():
    async with TorClient() as tor:
        await tor.bootstrap()
        
        async with tor.create_circuit() as circuit:
            stream = await circuit.open_stream("imap.example.com", 993)
            
            # Send raw bytes
            await stream.sendall(b"* IMAP connect\r\n")
            
            # Read response
            while True:
                data = await stream.recv(1024)
                if not data:
                    break
                print(data)
                
asyncio.run(raw_stream())
```

### Directory Operations

Access directory functionality directly:

```python
import asyncio
from libtor.directory import DirectoryClient, RouterInfo

async def directory_example():
    dir_client = DirectoryClient(timeout=30)
    
    # Fetch consensus
    relays = await dir_client.fetch_consensus()
    print(f"Found {len(relays)} relays")
    
    # Get filtered relays
    guards = dir_client.get_guards(min_bandwidth=1000)
    exits = dir_client.get_exits(min_bandwidth=1000, require_stable=True)
    
    # Bandwidth-weighted selection
    selected = dir_client.weighted_choice(guards)
    print(f"Selected guard: {selected.nickname}")
    
asyncio.run(directory_example())
```

### SOCKS4/5 Proxy Server

Run a local SOCKS proxy to route any application through Tor:

```python
import asyncio
from libtor import TorClient, SOCKSProxy

async def socks_proxy():
    async with TorClient() as tor:
        # Start SOCKS proxy on 127.0.0.1:1080
        async with SOCKSProxy(tor_client=tor, listen_port=1080) as proxy:
            print("SOCKS proxy running on 127.0.0.1:1080")
            print("Configure your applications to use this proxy")
            # Keep running
            await asyncio.Event().wait()

asyncio.run(socks_proxy())
```

Or from command line:

```bash
python -m libtor --socks 1080
```

### Configuration File

Create a `config.yml` file:

```yaml
tor:
  hops: 3
  timeout: 30.0
  directory_timeout: 30.0

socks:
  enabled: true
  host: 127.0.0.1
  port: 1080

directory:
  min_bandwidth_guard: 100
  min_bandwidth_exit: 50
  require_stable_exits: false

logging:
  level: INFO
  # file: /var/log/libtor.log
```

Load configuration:

```python
from libtor import Config, TorClient, SOCKSProxy, setup_logging

# Load config from file or environment
config = Config.from_default_locations()

# Setup logging
setup_logging(config)

# Use config with TorClient
tor = TorClient(
    hops=config.tor.hops,
    timeout=config.tor.timeout,
    directory_timeout=config.tor.directory_timeout,
)

# Start SOCKS proxy if enabled
if config.socks.enabled:
    async with SOCKSProxy(tor, config.socks.host, config.socks.port) as proxy:
        await asyncio.Event().wait()
```

### Environment Variables

All configuration can be set via environment variables:

```bash
export LIBTOR_HOPS=3
export LIBTOR_TIMEOUT=30
export LIBTOR_SOCKS_ENABLED=true
export LIBTOR_SOCKS_PORT=1080
export LIBTOR_LOG_LEVEL=INFO
```

### Low-Level Cell Access

For advanced use cases:

```python
import asyncio
from libtor.cells import Cell, CellCommand
from libtor.connection import ORConnection

async def raw_cells():
    conn = ORConnection("1.2.3.4", 9001)
    async with conn:
        await conn.connect()
        
        # Send a padding cell
        cell = Cell(0, CellCommand.PADDING, b"")
        await conn.send_cell(cell)
        
asyncio.run(raw_cells())
```

## API Reference

### TorClient

```python
client = TorClient(hops=3, timeout=30.0, directory_timeout=30.0)
```

| Method | Description |
|--------|-------------|
| `await client.bootstrap()` | Fetch consensus, populate relay lists |
| `async with client.create_circuit(...)` | Build a circuit, yields `Circuit` |
| `await client.fetch(url, timeout=30.0, extra_headers=None)` | Fetch an HTTP URL over a fresh circuit |
| `await client.resolve(hostname)` | DNS-over-Tor, returns list of IPs |
| `await client.close()` | No-op (no persistent connections) |

**create_circuit parameters:**
- `hops`: Number of hops (default: 3)
- `guard`: Specific guard relay (RouterInfo)
- `middle`: Specific middle relay (RouterInfo)
- `exit_`: Specific exit relay (RouterInfo)

### Circuit

Obtained from `TorClient.create_circuit()`.

```python
async with circuit:
```

| Method | Description |
|--------|-------------|
| `await circuit.open_stream(host, port)` | Open TCP stream, returns `TorStream` |
| `await circuit.open_dir_stream()` | Open directory stream |
| `await circuit.extend(router, ntor_key)` | Extend circuit by one hop |
| `await circuit.destroy(reason=DestroyReason.REQUESTED)` | Destroy the circuit |

### TorStream

Obtained from `Circuit.open_stream()`.

```python
async with stream:
    await stream.send(data)
    response = await stream.recv(1024)
```

| Method | Description |
|--------|-------------|
| `await stream.send(data)` | Send bytes, returns count |
| `await stream.sendall(data)` | Send all data |
| `await stream.recv(n=65536, timeout=None)` | Receive up to n bytes, returns `b""` on close |
| `await stream.recv_all(timeout=None)` | Receive until EOF |
| `await stream.http_get(host, path="/", extra_headers=None, timeout=30.0)` | HTTP/1.0 GET convenience |
| `await stream.close()` | Send RELAY_END |

### RouterInfo

Describes a Tor relay.

| Property | Type | Description |
|----------|------|-------------|
| `nickname` | str | Relay name |
| `identity` | bytes | 20-byte fingerprint |
| `address` | str | IP address |
| `or_port` | int | OR port |
| `dir_port` | int | Directory port |
| `bandwidth` | int | Bandwidth in KB/s |
| `flags` | List[str] | Relay flags |
| `is_guard` | bool | Has Guard flag |
| `is_exit` | bool | Has Exit flag |
| `is_fast` | bool | Has Fast flag |
| `is_stable` | bool | Has Stable flag |
| `is_valid` | bool | Has Valid flag |

### Exceptions

| Exception | Description |
|-----------|-------------|
| `TorError` | Base exception |
| `HandshakeError` | Cryptographic handshake failure |
| `CircuitError` | Circuit creation/operation failure |
| `StreamError` | Stream operation failure |
| `DirectoryError` | Consensus fetch/parse failure |
| `CellError` | Cell parse/validation failure |
| `RelayError` | Relay command failure |
| `DestroyedError` | Circuit/stream destroyed |

## Error Handling

```python
import asyncio
from libtor import TorClient, TorError, CircuitError

async def with_error_handling():
    try:
        async with TorClient() as tor:
            await tor.bootstrap()
            body = await tor.fetch("http://example.com")
            
    except TorError as e:
        print(f"Tor error: {e}")
        
    except asyncio.TimeoutError:
        print("Connection timed out")
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        
asyncio.run(with_error_handling())
```

## Configuration

### Custom Timeouts

```python
from libtor import TorClient

# Different timeouts for different operations
client = TorClient(
    hops=3,
    timeout=60.0,          # Circuit/stream operations
    directory_timeout=60.0 # Consensus fetching
)
```

### Guard State Persistence

libtor persists guard selection across sessions per the Tor specification:

```python
from libtor import TorClient, GuardState, GuardSelection

# Guard state is stored in libtor.db automatically
client = TorClient()

# Access guard state directly
async with TorClient() as tor:
    await tor.bootstrap()
    
    # Access the guard selection state
    gs = tor.guard_selection
    if gs:
        print(f"Persisted guards: {gs.state.guards}")
        
        # Record a failure (removes guard from persistent list)
        # gs.record_failure("ABCD1234...")
```

Guard state is stored in the `guard_state` table in `libtor.db`:

```sql
SELECT * FROM guard_state WHERE id = 1;
```

The table columns:
- `guards` (TEXT): JSON array of guard identity hex strings
- `timestamp` (TEXT): ISO timestamp
- `use_seconds` (INTEGER): 30 days
- `total_timeout` (INTEGER): 15 minutes  
- `fail_timeout` (INTEGER): 15 minutes

### ntor Key Cache

libtor caches ntor keys in SQLite with TTL-based eviction:

```python
from libtor.directory import DescriptorCache

# Cache is automatically used by TorClient
# Access it directly if needed
cache = DescriptorCache()

# Check cache status
print(f"Cached keys: {cache.get_key_count()}")
print(f"Stale keys: {cache.get_stale_count()}")

# Get a key
key = cache.get_ntor_key(identity_bytes)
if key:
    print("Key found in cache")

# Manually set a key
cache.set_ntor_key(identity_bytes, ntor_key)

# Mark a key as stale (e.g., after handshake failure)
cache.mark_stale(identity_bytes)
```

The cache file `ntor_key_cache.db` stores:
- `ntor_keys` table: identity → ntor_key with timestamp
- `stale_keys` table: identity → cooldown_until (1 hour after failure)

### Bandwidth Filtering

```python
dir_client = tor._dir

# Get high-bandwidth guards
guards = dir_client.get_guards(min_bandwidth=5000)

# Get stable exits
exits = dir_client.get_exits(min_bandwidth=1000, require_stable=True)
```

## Architecture

```
TorClient
 ├── DirectoryClient        ← fetches consensus, parses relay descriptors
 ├── DescriptorCache        ← SQLite-backed ntor key cache with TTL
 ├── GuardSelection         ← persistent guard state per tor-spec §2.3
 ├── ORConnection           ← TLS socket, cell I/O, link protocol
 │    └── asyncio dispatch  ← routes cells by circuit ID
 └── Circuit
      ├── CircuitHop[]      ← per-hop AES-CTR + SHA-1 crypto state
      │    └── CircuitKeys  ← derived via HKDF from ntor secret
      └── TorStream[]       ← RELAY_DATA send/recv, SENDME windows
```

## Protocol references

- [Tor Protocol Specification](https://spec.torproject.org/tor-spec/)
- `tor-spec.txt` — main Tor protocol specification
- `dir-spec.txt` — directory protocol
- `ntor-spec.txt` — ntor handshake

## Limitations

- No hidden service (`.onion`) client or server support yet
- No HTTPS (port 443) transparent proxying — use a CONNECT tunnel or fetch HTTP
- Digest verification for relay cells uses the `recognized==0` heuristic; a production client would maintain rolling SHA-1 state per hop direction
- Client-side only (no relay functionality)
- **ntor key distribution**: Directory-sourced ntor keys may be stale due to relay key rotation. libtor implements caching with stale key detection, but for production use, integrating with a local Tor daemon's key cache is recommended.

## Development

```bash
git clone https://github.com/dclavijo/libtor.git
cd libtor
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```

## License

MIT