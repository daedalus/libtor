# libtor

A pure-Python implementation of the Tor protocol — not a wrapper around the Tor binary, but the actual protocol speaking directly to relays using TLS, ntor/CREATE_FAST handshakes, and onion-encrypted relay cells.

[![PyPI](https://img.shields.io/pypi/v/libtor.svg)](https://pypi.org/project/libtor/)
[![Python](https://img.shields.io/pypi/pyversions/libtor.svg)](https://pypi.org/project/libtor/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Features

- **Actual Tor protocol** — TLS to ORs, link-protocol negotiation (v3–v5), VERSIONS/NETINFO handshake
- **ntor handshake** (Curve25519 + HKDF-SHA256) for EXTEND2
- **CREATE_FAST** for the first hop (safe because TLS provides forward secrecy)
- **AES-128-CTR onion encryption** with SHA-1 running digests
- **Circuit building** — guard → middle → exit path selection, weighted by bandwidth
- **Stream multiplexing** — RELAY_BEGIN / RELAY_DATA / RELAY_END
- **Flow control** — per-stream SENDME windows
- **Directory client** — fetches the v3 consensus from directory authorities, parses microdescriptors for ntor keys
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

## API reference

### `TorClient`

```python
client = TorClient(hops=3, timeout=30.0)
```

| Method | Description |
|--------|-------------|
| `await client.bootstrap()` | Fetch consensus, populate relay lists |
| `async with client.create_circuit(hops=3)` | Build a circuit, yields `Circuit` |
| `await client.fetch(url)` | Fetch an HTTP URL over a fresh circuit |
| `await client.resolve(hostname)` | DNS-over-Tor, returns list of IPs |

### `Circuit`

Obtained from `TorClient.create_circuit()`.

```python
async with circuit.open_stream(host, port) as stream:
    ...
```

| Method | Description |
|--------|-------------|
| `await circuit.open_stream(host, port)` | Open TCP stream, returns `TorStream` |
| `await circuit.open_dir_stream()` | Open directory stream |
| `await circuit.extend(relay, ntor_key)` | Extend circuit by one hop |
| `await circuit.destroy()` | Destroy the circuit |

### `TorStream`

Obtained from `Circuit.open_stream()`.

| Method | Description |
|--------|-------------|
| `await stream.send(data)` | Send bytes |
| `await stream.recv(n)` | Receive up to n bytes |
| `await stream.recv_all()` | Receive until EOF |
| `await stream.http_get(host, path)` | HTTP/1.0 GET convenience method |
| `await stream.close()` | Send RELAY_END |

## Advanced usage

### Pin specific relays

```python
from libtor.directory import RouterInfo

async with tor.create_circuit(
    guard=my_guard_relay,
    exit_=my_exit_relay,
) as circuit:
    ...
```

### Access the directory client

```python
dir_client = tor._dir
guards = dir_client.get_guards(min_bandwidth=500)
exits  = dir_client.get_exits(require_stable=True)
```

### Raw cell access

```python
from libtor.cells import Cell, CellCommand, RelayCell, RelayCommand
from libtor.connection import ORConnection

conn = ORConnection("1.2.3.4", 9001)
await conn.connect()
await conn.send_cell(Cell(0, CellCommand.PADDING, b""))
```

### Two-hop circuit (faster, less anonymous)

```python
async with tor.create_circuit(hops=2) as circuit:
    ...
```

## Architecture

```
TorClient
 ├── DirectoryClient        ← fetches consensus, parses relay descriptors
 ├── ORConnection           ← TLS socket, cell I/O, link protocol
 │    └── asyncio dispatch  ← routes cells by circuit ID
 └── Circuit
      ├── CircuitHop[]      ← per-hop AES-CTR + SHA-1 crypto state
      │    └── CircuitKeys  ← derived via HKDF from ntor secret
      └── TorStream[]       ← RELAY_DATA send/recv, SENDME windows
```

## Protocol references

- `tor-spec.txt`   — main Tor protocol specification
- `dir-spec.txt`   — directory protocol
- `ntor-spec.txt`  — ntor handshake

## Limitations

- No hidden service (`.onion`) client or server support yet
- No HTTPS (port 443) transparent proxying — use a CONNECT tunnel or fetch HTTP
- No guard-state persistence between runs (new circuit on every run)
- Digest verification for relay cells uses the `recognized==0` heuristic; a production client would maintain rolling SHA-1 state per hop direction

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
