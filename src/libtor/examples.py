#!/usr/bin/env python3
"""
examples.py – runnable libtor usage examples.

Run any example:
    python -m libtor.examples fetch
    python -m libtor.examples resolve
    python -m libtor.examples raw_stream
    python -m libtor.examples multi_circuit
"""

import asyncio
import logging
import sys

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s – %(message)s",
)


# ---------------------------------------------------------------------------
# Example 1: Simple HTTP fetch
# ---------------------------------------------------------------------------


async def example_fetch() -> None:
    """Fetch a URL over Tor and print the body."""
    from libtor import TorClient

    async with TorClient() as tor:
        await tor.bootstrap()
        print("\n[fetch] Building 3-hop circuit and fetching check.torproject.org …")
        body = await tor.fetch("http://check.torproject.org/")
        print(f"[fetch] Got {len(body)} bytes")
        if b"Congratulations" in body:
            print("[fetch] ✓ Tor is working!")
        else:
            print("[fetch] Response snippet:", body[:300])


# ---------------------------------------------------------------------------
# Example 2: DNS resolution over Tor
# ---------------------------------------------------------------------------


async def example_resolve() -> None:
    """Resolve a hostname via RELAY_RESOLVE (DNS-over-Tor)."""
    from libtor import TorClient

    async with TorClient() as tor:
        await tor.bootstrap()
        hostname = "example.com"
        print(f"\n[resolve] Resolving {hostname} over Tor …")
        addrs = await tor.resolve(hostname)
        print(f"[resolve] {hostname} → {addrs}")


# ---------------------------------------------------------------------------
# Example 3: Raw stream with manual send/recv
# ---------------------------------------------------------------------------


async def example_raw_stream() -> None:
    """Open a raw TCP stream and send/receive manually."""
    from libtor import TorClient

    async with TorClient() as tor:
        await tor.bootstrap()
        print("\n[raw] Building circuit and opening raw stream to example.com:80 …")

        async with tor.create_circuit() as circuit:
            print(f"[raw] Circuit: {circuit!r}")

            async with await circuit.open_stream("example.com", 80) as stream:
                print(f"[raw] Stream: {stream!r}")

                request = (
                    b"GET / HTTP/1.0\r\n"
                    b"Host: example.com\r\n"
                    b"User-Agent: libtor/0.1\r\n"
                    b"\r\n"
                )
                sent = await stream.send(request)
                print(f"[raw] Sent {sent} bytes")

                response = await stream.recv_all(timeout=30)
                print(f"[raw] Received {len(response)} bytes")
                # Print first 500 bytes of body
                if b"\r\n\r\n" in response:
                    body = response.split(b"\r\n\r\n", 1)[1]
                    print("[raw] Body preview:", body[:300].decode(errors="replace"))


# ---------------------------------------------------------------------------
# Example 4: Multiple circuits in parallel
# ---------------------------------------------------------------------------


async def example_multi_circuit() -> None:
    """Demonstrate multiple independent circuits running concurrently."""
    from libtor import TorClient

    async def fetch_one(tor: TorClient, label: str) -> None:
        async with tor.create_circuit() as circuit:
            print(f"[multi] {label}: circuit {circuit._circ_id} built")
            async with await circuit.open_stream("example.com", 80) as stream:
                body = await stream.http_get("example.com", "/")
                print(f"[multi] {label}: got {len(body)} bytes")

    async with TorClient() as tor:
        await tor.bootstrap()
        print("\n[multi] Launching 3 parallel circuits …")
        await asyncio.gather(
            fetch_one(tor, "A"),
            fetch_one(tor, "B"),
            fetch_one(tor, "C"),
        )


# ---------------------------------------------------------------------------
# Example 5: Using the directory client directly
# ---------------------------------------------------------------------------


async def example_directory() -> None:
    """Show relay statistics from the consensus."""
    from libtor.directory import DirectoryClient

    dir_client = DirectoryClient(timeout=30)
    print("\n[dir] Fetching consensus …")
    relays = await dir_client.fetch_consensus()

    guards = dir_client.get_guards()
    middles = dir_client.get_middle_relays()
    exits = dir_client.get_exits()

    print(f"[dir] Total relays : {len(relays)}")
    print(f"[dir] Guards       : {len(guards)}")
    print(f"[dir] Middle relays: {len(middles)}")
    print(f"[dir] Exit relays  : {len(exits)}")

    print("\n[dir] Top 5 guards by bandwidth:")
    for r in sorted(guards, key=lambda r: r.bandwidth, reverse=True)[:5]:
        print(
            f"  {r.nickname:20s}  {r.address:16s}:{r.or_port:<5d}  {r.bandwidth} KB/s"
        )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

EXAMPLES = {
    "fetch": example_fetch,
    "resolve": example_resolve,
    "raw_stream": example_raw_stream,
    "multi_circuit": example_multi_circuit,
    "directory": example_directory,
}

if __name__ == "__main__":
    name = sys.argv[1] if len(sys.argv) > 1 else "directory"
    if name not in EXAMPLES:
        print(f"Unknown example '{name}'. Choose from: {', '.join(EXAMPLES)}")
        sys.exit(1)
    asyncio.run(EXAMPLES[name]())
