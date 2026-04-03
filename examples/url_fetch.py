import argparse
import asyncio
import sys

sys.path.insert(0, "src")
import logging

from libtor import TorClient
from libtor.logging_ import setup_logging

setup_logging(2)  # INFO level


async def main(host, port, path):
    tor = TorClient()
    await tor.bootstrap()
    async with tor.create_circuit(hops=3, target_port=port) as circ:
        print(f"Circuit: {len(circ._hops)} hops")
        # Open stream
        print(f"Opening stream to {host}:{port}...")
        stream = await circ.open_stream(host, port)
        print(f"Stream: {stream}")
        # Send HTTP request
        print("Sending HTTP request...")
        await stream.send(
            (
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            ).encode()
        )
        print("Waiting for response...")
        try:
            chunks = []
            while True:
                chunk = await asyncio.wait_for(stream.recv(4096), timeout=5.0)
                if not chunk:
                    break
                chunks.append(chunk)
            resp = b"".join(chunks)
            print(f"Got response ({len(resp)} bytes): {resp}")
        except asyncio.TimeoutError:
            print("TIMEOUT waiting for response")
            # Check stream queue state
            print(f"Stream queue size: {stream._queue.qsize()}")
            print(f"Circuit queue size: {circ._queue.qsize()}")
            print(f"Circuit streams: {list(circ._streams.keys())}")
        await stream.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "url", help="Destination URL (e.g., http://check.torproject.org:80/api/ip)"
    )
    args = parser.parse_args()

    from urllib.parse import urlparse

    parsed = urlparse(args.url)
    host = parsed.hostname
    port = parsed.port or 80
    path = parsed.path or "/"

    asyncio.run(main(host, port, path))
