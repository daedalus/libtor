"""
TorClient – high-level async API for the torpy library.

Handles:
  - Bootstrapping (consensus fetch + relay selection)
  - Guard state persistence across sessions
  - ntor key fetching for each relay
  - Building circuits (guard → middle → exit)
  - Convenience wrappers for HTTP and raw TCP
"""

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from .circuit import Circuit
from .connection import ORConnection
from .directory import DirectoryClient, GuardSelection, RouterInfo
from .exceptions import CircuitError, TorError

log = logging.getLogger(__name__)

DEFAULT_CIRCUIT_HOPS = 3
DEFAULT_TIMEOUT = 30.0


class TorClient:
    """
    High-level Tor client.

    Example::

        async with TorClient() as tor:
            await tor.bootstrap()
            async with tor.create_circuit() as circuit:
                async with circuit.open_stream("example.com", 80) as stream:
                    body = await stream.http_get("example.com")
                    print(body[:200])

    Or using the shorthand helper::

        async with TorClient() as tor:
            body = await tor.fetch("http://example.com")
            print(body[:200])
    """

    def __init__(
        self,
        hops: int = DEFAULT_CIRCUIT_HOPS,
        timeout: float = DEFAULT_TIMEOUT,
        directory_timeout: float = 30.0,
        guard_state_file: str | None = "guard_state.json",
    ):
        self._hops = hops
        self._timeout = timeout
        self._dir = DirectoryClient(timeout=directory_timeout)
        self._bootstrapped = False

        # Guard state for persistent guard selection
        self._guard_selection: GuardSelection | None = None
        self._guard_state_file = guard_state_file

    @property
    def guard_selection(self) -> GuardSelection | None:
        """Return the guard selection, None before bootstrap."""
        return self._guard_selection

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    async def bootstrap(self) -> None:
        """
        Fetch the consensus and prepare relay lists.
        Must be called before creating circuits.

        Initializes guard selection state from disk if available.
        """
        log.info("Bootstrapping: fetching consensus …")
        await self._dir.fetch_consensus()

        # Initialize guard selection with persisted state
        self._guard_selection = GuardSelection(state_file=self._guard_state_file)
        guards = self._dir.get_guards()
        middles = self._dir.get_middle_relays()
        exits = self._dir.get_exits()

        log.info(
            "Bootstrap complete: %d guards, %d middles, %d exits available",
            len(guards),
            len(middles),
            len(exits),
        )
        self._bootstrapped = True

    async def close(self) -> None:
        """No persistent connections – nothing to close at client level."""
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()

    # -----------------------------------------------------------------------
    # Circuit creation
    # -----------------------------------------------------------------------

    @asynccontextmanager
    async def create_circuit(
        self,
        hops: int | None = None,
        guard: RouterInfo | None = None,
        middle: RouterInfo | None = None,
        exit_: RouterInfo | None = None,
    ) -> AsyncIterator[Circuit]:
        """
        Async context manager that yields a built Circuit.

        ``hops`` overrides the client-level default.
        You may pin specific relays via guard/middle/exit_ kwargs.
        """
        if not self._bootstrapped:
            await self.bootstrap()

        num_hops = hops or self._hops

        path = await self._select_path(
            num_hops=num_hops,
            guard=guard,
            middle=middle,
            exit_=exit_,
        )

        conn = ORConnection(path[0].address, path[0].or_port, timeout=self._timeout)
        circuit = Circuit(conn, timeout=self._timeout)

        async with conn:
            await circuit.create(path[0])
            log.info("Circuit created to guard %s", path[0].nickname)

            for relay in path[1:]:
                nkey = await self._fetch_ntor_key(relay, path[0])
                await circuit.extend(relay, ntor_key=nkey)
                log.info("Circuit extended to %s", relay.nickname)

            try:
                yield circuit
            finally:
                await circuit.destroy()

    # -----------------------------------------------------------------------
    # Convenience helpers
    # -----------------------------------------------------------------------

    async def fetch(
        self,
        url: str,
        timeout: float = 30.0,
        extra_headers: dict | None = None,
    ) -> bytes:
        """
        Fetch a URL over a fresh Tor circuit.

        Supports http:// and (with connect) https:// via CONNECT.
        Returns the response body bytes.

        Example::

            body = await tor.fetch("http://check.torproject.org/")
        """
        host, port, path, is_https = _parse_url(url)

        async with self.create_circuit() as circuit:
            async with await circuit.open_stream(host, port) as stream:
                if is_https:
                    # Upgrade to TLS inside the Tor stream
                    import ssl as _ssl

                    ctx = _ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = _ssl.CERT_NONE
                    # Wrap the stream's underlying transport (advanced – simplified here)
                    raise TorError(
                        "Direct HTTPS is not yet supported; "
                        "use port 80 or connect to a .onion HTTP service. "
                        "For HTTPS, open a stream to port 443 and wrap with ssl."
                    )
                return await stream.http_get(
                    host,
                    path,
                    extra_headers=extra_headers,
                    timeout=timeout,
                )

    async def resolve(self, hostname: str) -> list[str]:
        """
        Resolve a hostname via Tor's RELAY_RESOLVE (DNS-over-Tor).

        Returns a list of IP addresses.
        """

        from .cells import RelayCommand

        async with self.create_circuit() as circuit:
            stream_id = circuit._alloc_stream_id()
            q = asyncio.Queue()
            circuit._streams[stream_id] = q

            payload = hostname.encode() + b"\x00"
            await circuit._send_relay_cell(
                relay_command=RelayCommand.RESOLVE,
                stream_id=stream_id,
                data=payload,
            )

            cell = await asyncio.wait_for(q.get(), timeout=self._timeout)
            if cell is None:
                raise TorError("Circuit closed during RESOLVE")
            if cell.relay_command != RelayCommand.RESOLVED:
                raise TorError(f"Unexpected response to RESOLVE: {cell!r}")

            return _parse_resolved(cell.data)

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    async def _select_path(
        self,
        num_hops: int,
        guard: RouterInfo | None,
        middle: RouterInfo | None,
        exit_: RouterInfo | None,
    ) -> list[RouterInfo]:
        """Select guard → [middle…] → exit, avoiding duplicates."""
        guards = self._dir.get_guards()
        middles = self._dir.get_middle_relays()
        exits = self._dir.get_exits()

        if not guards or not exits:
            raise CircuitError(
                "Insufficient relays in consensus "
                f"(guards={len(guards)}, exits={len(exits)})"
            )

        # Use guard selection for persistent guards if no specific guard provided
        if guard is None and self._guard_selection is not None:
            chosen_guard = self._guard_selection.select(guards)
            if chosen_guard is None:
                log.warning("No persistent guards available, selecting from all guards")
                chosen_guard = self._dir.weighted_choice(guards)
        else:
            chosen_guard = guard or self._dir.weighted_choice(guards)

        chosen_exit = exit_ or self._dir.weighted_choice(
            [r for r in exits if r.identity != chosen_guard.identity]
        )

        path = [chosen_guard]

        for _ in range(num_hops - 2):
            excluded = {r.identity for r in path}
            excluded.add(chosen_exit.identity)
            candidates = [r for r in middles if r.identity not in excluded]
            if not candidates:
                raise CircuitError("Not enough relays for desired circuit length")
            m = middle or self._dir.weighted_choice(candidates)
            path.append(m)

        path.append(chosen_exit)
        return path

    async def _fetch_ntor_key(
        self,
        router: RouterInfo,
        via: RouterInfo,
    ) -> bytes:
        """
        Fetch the ntor-onion-key for `router` using `via` as the directory
        cache (plain HTTP to via's dir_port).
        """
        if router.ntor_onion_key is not None:
            return router.ntor_onion_key

        dir_port = via.dir_port or 80
        key = await self._dir.fetch_ntor_key(router, via.address, dir_port)
        if key is None:
            # Try the router's own dir port
            if router.dir_port:
                key = await self._dir.fetch_ntor_key(
                    router, router.address, router.dir_port
                )
        if key is None:
            raise CircuitError(
                f"Could not fetch ntor key for relay {router.nickname}. "
                "Ensure the relay has a dir_port or provide the key manually."
            )
        router.ntor_onion_key = key
        return key


# ---------------------------------------------------------------------------
# URL parsing helper
# ---------------------------------------------------------------------------


def _parse_url(url: str) -> tuple[str, int, str, bool]:
    """Return (host, port, path, is_https) from an http/https URL."""
    is_https = url.startswith("https://")
    url = url.removeprefix("https://").removeprefix("http://")
    if "/" in url:
        hostpart, _, path = url.partition("/")
        path = "/" + path
    else:
        hostpart = url
        path = "/"
    if ":" in hostpart:
        host, _, port_s = hostpart.rpartition(":")
        port = int(port_s)
    else:
        host = hostpart
        port = 443 if is_https else 80
    return host, port, path, is_https


def _parse_resolved(data: bytes) -> list[str]:
    """Parse RELAY_RESOLVED payload into IP strings."""
    results = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            break
        atype = data[offset]
        alen = data[offset + 1]
        offset += 2
        if offset + alen > len(data):
            break
        aval = data[offset : offset + alen]
        offset += alen
        # TTL (4 bytes)
        offset += 4

        if atype == 4 and alen == 4:
            results.append(".".join(str(b) for b in aval))
        elif atype == 6 and alen == 16:
            import socket

            results.append(socket.inet_ntop(socket.AF_INET6, aval))
        elif atype == 0xF0:
            results.append(aval.decode(errors="replace"))
    return results
