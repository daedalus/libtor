"""
TorClient – high-level async API for the torpy library.

Handles:
  - Bootstrapping (consensus fetch + relay selection)
  - Directory cache for fresh descriptors
  - Guard state persistence across sessions
  - ntor key fetching for each relay
  - Building circuits (guard → middle → exit)
  - Convenience wrappers for HTTP and raw TCP
"""

import asyncio
import logging
import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from .circuit import Circuit
from .connection import ORConnection
from .directory import (
    DescriptorCache,
    DIRECTORY_AUTHORITIES,
    DIR_SERVERS,
    DirectoryClient,
    GuardSelection,
    RouterInfo,
)
from .exceptions import CircuitError, HandshakeError, TorError
from .cells import RelayCommand
from .logging_ import trace, debug, info, setup_logging

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
        guard_state_file: str | None = None,
        fetch_descriptors: bool = True,
        cache_file: str | None = None,
        debug: bool = False,
    ):
        self._hops = hops
        self._timeout = timeout
        self._debug = debug
        self._desc_cache = DescriptorCache(
            timeout=directory_timeout,
            cache_file=cache_file,
        )
        self._dir = DirectoryClient(
            timeout=directory_timeout,
            desc_cache=self._desc_cache,
        )
        self._fetch_descriptors = fetch_descriptors
        self._bootstrapped = False

        # Guard state for persistent guard selection
        self._guard_selection: GuardSelection | None = None
        self._guard_state_file = guard_state_file

        # Set debug flags in other modules
        if debug:
            import libtor.circuit
            import libtor.directory

            libtor.circuit.DEBUG = True
            libtor.directory.DEBUG = True

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
        Loads cached ntor keys from SQLite DB if available, otherwise fetches via Tor.
        """
        log.info("Bootstrapping: fetching consensus …")
        await self._dir.fetch_consensus()

        # Check cache status - only fetch keys if cache is empty
        cache_keys = self._desc_cache.get_key_count()
        stale_count = self._desc_cache.get_stale_count()

        if cache_keys == 0 and self._fetch_descriptors:
            # No cached keys - fetch a small batch for immediate needs
            # We'll fetch more lazily as needed during circuit creation
            log.info("No cached ntor keys, will fetch lazily on demand")
        else:
            log.info(
                "Using cached ntor keys from DB (%d keys, %d stale)",
                cache_keys,
                stale_count,
            )

        # Initialize guard selection with persisted state from database
        self._guard_selection = GuardSelection(
            conn=self._desc_cache.conn,
            state_file=self._guard_state_file,
        )
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

    async def _fetch_ntor_keys_from_directory(self) -> None:
        """
        Fetch ntor keys from directory servers directly.

        Per Tor C implementation:
        - Uses directory servers to fetch router descriptors
        - Each descriptor contains the ntor-onion-key
        - Fetches in parallel to speed up
        """
        log.info("Fetching ntor keys from directory servers...")

        # Get all guards, middles, and exits
        targets = []
        targets.extend([g.identity for g in self._dir.get_guards()])
        targets.extend([m.identity for m in self._dir.get_middle_relays()])
        targets.extend([e.identity for e in self._dir.get_exits()])
        targets = list(set(targets))  # Remove duplicates

        log.info("Fetching ntor keys for %d relays", len(targets))

        # Fetch keys for first 50 relays (parallel-ish)
        success_count = 0
        for identity in targets[:50]:
            router = next(
                (r for r in self._dir._routers if r.identity == identity),
                None,
            )
            if not router:
                continue

            try:
                key = await self._dir.fetch_ntor_key(router, "204.13.164.118", 80)
                if key:
                    self._desc_cache.set_ntor_key(identity, key)
                    log.debug("Got fresh ntor key for %s", router.nickname)
                    success_count += 1
                else:
                    log.debug("No ntor key for %s", router.nickname)
            except Exception as e:
                log.debug("Failed to fetch ntor key for %s: %s", router.nickname, e)

        log.info(
            "Done fetching ntor keys: %d/%d successful",
            success_count,
            min(50, len(targets)),
        )

    async def close(self) -> None:
        log.info("Fetching consensus and ntor keys via Tor circuit...")

        # Build 1-hop circuit directly without requiring bootstrap
        from .circuit import Circuit, CircuitHop
        from .connection import ORConnection
        from .crypto import FastHandshake
        from .cells import Cell, CellCommand, RelayCommand

        guards = self._dir.get_guards()
        exits = self._dir.get_exits()

        # Find guard+exit
        exit_ids = {e.identity for e in exits}
        guard_exits = [g for g in guards if g.identity in exit_ids]

        # Use any guard if no guard+exit
        path_relays = guard_exits[:1] or guards[:1]
        if not path_relays:
            log.warning("No relays available for directory circuit")
            return

        relay = path_relays[0]
        log.info("Building 1-hop circuit to %s", relay.nickname)

        conn = ORConnection(relay.address, relay.or_port, timeout=self._timeout)
        circuit = Circuit(conn, timeout=self._timeout)

        try:
            async with conn:
                # Create circuit with CREATE_FAST
                hs = FastHandshake()
                cell = Cell(
                    circuit._circ_id, CellCommand.CREATE_FAST, hs.create_payload()
                )
                await conn.send_cell(cell)

                resp = await asyncio.wait_for(
                    circuit._queue.get(), timeout=self._timeout
                )
                if resp.command != CellCommand.CREATED_FAST:
                    log.warning("Failed to create directory circuit: %s", resp.command)
                    return

                y = resp.payload[:20]
                kh = resp.payload[20:40]
                keys = hs.complete(y, kh)
                circuit._hops.append(CircuitHop(keys=keys, router=relay))

                # Start dispatch task
                circuit._dispatch_task = asyncio.create_task(
                    circuit._stream_dispatch(), name=f"dir-circuit-dispatch"
                )

                # Open directory stream
                stream_id = circuit._alloc_stream_id()
                q = asyncio.Queue()
                circuit._streams[stream_id] = q

                await circuit._send_relay_cell(
                    relay_command=RelayCommand.BEGIN_DIR,
                    stream_id=stream_id,
                    data=b"",
                )

                # Wait for CONNECTED
                cell = await asyncio.wait_for(q.get(), timeout=self._timeout)
                if cell is None or cell.relay_command not in (
                    RelayCommand.CONNECTED,
                    RelayCommand.DATA,
                ):
                    log.warning("Failed to open dir stream")
                    return

                log.info("Directory stream ready")

                # First fetch the consensus through Tor (it's fresher/larger)
                try:
                    log.info("Fetching fresh consensus through Tor...")

                    # Open fresh stream for consensus
                    stream_id2 = circuit._alloc_stream_id()
                    q2 = asyncio.Queue()
                    circuit._streams[stream_id2] = q2

                    await circuit._send_relay_cell(
                        relay_command=RelayCommand.BEGIN_DIR,
                        stream_id=stream_id2,
                        data=b"",
                    )

                    cell = await asyncio.wait_for(q2.get(), timeout=30)
                    if cell is None or cell.relay_command not in (
                        RelayCommand.CONNECTED,
                        RelayCommand.DATA,
                    ):
                        log.warning("Failed to open stream for consensus")
                    else:
                        request = b"GET /tor/status-vote/current/consensus HTTP/1.0\r\nHost: 128.31.0.39\r\n\r\n"
                        await circuit._send_relay_cell(
                            relay_command=RelayCommand.DATA,
                            stream_id=stream_id2,
                            data=request,
                        )

                        # Collect consensus response
                        consensus_data = b""
                        while True:
                            cell = await asyncio.wait_for(q2.get(), timeout=60)
                            if cell is None:
                                break
                            if cell.relay_command == RelayCommand.END:
                                break
                            if cell.relay_command == RelayCommand.DATA:
                                consensus_data += cell.data

                        # Parse and update consensus
                        if consensus_data:
                            text = consensus_data.decode("utf-8", errors="ignore")
                            if "\r\n\r\n" in text:
                                _, body = text.split("\r\n\r\n", 1)
                            else:
                                body = text

                            from .directory import ConsensuParser

                            new_routers = ConsensuParser.parse(body)
                            if new_routers:
                                self._dir._routers = new_routers
                                log.info(
                                    "Updated consensus: %d routers", len(new_routers)
                                )
                except Exception as e:
                    import traceback

                    log.warning("Failed to fetch fresh consensus: %s", e)
                    log.debug("Trace: %s", traceback.format_exc())

                # Now fetch ntor keys for guards, middles, and exits from the new consensus
                import base64

                targets = []
                targets.extend([g.identity for g in self._dir.get_guards()])
                targets.extend([m.identity for m in self._dir.get_middle_relays()])
                targets.extend([e.identity for e in self._dir.get_exits()])
                targets = list(set(targets))  # Remove duplicates

                log.info("Fetching ntor keys for %d relays", len(targets))

                for identity in targets[:20]:
                    router = next(
                        (r for r in self._dir._routers if r.identity == identity),
                        None,
                    )
                    if not router:
                        continue

                    try:
                        # Open a new stream for each request
                        stream_id = circuit._alloc_stream_id()
                        q = asyncio.Queue()
                        circuit._streams[stream_id] = q

                        await circuit._send_relay_cell(
                            relay_command=RelayCommand.BEGIN_DIR,
                            stream_id=stream_id,
                            data=b"",
                        )

                        # Wait for CONNECTED
                        cell = await asyncio.wait_for(q.get(), timeout=30)
                        if cell is None or cell.relay_command not in (
                            RelayCommand.CONNECTED,
                            RelayCommand.DATA,
                        ):
                            continue

                        # Fetch descriptor
                        request = f"GET /tor/server/fp/{router.identity_hex} HTTP/1.0\r\nHost: 128.31.0.39\r\n\r\n".encode()
                        await circuit._send_relay_cell(
                            relay_command=RelayCommand.DATA,
                            stream_id=stream_id,
                            data=request,
                        )

                        # Read response
                        desc_data = b""
                        while True:
                            cell = await asyncio.wait_for(q.get(), timeout=30)
                            if cell is None:
                                break
                            if cell.relay_command == RelayCommand.END:
                                break
                            if cell.relay_command == RelayCommand.DATA:
                                desc_data += cell.data

                        # Parse for ntor key
                        if desc_data and b"ntor-onion-key" in desc_data:
                            text = desc_data.decode("utf-8", errors="ignore")
                            for line in text.split("\n"):
                                if line.startswith("ntor-onion-key "):
                                    key = base64.b64decode(line.split()[1] + "==")
                                    self._desc_cache.set_ntor_key(identity, key)
                                    log.info(
                                        "Got fresh ntor key for %s", router.nickname
                                    )
                                    break

                        # Close stream
                        circuit.close_stream(stream_id)

                    except Exception as e:
                        log.debug("Failed to fetch key for %s: %s", router.nickname, e)

        except Exception as e:
            log.warning("Failed to fetch descriptors via Tor: %s", e)
        finally:
            await circuit.destroy()

        log.info("Done fetching ntor keys via Tor")

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
        target_host: str | None = None,
        target_port: int | None = None,
    ) -> AsyncIterator[Circuit]:
        """Build a multi-hop circuit to the Tor network.

        Creates a circuit with the specified number of hops (default: 3).
        Yields a Circuit that can be used to open streams.

        target_host and target_port can be specified to filter exit nodes
        by exit policy (exit must allow connecting to target_port).
        """

        if not self._bootstrapped:
            await self.bootstrap()

        num_hops = hops or self._hops

        # Use longer timeout for multi-hop circuits (key fetching takes time)
        timeout = 30.0 * 6 if num_hops > 1 else self._timeout

        # For multi-hop circuits, we need ntor for the guard
        # If it fails, we retry with different guards rather than falling back to CREATE_FAST
        is_directory = num_hops == 1
        max_guard_retries = 3 if not is_directory else 1

        for attempt in range(max_guard_retries):
            log.debug(f"Attempt {attempt + 1}/{max_guard_retries}")
            path = await self._select_path(
                num_hops=num_hops,
                guard=guard,
                middle=middle,
                exit_=exit_,
                target_host=target_host,
                target_port=target_port,
            )
            log.debug(f"Path selected: {[r.nickname for r in path]}")

            conn = ORConnection(path[0].address, path[0].or_port, timeout=timeout)
            circuit = Circuit(conn, timeout=timeout)

            # Fetch ntor key for the guard
            guard_ntor_key = None
            if not is_directory:
                guard_ntor_key = self._desc_cache.get_ntor_key(path[0].identity)
                if guard_ntor_key is None:
                    guard_ntor_key = await self._fetch_ntor_key(
                        path[0], force_refresh=True
                    )

            async with conn:
                try:
                    await circuit.create(
                        path[0], ntor_key=guard_ntor_key, is_directory=is_directory
                    )
                    log.info("Circuit created to guard %s", path[0].nickname)
                    hops_str = " → ".join(h.router.nickname for h in circuit._hops)
                    log.info(f"Circuit path: {hops_str}")
                except HandshakeError as e:
                    # ntor key is stale - try refreshing the key once
                    log.warning(
                        "Handshake failed (stale ntor key) for %s, attempting key refresh",
                        path[0].nickname,
                    )
                    # Try force refreshing the key
                    fresh_key = self._desc_cache.get_ntor_key(path[0].identity)
                    if fresh_key is None:
                        fresh_key = await self._fetch_ntor_key(
                            path[0], force_refresh=True
                        )
                    if fresh_key:
                        log.info(
                            "Got fresh ntor key for %s, retrying circuit create",
                            path[0].nickname,
                        )
                        await circuit.destroy()
                        # Create new circuit with fresh key
                        circuit = Circuit(conn, timeout=self._timeout)
                        await circuit.create(
                            path[0], ntor_key=fresh_key, is_directory=is_directory
                        )
                        log.info(
                            "Circuit created to guard %s with fresh key",
                            path[0].nickname,
                        )
                    else:
                        # Mark stale and try different guard
                        self._mark_ntor_key_stale(path[0])
                        if self._guard_selection and self._guard_selection.state:
                            self._guard_selection.record_handshake_failure(
                                path[0].identity_hex
                            )
                        await circuit.destroy()
                        guard = None  # Select new guard
                        continue
                except Exception as e:
                    log.warning(
                        "Circuit create failed (attempt %d/%d): %s",
                        attempt + 1,
                        max_guard_retries,
                        e,
                    )
                    await circuit.destroy()
                    if attempt < max_guard_retries - 1:
                        # Try a different guard
                        guard = None  # Will select new guard in next iteration
                        continue
                    raise CircuitError(
                        f"Failed to create circuit after {max_guard_retries} attempts: {e}"
                    )

                # Keep circuit alive during extend by sending padding cells periodically
                async def keepalive_task():
                    """Send periodic padding to keep circuit alive during key fetching."""
                    from .cells import RelayCommand

                    while not circuit._destroyed:
                        try:
                            await asyncio.sleep(1)  # Send every 1 second
                            if circuit._destroyed:
                                break
                            # Send a NOOP relay cell to keep circuit alive
                            await circuit._send_relay_cell(
                                relay_command=RelayCommand.DROP,
                                stream_id=0,
                                data=b"",
                            )
                            log.debug("Sent keepalive padding cell")
                        except Exception:
                            pass

                keepalive = asyncio.create_task(keepalive_task())

                # Extend to middle and exit hops
                extended_ok = True
                for relay in path[1:]:
                    log.info("=== Extending to %s ===", relay.nickname)

                    # Fetch ntor key BEFORE extending (circuit is idle while key is fetched)
                    # This prevents the circuit from being closed due to idle timeout
                    log.debug(f"CLIENT: Starting ntor key fetch for {relay.nickname}")

                    nkey = self._desc_cache.get_ntor_key(relay.identity)
                    if nkey is None:
                        # Skip circuit-based fetch - requires 2+ hop circuit which we don't have yet
                        # Instead, fetch directly via HTTP (falls back to consensus key)
                        log.info("Cache miss for %s, fetching via HTTP", relay.nickname)
                        nkey = await self._fetch_ntor_key(relay, force_refresh=True)

                    log.debug(
                        f"CLIENT: Finished ntor key fetch for {relay.nickname}, result={'None' if nkey is None else 'key'}"
                    )

                    if circuit._destroyed:
                        log.warning(
                            "Circuit destroyed during key fetch for %s, retrying with new circuit",
                            relay.nickname,
                        )
                        extended_ok = False
                        break

                    if nkey is None:
                        log.warning(
                            "No ntor key for %s, skipping extend", relay.nickname
                        )
                        self._mark_ntor_key_stale(relay)
                        extended_ok = False
                        break

                        log.info(
                            "Extend: about to call circuit.extend(%s)", relay.nickname
                        )
                    # Per Tor C implementation: if ntor fails, fall back to CREATE_FAST
                    # This allows circuit creation to succeed even with stale keys
                    trace(f"Circuit.extend({relay.nickname})")
                    try:
                        await circuit.extend(relay, ntor_key=nkey)
                        trace(f"Circuit.extend({relay.nickname}) returned")
                        log.info("Circuit extended to %s", relay.nickname)
                        # Log the full circuit path
                        hops_str = " → ".join(h.router.nickname for h in circuit._hops)
                        log.info(f"Circuit path: {hops_str}")
                    except Exception as e:
                        import traceback

                        log.error("Extend exception: %s", traceback.format_exc())
                        # ntor failed - per Tor C implementation, we don't fall back to
                        # CREATE_FAST for circuit extension (it's explicitly forbidden by
                        # the Tor protocol - relays reject CREATE_FAST inside EXTEND2 cells).
                        # Mark the key as stale and try a different path.
                        log.warning(
                            "Extend handshake failed for %s (%s), cannot fall back to CREATE_FAST",
                            relay.nickname,
                            e,
                        )
                        self._mark_ntor_key_stale(relay)
                        extended_ok = False
                        break

                keepalive.cancel()
                try:
                    await keepalive
                except asyncio.CancelledError:
                    pass

                if extended_ok or num_hops == 1:
                    try:
                        yield circuit
                    finally:
                        await circuit.destroy()
                    return

                # If extend failed, try again with new path
                await circuit.destroy()
                guard = None  # Will select new guard in next iteration

        raise CircuitError("Failed to build multi-hop circuit")

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
        target_host: str | None = None,
        target_port: int | None = None,
    ) -> list[RouterInfo]:
        """Select guard → [middle…] → exit, avoiding duplicates and stale keys.

        If target_host and target_port are specified, filters exit nodes
        by exit policy (exit must allow connecting to target_port).
        """
        guards = self._dir.get_guards()
        middles = self._dir.get_middle_relays()
        exits = self._dir.get_exits()

        # Filter out relays with known stale ntor keys (unless explicitly requested)
        # For now, don't filter by stale status - let the handshake fail and mark stale then
        if guard is None:
            pass  # Temporarily disabled stale filtering
            # guards = [g for g in guards if not self._desc_cache.is_stale(g.identity)]
            # middles = [m for m in middles if not self._desc_cache.is_stale(m.identity)]
            # exits = [e for e in exits if not self._desc_cache.is_stale(e.identity)]

        if not guards:
            raise CircuitError("Insufficient relays in consensus (guards=0)")

        # For 1-hop circuit, prefer guards that are also exits
        if num_hops == 1:
            exit_ids = {e.identity for e in exits} if exits else set()
            guard_exits = [g for g in guards if g.identity in exit_ids]
            if guard_exits:
                return [self._dir.weighted_choice(guard_exits)]
            elif exits:
                # Use an exit relay as guard
                return [self._dir.weighted_choice(exits)]
            else:
                return [self._dir.weighted_choice(guards)]

        # Use guard selection for persistent guards if no specific guard provided
        if guard is None and self._guard_selection is not None:
            chosen_guard = self._guard_selection.select(guards)
            if chosen_guard is None:
                log.warning("No persistent guards available, selecting from all guards")
                chosen_guard = self._dir.weighted_choice(guards)
        else:
            chosen_guard = guard or self._dir.weighted_choice(guards)

        path = [chosen_guard]

        if not exits:
            raise CircuitError("No exit relays available")

        # Filter exits by target port if specified
        # Note: We don't fetch exit policies upfront - can_exit_to() will return True
        # if no policy info is available. The actual failure will happen at stream
        # open time if the exit doesn't allow the target port.
        if target_port is not None:
            log.debug(f"Filtering exits for port {target_port}")
            # Try to filter exits that we know definitely reject the port
            # (we accept False from can_exit_to, but True is ambiguous)
            valid_exits = [r for r in exits if r.can_exit_to(target_port) is False]
            if valid_exits:
                log.debug(
                    f"Excluding {len(valid_exits)} exits that reject port {target_port}"
                )
                exits = [r for r in exits if r not in valid_exits]

        chosen_exit = exit_ or self._dir.weighted_choice(
            [r for r in exits if r.identity != chosen_guard.identity]
        )

        for _ in range(num_hops - 2):
            excluded = {r.identity for r in path}
            excluded.add(chosen_exit.identity)
            candidates = [r for r in middles if r.identity not in excluded]
            if not candidates:
                raise CircuitError("Not enough relays for desired circuit length")
            m = middle or self._dir.weighted_choice(candidates)
            path.append(m)

        path.append(chosen_exit)

        # For num_hops=3, path is now [guard, middle, exit]
        # Ensure all three are different
        if len(path) != len({r.identity for r in path}):
            raise CircuitError("Duplicate relay in path")

        return path

    async def _fetch_ntor_key_through_circuit(
        self,
        circuit: Circuit,
        router: RouterInfo,
    ) -> bytes | None:
        """Fetch ntor key for router through an existing Tor circuit.

        This is faster than direct HTTP because it goes through the Tor network.
        """
        log.debug(f"CLIENT: Fetching ntor key for {router.nickname} via circuit")

        stream_id = circuit._alloc_stream_id()
        q: asyncio.Queue = asyncio.Queue()
        circuit._streams[stream_id] = q

        try:
            await circuit._send_relay_cell(
                relay_command=RelayCommand.BEGIN_DIR,
                stream_id=stream_id,
                data=b"",
            )

            cell = await asyncio.wait_for(q.get(), timeout=30)
            if cell is None or cell.relay_command not in (
                RelayCommand.CONNECTED,
                RelayCommand.DATA,
            ):
                log.warning("Failed to open dir stream for key fetch")
                return None

            request = f"GET /tor/server/fp/{router.identity_hex} HTTP/1.0\r\nHost: 128.31.0.39\r\n\r\n".encode()
            await circuit._send_relay_cell(
                relay_command=RelayCommand.DATA,
                stream_id=stream_id,
                data=request,
            )

            desc_data = b""
            while True:
                cell = await asyncio.wait_for(q.get(), timeout=30)
                if cell is None:
                    break
                if cell.relay_command == RelayCommand.END:
                    break
                if cell.relay_command == RelayCommand.DATA:
                    desc_data += cell.data

            if desc_data and b"ntor-onion-key" in desc_data:
                text = desc_data.decode("utf-8", errors="ignore")
                for line in text.split("\n"):
                    if line.startswith("ntor-onion-key "):
                        key = base64.b64decode(line.split()[1] + "==")
                        self._desc_cache.set_ntor_key(router.identity, key)
                        log.debug(
                            f"CLIENT: Got ntor key for {router.nickname} via circuit, updated cache"
                        )
                        return key

            return None
        except Exception as e:
            log.debug("Failed to fetch key via circuit for %s: %s", router.nickname, e)
            return None
        finally:
            circuit.close_stream(stream_id)

    async def _fetch_ntor_key(
        self,
        router: RouterInfo,
        via: RouterInfo | None = None,
        force_refresh: bool = False,
    ) -> bytes | None:
        """Fetch the ntor-onion-key for `router`.

        Uses microdescriptor fetching for fresher keys, then falls back to server descriptors.
        """
        # Check cache first, unless force_refresh
        cached_key = self._desc_cache.get_ntor_key(router.identity)
        if cached_key and not force_refresh:
            return cached_key

        # Use DescriptorCache.get_fresh_ntor_key which tries microdescriptor first
        # (fresher keys) then falls back to server descriptor
        from .directory import FALLBACK_DIRS

        try:
            key = await self._desc_cache.get_fresh_ntor_key(router, FALLBACK_DIRS)
            if key:
                log.debug(
                    "Got fresh ntor key for %s via microdescriptor", router.nickname
                )
                return key
        except Exception as e:
            log.debug("Fresh key fetch failed for %s: %s", router.nickname, e)

        log.warning(
            "Could not fetch ntor key for relay %s",
            router.nickname,
        )
        return None

    def _mark_ntor_key_stale(self, router: RouterInfo) -> None:
        """Mark a relay's ntor key as stale (handshake failed)."""
        self._desc_cache.mark_stale(router.identity)


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
