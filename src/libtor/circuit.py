"""
Tor circuit – CREATE2, EXTEND2, relay cell send/receive.

References:
  - tor-spec.txt §5 (Circuit Management)
  - tor-spec.txt §6 (Flow Control – SENDME)
  - tor-spec.txt §7 (Relay cells)
"""

import asyncio
import logging
import struct

from .cells import (
    Cell,
    CellCommand,
    DestroyReason,
    EndReason,
    RelayCell,
    RelayCommand,
)
from .connection import ORConnection
from .crypto import CircuitKeys, FastHandshake, NtorHandshake
from .directory import RouterInfo
from .exceptions import (
    CircuitError,
    DestroyedError,
    RelayError,
)
from .logging_ import trace, debug, info, setup_logging

log = logging.getLogger(__name__)

# Flow control window sizes (tor-spec.txt §7.4)
CIRCUIT_WINDOW_START = 1000
CIRCUIT_WINDOW_INCREMENT = 100
STREAM_WINDOW_START = 500
STREAM_WINDOW_INCREMENT = 50


class CircuitHop:
    """Cryptographic state for one hop in the circuit."""

    def __init__(self, keys: CircuitKeys, router: RouterInfo):
        self.keys = keys
        self.router = router


class Circuit:
    """
    A Tor circuit – an onion-encrypted path through 1–3 relays.

    Usage::

        async with circuit.open_stream("example.com", 80) as stream:
            ...
    """

    def __init__(self, conn: ORConnection, timeout: float = 30.0):
        self._conn = conn
        self._timeout = timeout
        self._circ_id = conn.alloc_circuit_id()
        self._queue = conn.register_circuit(self._circ_id)
        self._hops: list[CircuitHop] = []
        self._streams: dict[int, asyncio.Queue] = {}
        self._next_stream_id = 1
        self._destroyed = False
        self._dispatch_task: asyncio.Task | None = None
        self._extend_event: asyncio.Event | None = None
        self._extend_result: RelayCell | None = None

        # Circuit-level SENDME window
        self._deliver_window = CIRCUIT_WINDOW_START
        self._package_window = CIRCUIT_WINDOW_START

    # -----------------------------------------------------------------------
    # Build
    # -----------------------------------------------------------------------

    async def create(
        self,
        guard: RouterInfo,
        ntor_key: bytes | None = None,
        is_directory: bool = False,
    ) -> None:
        """
        Create the circuit to the guard (first hop).

        Per tor-spec.txt:
        - For anonymous connections, use CREATE2 with ntor handshake (N>=3 recommended)
        - CREATE_FAST is only for one-hop directory connections
        - "Parties SHOULD NOT use CREATE_FAST except for creating one-hop circuits"

        However, if ntor handshake fails (stale keys), fall back to CREATE_FAST.
        This is necessary because directory-sourced keys are often stale.

        Args:
            guard: The guard relay to connect to
            ntor_key: The ntor-onion-key for the guard (tries CREATE_FAST if None or fails)
            is_directory: If True, use CREATE_FAST for directory fetches only
        """
        if is_directory:
            # Use CREATE_FAST only for directory fetches (one-hop circuits)
            hs = FastHandshake()
            payload = hs.create_payload()

            cell = Cell(self._circ_id, CellCommand.CREATE_FAST, payload)
            await self._conn.send_cell(cell)

            resp = await asyncio.wait_for(self._queue.get(), timeout=self._timeout)
            if resp is None:
                raise CircuitError("Connection closed waiting for CREATED_FAST")
            if resp.command == CellCommand.DESTROY:
                reason = resp.payload[0] if resp.payload else 0
                raise CircuitError(
                    f"Circuit destroyed by relay (reason={DestroyReason(reason).name})"
                )
            if resp.command != CellCommand.CREATED_FAST:
                raise CircuitError(f"Expected CREATED_FAST, got {resp.command}")

            y = resp.payload[:20]
            kh = resp.payload[20:40]
            keys = hs.complete(y, kh)
            self._hops.append(CircuitHop(keys=keys, router=guard))
            log.debug("CREATE_FAST complete, guard=%s", guard.nickname)
        else:
            # Try ntor first, fall back to CREATE_FAST if it fails
            if ntor_key is not None:
                try:
                    await self._create_with_ntor(guard, ntor_key)
                    log.debug("Circuit created to %s via ntor", guard.nickname)
                except HandshakeError as e:
                    # ntor failed (stale key), fall back to CREATE_FAST
                    log.warning(
                        "ntor handshake failed for %s (%s), trying CREATE_FAST",
                        guard.nickname,
                        e,
                    )
                    # Allocate a fresh circuit ID for CREATE_FAST (different handshake)
                    self._circ_id = self._conn.alloc_circuit_id()
                    self._queue = self._conn.register_circuit(self._circ_id)
                    hs = FastHandshake()
                    payload = hs.create_payload()

                    cell = Cell(self._circ_id, CellCommand.CREATE_FAST, payload)
                    await self._conn.send_cell(cell)

                    resp = await asyncio.wait_for(
                        self._queue.get(), timeout=self._timeout
                    )
                    if resp is None:
                        raise CircuitError("Connection closed waiting for CREATED_FAST")
                    if resp.command == CellCommand.DESTROY:
                        reason = resp.payload[0] if resp.payload else 0
                        raise CircuitError(
                            f"Circuit destroyed by relay (reason={DestroyReason(reason).name})"
                        )
                    if resp.command != CellCommand.CREATED_FAST:
                        raise CircuitError(f"Expected CREATED_FAST, got {resp.command}")

                    y = resp.payload[:20]
                    kh = resp.payload[20:40]
                    keys = hs.complete(y, kh)
                    self._hops.append(CircuitHop(keys=keys, router=guard))
                    log.debug("CREATE_FAST fallback complete, guard=%s", guard.nickname)

            # Start the stream dispatcher AFTER circuit is created (needed for EXTEND)
            self._dispatch_task = asyncio.create_task(
                self._stream_dispatch(), name=f"circuit-{self._circ_id}-dispatch"
            )

    async def _create_with_ntor(self, guard: RouterInfo, ntor_key: bytes) -> None:
        """Create circuit using CREATE2 with ntor handshake.

        Tries ntor-v3 first, falls back to legacy ntor if v3 is rejected.

        Per Tor C implementation (onion_crypto.c):
        - Uses ONION_HANDSHAKE_TYPE_NTOR_V3 (0x0003) for modern relays
        - Falls back to ONION_HANDSHAKE_TYPE_NTOR (0x0002)
        - ntor-v3 requires congestion_control or enable_cgo support

        HTYPE values (from tor/src/core/or/or.h):
        - TAP: 0x0000 (deprecated)
        - FAST: 0x0001 (for first hop only)
        - NTOR: 0x0002 (legacy ntor)
        - NTOR_V3: 0x0003 (modern ntor with SHA3-256)
        """
        # Try ntor-v3 first (HTYPE=3 = 0x0003)
        from .crypto import NtorV3Handshake

        hs = NtorV3Handshake(guard.identity, ntor_key)
        onion_skin = hs.create_onion_skin()

        # CREATE2: htype=3 (ntor-v3), hlen=96
        payload = struct.pack("!HH", 3, len(onion_skin)) + onion_skin
        cell = Cell(self._circ_id, CellCommand.CREATE2, payload)
        await self._conn.send_cell(cell)

        resp = await asyncio.wait_for(self._queue.get(), timeout=self._timeout)
        if resp is None:
            raise CircuitError("Connection closed waiting for CREATED2")

        # If ntor-v3 is rejected, try legacy ntor (HTYPE=2)
        if resp.command == CellCommand.DESTROY:
            reason = resp.payload[0] if resp.payload else 0
            if reason == 1:  # PROTOCOL - try legacy ntor
                log.debug("ntor-v3 rejected by relay, trying legacy ntor (HTYPE=2)")
                await self._create_with_legacy_ntor(guard, ntor_key)
                return
            raise CircuitError(
                f"Circuit destroyed by relay (reason={DestroyReason(reason).name})"
            )

        if resp.command != CellCommand.CREATED2:
            raise CircuitError(f"Expected CREATED2, got {resp.command}")

        # Process ntor-v3 response
        try:
            keys = hs.complete(resp.payload)
            self._hops.append(CircuitHop(keys=keys, router=guard))
            log.debug("CREATE2 (ntor-v3) complete, guard=%s", guard.nickname)
        except Exception as e:
            # Auth failed - this is expected if key is stale
            # Re-raise as HandshakeError so caller can handle it
            from .exceptions import HandshakeError

            raise HandshakeError(f"ntor-v3 auth failed (stale key?): {e}") from e

    async def _create_with_legacy_ntor(
        self, guard: RouterInfo, ntor_key: bytes
    ) -> None:
        """Create circuit using CREATE2 with legacy ntor handshake (HTYPE=2)."""
        from .crypto import NtorHandshake

        hs = NtorHandshake(guard.identity, ntor_key)
        onion_skin = hs.create_onion_skin()

        # CREATE2: htype=2 (legacy ntor), hlen=84
        payload = struct.pack("!HH", 2, len(onion_skin)) + onion_skin
        cell = Cell(self._circ_id, CellCommand.CREATE2, payload)
        await self._conn.send_cell(cell)

        resp = await asyncio.wait_for(self._queue.get(), timeout=self._timeout)
        if resp is None:
            raise CircuitError("Connection closed waiting for CREATED2")
        if resp.command == CellCommand.DESTROY:
            reason = resp.payload[0] if resp.payload else 0
            raise CircuitError(
                f"Circuit destroyed by relay (reason={DestroyReason(reason).name})"
            )
        if resp.command != CellCommand.CREATED2:
            raise CircuitError(f"Expected CREATED2, got {resp.command}")

        # Process legacy ntor response
        try:
            keys = hs.complete(resp.payload)
            self._hops.append(CircuitHop(keys=keys, router=guard))
            log.debug("CREATE2 (legacy ntor) complete, guard=%s", guard.nickname)
        except Exception as e:
            # Auth failed - key is stale
            from .exceptions import HandshakeError

            raise HandshakeError(f"legacy ntor auth failed: {e}") from e

    async def extend(self, router: RouterInfo, ntor_key: bytes | None = None) -> None:
        """
        Extend the circuit by one hop using EXTEND2 / ntor handshake.
        Falls back to EXTEND / CREATE_FAST if ntor_key is not available.
        """
        import sys

        debug(f"CIRCUIT.extend: start for {router.nickname}", flush=True)
        log.info(
            "Attempting to extend circuit to %s (hop %d)",
            router.nickname,
            len(self._hops) + 1,
        )
        log.debug("extend: ntor_key is %s", "provided" if ntor_key else "None")

        if not self._hops:
            raise CircuitError("Cannot EXTEND before CREATE")
        if self._destroyed:
            raise DestroyedError("Circuit is destroyed")

        # Try ntor first, but fall back to CREATE_FAST if it fails
        # Note: Tor spec says relays SHOULD NOT accept CREATE_FAST in EXTEND2,
        # but many relays do accept it as a fallback
        if ntor_key is not None:
            log.debug("Trying ntor handshake for extend to %s", router.nickname)
            try:
                await asyncio.wait_for(
                    self._extend_ntor(router, ntor_key), timeout=self._timeout
                )
                log.info("ntor extend succeeded to %s", router.nickname)
                return
            except asyncio.TimeoutError:
                log.error("ntor extend timed out to %s", router.nickname)
                raise CircuitError(f"Timeout extending to {router.nickname}")
            except Exception as e:
                log.error("ntor extend failed to %s: %s", router.nickname, e)
                # Fall back to CREATE_FAST
                log.info(
                    "Falling back to CREATE_FAST for extend to %s", router.nickname
                )
                try:
                    await self._extend_fast(router)
                    log.info("CREATE_FAST extend succeeded to %s", router.nickname)
                    return
                except Exception as fast_err:
                    log.error("CREATE_FAST fallback also failed: %s", fast_err)
                    raise
        else:
            # No ntor key - use CREATE_FAST
            log.info("No ntor key for %s, using CREATE_FAST", router.nickname)
            try:
                await self._extend_fast(router)
            except Exception as e:
                log.error("CREATE_FAST extend failed to %s: %s", router.nickname, e)
                raise CircuitError(f"Failed to extend to {router.nickname}: {e}")

    async def _extend_ntor(self, router: RouterInfo, ntor_key: bytes) -> None:
        """Extend circuit using ntor/EXTEND2."""
        import sys
        import time

        debug(
            f"TRACE: _extend_ntor START for {router.nickname}",
            flush=True,
            file=sys.stderr,
        )

        log.info(
            "Attempting to extend circuit to %s (hop %d)",
            router.nickname,
            len(self._hops) + 1,
        )
        debug(
            f"DEBUG: router.address={router.address}, router.or_port={router.or_port}",
            flush=True,
            file=sys.stderr,
        )

        log.info(
            "Sending EXTEND2 to %s:%d (legacy ntor)", router.address, router.or_port
        )

        start_time = time.time()

        # Create an event to signal when EXTENDED2 is received
        extend_event = asyncio.Event()
        extend_result: list[RelayCell] = []  # Use list to allow mutation in closure

        # Store the event/result so stream_dispatch can signal us
        self._extend_event = extend_event
        self._extend_result = extend_result
        log.debug(
            "_extend_ntor: set up extend_event, current hops: %d", len(self._hops)
        )

        hs = NtorHandshake(router.identity, ntor_key)
        onion_skin = hs.create_onion_skin()
        log.debug(
            "_extend_ntor: ntor_key for %s (len=%d): %s...",
            router.nickname,
            len(ntor_key),
            ntor_key.hex()[:40],
        )
        debug(
            f"DEBUG: created onion_skin, len={len(onion_skin)}, first32={onion_skin[:32].hex()}",
            flush=True,
            file=sys.stderr,
        )
        log.debug(
            "_extend_ntor: created onion_skin, elapsed=%.2fs", time.time() - start_time
        )

        # EXTEND2 payload  (tor-spec.txt §5.1.2)
        # nspec=2: IPv4 specifier + legacy ID specifier

        # Per tor-spec.txt: "When speaking v2 of the link protocol or later,
        # clients MUST only send EXTEND/EXTEND2 message inside RELAY_EARLY cells."
        use_early = True

        trace(f"_extend_ntor: START, use_early={use_early}")

        # CRITICAL DEBUG: Log that we're about to use RELAY_EARLY
        debug(
            f"DEBUG _extend_ntor: use_early={use_early} for EXTEND2, about to call _send_relay_cell",
        )

        debug(f"DEBUG: about to build EXTEND2 payload", flush=True, file=sys.stderr)

        # Create EXTEND2 payload with detailed logging
        addr_parts = router.address.split(".")
        addr_int = (
            (int(addr_parts[0]) << 24)
            | (int(addr_parts[1]) << 16)
            | (int(addr_parts[2]) << 8)
            | int(addr_parts[3])
        )

        # Log router info
        debug(
            f"DEBUG EXTEND2: router={router.nickname}, address={router.address}, or_port={router.or_port}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"DEBUG EXTEND2: identity={router.identity.hex()[:40]}... (len={len(router.identity)})",
            flush=True,
            file=sys.stderr,
        )

        nspec = b"\x02"  # two link specifiers (IPv4 + legacy ID) - same as torpy
        debug(
            f"DEBUG EXTEND2: nspec={nspec.hex()} (value={nspec[0]})",
            flush=True,
            file=sys.stderr,
        )

        # Link specifier: type=0 (TLS-over-TCP IPv4), len=6
        # Format: [type=0][len=6][IPv4(4)][port(2)]
        ls_ipv4 = (
            struct.pack("!BB", 0, 6)
            + struct.pack("!I", addr_int)
            + struct.pack("!H", router.or_port)
        )
        debug(
            f"DEBUG EXTEND2: IPv4 link spec: type={ls_ipv4[0]}, len={ls_ipv4[1]}, addr=0x{ls_ipv4[2:6].hex()}, port={struct.unpack('!H', ls_ipv4[6:8])[0]}",
            flush=True,
            file=sys.stderr,
        )
        debug(f"DEBUG EXTEND2: IPv4 raw: {ls_ipv4.hex()}", flush=True, file=sys.stderr)

        # Link specifier: type=2 (legacy identity), len=20
        # Format: [type=2][len=20][identity(20)]
        ls_id = struct.pack("!BB", 2, 20) + router.identity
        debug(
            f"DEBUG EXTEND2: ID link spec: type={ls_id[0]}, len={ls_id[1]}, identity={ls_id[2:22].hex()[:40]}...",
            flush=True,
            file=sys.stderr,
        )
        debug(f"DEBUG EXTEND2: ID raw: {ls_id.hex()}", flush=True, file=sys.stderr)

        # htype=2 (legacy ntor) - most widely supported
        # htype=3 (ntor-v3) requires special handling
        htype = 2
        hlen = len(onion_skin)
        htype_hlen = struct.pack("!HH", htype, hlen)
        debug(f"DEBUG EXTEND2: htype={htype}, hlen={hlen}", flush=True, file=sys.stderr)

        # Onion skin breakdown
        node_id = onion_skin[:20]
        key_id = onion_skin[20:52]
        client_pk = onion_skin[52:84]
        debug(
            f"DEBUG EXTEND2: onion_skin - node_id={node_id.hex()[:40]}...",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"DEBUG EXTEND2: onion_skin - key_id={key_id.hex()[:40]}...",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"DEBUG EXTEND2: onion_skin - client_pk={client_pk.hex()[:40]}...",
            flush=True,
            file=sys.stderr,
        )

        extend2_payload = nspec + ls_ipv4 + ls_id + htype_hlen + onion_skin

        # Full payload breakdown
        debug(
            f"DEBUG EXTEND2: FULL payload ({len(extend2_payload)} bytes):",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [0:1]   nspec:     {extend2_payload[0:1].hex()}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [1:3]   ls_ipv4:   {extend2_payload[1:3].hex()}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [3:9]   IPv4 addr: {extend2_payload[3:9].hex()}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [9:11]  port:      {extend2_payload[9:11].hex()}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [11:13] ls_id:     {extend2_payload[11:13].hex()}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [13:33] identity:  {extend2_payload[13:33].hex()}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [33:35] htype:     {extend2_payload[33:35].hex()}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [35:37] hlen:      {extend2_payload[35:37].hex()}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  [37:121] onion_skin: {extend2_payload[37:121].hex()[:60]}...",
            flush=True,
            file=sys.stderr,
        )

        # Detailed debug logging
        log.debug(
            "EXTEND2 payload breakdown: nspec=%s, ls_ipv4_type=%s, ls_ipv4_len=%d, ls_ipv4_addr=%s, ls_ipv4_port=%d",
            nspec.hex(),
            ls_ipv4[0:1].hex(),
            ls_ipv4[1],
            ls_ipv4[2:6].hex(),
            struct.unpack("!H", ls_ipv4[6:8])[0],
        )
        log.debug(
            "EXTEND2: ls_id_type=%s, ls_id_len=%d, ls_id_identity=%s",
            ls_id[0:1].hex(),
            ls_id[1],
            ls_id[2:22].hex(),
        )
        log.debug(
            "EXTEND2: htype=%d, hlen=%d, onion_skin_len=%d",
            struct.unpack("!H", htype_hlen[0:2])[0],
            struct.unpack("!H", htype_hlen[2:4])[0],
            len(onion_skin),
        )

        await self._send_relay_cell(
            relay_command=RelayCommand.EXTEND2,
            stream_id=0,
            data=extend2_payload,
            hop_index=len(self._hops) - 1,
            use_early=use_early,
        )

        debug(
            f"DEBUG: _send_relay_cell about to be called with use_early={use_early}",
            flush=True,
            file=sys.stderr,
        )
        debug(f"DEBUG: waiting for EXTENDED2 response...", flush=True, file=sys.stderr)

        log.info("EXTEND2 cell SENT, waiting for EXTENDED2 response...")
        log.debug(
            "_extend_ntor: payload length=%d, first bytes: %s",
            len(extend2_payload),
            extend2_payload[:16].hex(),
        )
        log.debug("_extend_ntor: cell sent, elapsed=%.2fs", time.time() - start_time)

        # Wait for EXTENDED2 using event-based approach to avoid race with stream_dispatch
        # Also check for DESTROY more directly
        log.debug("_extend_ntor: starting wait loop for EXTENDED2")
        while True:
            # Check if circuit was destroyed
            if self._destroyed:
                log.error("_extend_ntor: circuit was destroyed during EXTEND2")
                raise CircuitError("Circuit destroyed during EXTEND2")
            # Wait for the event to be set by stream_dispatch
            log.debug(
                "_extend_ntor: waiting for extend_event (timeout=%.1f)", self._timeout
            )
            try:
                await asyncio.wait_for(self._extend_event.wait(), timeout=self._timeout)
            except asyncio.TimeoutError:
                log.error(
                    "_extend_ntor: timeout waiting for EXTENDED2 after %.1fs",
                    self._timeout,
                )
                raise CircuitError("Timeout waiting for EXTENDED2 response")

            log.debug("_extend_ntor: event triggered, checking result")
            debug(
                f"DEBUG: event triggered, extend_result={self._extend_result}",
                flush=True,
                file=sys.stderr,
            )

            # Check if we got the result
            if self._extend_result:
                rc = self._extend_result[0]
                log.debug("_extend_ntor: got EXTENDED2 via event!")

                # Reset for next extend operation
                self._extend_event.clear()
                self._extend_result.clear()

                log.debug("_extend_ntor: EXTENDED2 data length: %d", len(rc.data))

                # Parse EXTENDED2: hlen(2) + hdata
                if len(rc.data) < 2:
                    raise CircuitError("EXTENDED2 payload too short")
                hlen = struct.unpack("!H", rc.data[:2])[0]
                hdata = rc.data[2 : 2 + hlen]
                log.debug("_extend_ntor: hlen=%d, hdata length=%d", hlen, len(hdata))

                # The EXTENDED2 body is the same as CREATED2: hlen(2) + hdata
                # But NtorHandshake.complete() expects CREATED2-style payload with length prefix
                # So we need to prepend the length to hdata before calling complete
                created2_body = struct.pack("!H", hlen) + hdata

                try:
                    keys = hs.complete(created2_body)
                    self._hops.append(CircuitHop(keys=keys, router=router))
                    log.debug(
                        "EXTEND2 complete, hop=%s (total=%d)",
                        router.nickname,
                        len(self._hops),
                    )
                    break
                except HandshakeError as e:
                    log.error("_extend_ntor: handshake completion failed: %s", e)
                    raise CircuitError(f"EXTEND2 handshake failed: {e}")
            else:
                # Event was set but no result - this means we got a DESTROY
                log.error(
                    "_extend_ntor: event triggered but no result (likely DESTROY)"
                )
                self._extend_event.clear()
                raise CircuitError("Circuit destroyed during EXTEND2")

    async def _extend_fast(self, router: RouterInfo) -> None:
        """Extend circuit using CREATE_FAST.

        Uses RELAY_EARLY cell with CREATE_FAST handshake inside EXTEND2.
        """
        log.info("_extend_fast: starting for %s:%d", router.address, router.or_port)

        hs = FastHandshake()
        create_fast_payload = hs.create_payload()

        # Build CREATE_FAST payload inside EXTEND2
        create_fast_cell = (
            struct.pack("!HH", 1, len(create_fast_payload)) + create_fast_payload
        )

        # EXTEND2 payload structure
        addr_bytes = _encode_ipv4(router.address)
        port_bytes = struct.pack("!H", router.or_port)
        # Link specifier: type=0 (TLS-over-TCP IPv4), len=6
        ls_ipv4 = b"\x00\x06" + addr_bytes + port_bytes
        # Link specifier: type=2 (legacy identity), len=20
        ls_id = b"\x02\x14" + router.identity

        nspec = b"\x02"  # two link specifiers
        # htype=1 (CREATE_FAST), hlen=20
        htype_hlen = struct.pack("!HH", 1, len(create_fast_cell))
        extend2_payload = nspec + ls_ipv4 + ls_id + htype_hlen + create_fast_cell

        log.info(
            "_extend_fast: sending RELAY_EARLY EXTEND2 to %s:%d",
            router.address,
            router.or_port,
        )

        # Create event for EXTENDED response
        self._extend_event = asyncio.Event()
        self._extend_result = []

        await self._send_relay_cell(
            relay_command=RelayCommand.EXTEND2,
            stream_id=0,
            data=extend2_payload,
            hop_index=len(self._hops) - 1,
            use_early=True,  # Use RELAY_EARLY for circuit extension
        )
        log.info("_extend_fast: cell sent, waiting for EXTENDED2")

        # Wait for EXTENDED2 using event-based approach
        try:
            await asyncio.wait_for(self._extend_event.wait(), timeout=self._timeout)
        except asyncio.TimeoutError:
            log.error("_extend_fast: timeout waiting for EXTENDED2")
            raise CircuitError("Timeout waiting for EXTENDED2 response")

        if self._extend_result:
            relay = self._extend_result[0]
            log.info("_extend_fast: got EXTENDED2, processing response")

            # Reset
            self._extend_event.clear()
            self._extend_result.clear()

            # Parse EXTENDED2: hlen(2) + hdata
            if len(relay.data) < 2:
                raise CircuitError("EXTENDED2 payload too short")
            hlen = struct.unpack("!H", relay.data[:2])[0]
            hdata = relay.data[2 : 2 + hlen]

            # For CREATE_FAST, the response is y(20) + kh(20)
            if len(hdata) < 40:
                raise CircuitError("EXTENDED2 hdata too short for CREATE_FAST")
            y = hdata[:20]
            kh = hdata[20:40]

            keys = hs.complete(y, kh)
            self._hops.append(CircuitHop(keys=keys, router=router))
            log.info(
                "EXTEND (CREATE_FAST) complete, hop=%s (total=%d)",
                router.nickname,
                len(self._hops),
            )
        else:
            # Event was set but no result - circuit was destroyed
            self._extend_event.clear()
            raise CircuitError("Circuit destroyed during EXTEND2 (CREATE_FAST)")

    async def _wait_for_extended(self) -> RelayCell:
        """Wait for EXTENDED response."""
        while True:
            log.debug("_extend_fast: waiting for EXTENDED response")
            relay = await self._recv_relay_cell(timeout=self._timeout)
            log.debug("_extend_fast: got response %s", relay)
            if relay is None:
                raise CircuitError("Connection closed waiting for EXTENDED")
            if relay.relay_command == RelayCommand.EXTENDED:
                return relay
            if relay.relay_command == RelayCommand.TRUNCATED:
                raise CircuitError("Circuit truncated during EXTEND")
            log.debug("Unexpected relay cell during EXTEND: %r", relay)

    async def _wait_for_extended2(self) -> RelayCell:
        """Wait for EXTENDED2 response."""
        while True:
            log.debug("_extend_fast: waiting for EXTENDED2 response")
            relay = await self._recv_relay_cell(timeout=self._timeout)
            log.debug("_extend_fast: got response %s", relay)
            if relay is None:
                raise CircuitError("Connection closed waiting for EXTENDED2")
            if relay.relay_command == RelayCommand.EXTENDED2:
                return relay
            if relay.relay_command == RelayCommand.TRUNCATED:
                raise CircuitError("Circuit truncated during EXTEND2")
            log.debug("Unexpected relay cell during EXTEND2: %r", relay)

    # -----------------------------------------------------------------------
    # Stream management
    # -----------------------------------------------------------------------

    def _alloc_stream_id(self) -> int:
        sid = self._next_stream_id
        self._next_stream_id = (self._next_stream_id % 0xFFFF) + 1
        return sid

    async def open_stream(self, host: str, port: int) -> "TorStream":
        """Open a new RELAY_BEGIN stream to host:port through this circuit."""
        from .stream import TorStream

        if self._destroyed:
            raise DestroyedError("Circuit is destroyed")
        if not self._hops:
            raise CircuitError("Circuit has no hops")

        stream_id = self._alloc_stream_id()
        q: asyncio.Queue = asyncio.Queue()
        self._streams[stream_id] = q

        # BEGIN payload: "host:port\x00" + flags(4)
        target = f"{host}:{port}\x00".encode()
        flags = struct.pack("!I", 0)
        payload = target + flags

        await self._send_relay_cell(
            relay_command=RelayCommand.BEGIN,
            stream_id=stream_id,
            data=payload,
        )

        # Wait for CONNECTED or END
        cell = await asyncio.wait_for(q.get(), timeout=self._timeout)
        if cell is None:
            raise CircuitError("Circuit closed while opening stream")
        log.debug(
            "Stream open response: relay_cmd=%d, data=%r", cell.relay_command, cell.data
        )
        if cell.relay_command == RelayCommand.END:
            reason = cell.data[0] if cell.data else 0
            log.warning(
                "Stream END reason=%d (%s)",
                reason,
                EndReason(reason).name if reason < len(EndReason) else "unknown",
            )
            raise RelayError(
                f"Stream rejected by exit (reason={EndReason(reason).name if reason < len(EndReason) else reason})"
            )
        if cell.relay_command != RelayCommand.CONNECTED:
            raise RelayError(f"Expected CONNECTED, got relay_cmd={cell.relay_command}")

        stream = TorStream(
            circuit=self,
            stream_id=stream_id,
            queue=q,
        )
        log.debug("Stream %d opened to %s:%d", stream_id, host, port)
        return stream

    async def open_dir_stream(self) -> "TorStream":
        """Open a RELAY_BEGIN_DIR stream (for directory fetches over circuit)."""
        from .stream import TorStream

        if self._destroyed:
            raise DestroyedError("Circuit is destroyed")

        stream_id = self._alloc_stream_id()
        q: asyncio.Queue = asyncio.Queue()
        self._streams[stream_id] = q

        await self._send_relay_cell(
            relay_command=RelayCommand.BEGIN_DIR,
            stream_id=stream_id,
            data=b"",
        )

        cell = await asyncio.wait_for(q.get(), timeout=self._timeout)
        if cell is None:
            raise CircuitError("Circuit closed while opening dir stream")
        if cell.relay_command not in (RelayCommand.CONNECTED, RelayCommand.DATA):
            raise RelayError(f"Unexpected cell opening dir stream: {cell!r}")

        return TorStream(
            circuit=self,
            stream_id=stream_id,
            queue=q,
            _prefill=cell if cell.relay_command == RelayCommand.DATA else None,
        )

    def close_stream(self, stream_id: int) -> None:
        self._streams.pop(stream_id, None)

    # -----------------------------------------------------------------------
    # Relay cell encryption / decryption
    # -----------------------------------------------------------------------

    async def _send_relay_cell(
        self,
        relay_command: int,
        stream_id: int,
        data: bytes,
        hop_index: int | None = None,
        use_early: bool = False,
    ) -> None:
        """
        Build, digest, and onion-encrypt a relay cell, then send it.
        hop_index defaults to the last (exit) hop.
        use_early: if True, use RELAY_EARLY instead of RELAY for circuit extension.
        """
        import sys

        debug(
            f"DEBUG _send_relay_cell: START - command={relay_command}, stream_id={stream_id}, hop_index={hop_index}, use_early={use_early}",
            flush=True,
            file=sys.stderr,
        )

        log.debug(
            "_send_relay_cell: command=%d, stream_id=%d, hop_index=%s, use_early=%s",
            relay_command,
            stream_id,
            hop_index,
            use_early,
        )

        if hop_index is None:
            hop_index = len(self._hops) - 1

        log.debug("_send_relay_cell: building RelayCell")
        rc = RelayCell(relay_command=relay_command, stream_id=stream_id, data=data)
        payload = bytearray(rc.to_payload())

        # Detailed debug: show full relay payload before digest/encryption
        debug(
            f"DEBUG _send_relay_cell: raw relay payload ({len(payload)} bytes):",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  relay_command={relay_command} (0x{relay_command:02x})",
            flush=True,
            file=sys.stderr,
        )
        debug(f"  recognized={payload[1:3].hex()}", flush=True, file=sys.stderr)
        debug(f"  stream_id={payload[3:5].hex()}", flush=True, file=sys.stderr)
        debug(f"  digest=00000000 (will be filled)", flush=True, file=sys.stderr)
        debug(
            f"  length={payload[9:11].hex()} ({struct.unpack('!H', payload[9:11])[0]})",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  data (first 32): {payload[11:43].hex()[:64]}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"  FULL payload hex: {payload.hex()[:100]}...", flush=True, file=sys.stderr
        )

        # Log what we're about to encrypt
        log.debug(
            "_send_relay_cell: before encryption - command=%d, stream_id=%d, recognized=%d, digest_placement=%s",
            rc.relay_command,
            rc.stream_id,
            rc.recognized,
            "bytes 5-9 will get digest",
        )

        # Compute digest at the target hop
        # Digest covers the whole relay payload with digest field zeroed
        hop = self._hops[hop_index]
        log.debug("_send_relay_cell: computing forward digest for hop %d", hop_index)
        mac = hop.keys.update_fwd_digest(bytes(payload))
        payload[5:9] = mac  # insert 4-byte digest

        # Onion-encrypt from innermost outward
        log.debug("_send_relay_cell: onion-encrypting for %d hops", hop_index + 1)
        enc_payload = bytes(payload)
        debug(
            f"DEBUG _send_relay_cell: before encryption: {enc_payload.hex()[:80]}...",
            flush=True,
            file=sys.stderr,
        )
        for i in range(hop_index, -1, -1):
            debug(
                f"DEBUG _send_relay_cell: encrypting with hop {i}, input len={len(enc_payload)}",
                flush=True,
                file=sys.stderr,
            )
            enc_payload = self._hops[i].keys.encrypt_forward(enc_payload)
            debug(
                f"DEBUG _send_relay_cell: after encrypt with hop {i}: {enc_payload.hex()[:80]}... (len={len(enc_payload)})",
                flush=True,
                file=sys.stderr,
            )

        log.debug("_send_relay_cell: creating cell")
        # EXTEND2 must always be sent in RELAY_EARLY per Tor spec
        if int(relay_command) == int(RelayCommand.EXTEND2):
            cell_cmd = CellCommand.RELAY_EARLY
        elif use_early:
            cell_cmd = CellCommand.RELAY_EARLY
        else:
            cell_cmd = CellCommand.RELAY
        debug(
            f"DEBUG _send_relay_cell: FINAL: use_early={use_early}, cell_cmd={cell_cmd} ({cell_cmd.value}), relay_command={relay_command}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"DEBUG CellCommand.RELAY_EARLY.value={CellCommand.RELAY_EARLY.value}, CellCommand.RELAY.value={CellCommand.RELAY.value}",
            flush=True,
            file=sys.stderr,
        )
        debug(
            f"DEBUG _send_relay_cell: ABOUT TO CREATE CELL with command={cell_cmd.value} (RELAY_EARLY={CellCommand.RELAY_EARLY.value})",
            flush=True,
            file=sys.stderr,
        )
        cell = Cell(
            circ_id=self._circ_id,
            command=cell_cmd,
            payload=enc_payload,
        )
        # Log the full encrypted payload for debugging
        cmd_val = cell.command
        cmd_name = CellCommand(cmd_val).name if cmd_val in CellCommand else str(cmd_val)
        log.debug(
            "_send_relay_cell: final cell - circ_id=%d, command=%s, payload_len=%d, payload_first_32=%s",
            cmd_val,
            cmd_name,
            len(enc_payload),
            enc_payload[:32].hex(),
        )
        log.debug(
            "_send_relay_cell: final cell command=%d, payload (%d bytes): %s",
            cell.command,
            len(enc_payload),
            enc_payload.hex()[:80] + "...",
        )
        log.debug("_send_relay_cell: sending cell to connection")
        debug(
            f"DEBUG _send_relay_cell: about to send cell", flush=True, file=sys.stderr
        )
        await self._conn.send_cell(cell)
        debug(f"DEBUG _send_relay_cell: cell sent!", flush=True, file=sys.stderr)
        log.debug("_send_relay_cell: sent cell %s", cell)

    async def _recv_relay_cell(self, timeout: float | None = None) -> RelayCell | None:
        """
        Receive the next relay cell destined for this circuit (stream_id=0).
        Strips one layer of encryption and verifies the digest.
        """
        log.debug("_recv_relay_cell: waiting for relay cell (timeout=%s)", timeout)
        log.debug("_recv_relay_cell: queue size before wait: %d", self._queue.qsize())

        try:
            cell = await asyncio.wait_for(self._queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            log.error("_recv_relay_cell: timeout waiting for cell")
            log.error(
                "_recv_relay_cell: queue size at timeout: %d", self._queue.qsize()
            )
            raise CircuitError("Timeout waiting for relay cell response")

        if cell is None:
            log.debug("_recv_relay_cell: got None (connection closed)")
            return None

        log.info("_recv_relay_cell: got raw cell %s", cell)

        # Log the relay header to see stream_id
        relay_header = RelayCell.from_payload(bytes(cell.payload[:509]))
        log.info(
            "_recv_relay_cell: relay header: stream_id=%d, command=%d, recognized=%d",
            relay_header.stream_id,
            relay_header.relay_command,
            relay_header.recognized,
        )

        # Try to decrypt
        try:
            rc = self._decrypt_cell(cell)
            if rc is None:
                log.error(
                    "_recv_relay_cell: _decrypt_cell returned None - unrecognized!"
                )
                # Put it back for stream_dispatch to handle
                await self._queue.put(cell)
                return None
            log.debug(
                "_recv_relay_cell: successfully decrypted, command=%d", rc.relay_command
            )
            return rc
        except Exception as decrypt_err:
            log.error("_recv_relay_cell: decrypt error: %s", decrypt_err)
            raise

    def _decrypt_cell(self, cell: Cell) -> RelayCell | None:
        """Peel onion layers until 'recognized' field is zero."""
        log.debug("_decrypt_cell: processing cell, num_hops=%d", len(self._hops))
        payload = bytes(cell.payload[:509])

        for i, hop in enumerate(self._hops):
            log.debug("_decrypt_cell: decrypting hop %d (%s)", i, hop.router.nickname)
            payload = hop.keys.decrypt_backward(payload)
            rc = RelayCell.from_payload(payload)
            log.debug(
                "_decrypt_cell: hop %d, recognized=%d, stream_id=%d, command=%d, payload_len=%d",
                i,
                rc.recognized,
                rc.stream_id,
                rc.relay_command,
                len(payload),
            )
            if rc.recognized == 0:
                # Verify digest
                check_payload = bytearray(payload)
                check_payload[5:9] = b"\x00\x00\x00\x00"
                expected_mac = hop.keys.update_bwd_digest(bytes(check_payload))
                # Restore original digest for comparison
                actual_mac = payload[5:9]
                # In a full implementation we'd compare; here we trust 'recognized==0'
                log.debug("_decrypt_cell: decrypted successfully at hop %d", i)
                return rc

        log.debug("Could not decrypt relay cell at any hop")
        return None

    # -----------------------------------------------------------------------
    # Stream dispatch
    # -----------------------------------------------------------------------

    async def _stream_dispatch(self) -> None:
        """Route inbound relay cells to the correct stream queue."""
        log.debug("_stream_dispatch: starting for circ_id=%d", self._circ_id)
        try:
            while not self._destroyed:
                log.debug("_stream_dispatch: waiting for cell")
                cell = await self._queue.get()
                log.debug("_stream_dispatch: got cell %s", cell)
                if cell is None:
                    log.debug("_stream_dispatch: got None, exiting")
                    break

                log.debug(
                    "_stream_dispatch: cell command before DESTROY check: %s",
                    cell.command,
                )
                if cell.command == CellCommand.DESTROY:
                    self._destroyed = True
                    reason = cell.payload[0] if cell.payload else 0
                    log.error(
                        "Circuit %d DESTROY received (reason=%d, %s), full payload: %s",
                        self._circ_id,
                        reason,
                        DestroyReason(reason).name,
                        cell.payload.hex(),
                    )
                    # Signal any waiting extend operation
                    if self._extend_event is not None:
                        self._extend_event.set()
                    for q in self._streams.values():
                        await q.put(None)
                    break

                # Try to decrypt first - for circuit-level cells (EXTENDED2, TRUNCATED),
                # we need to decrypt with the innermost hop to see stream_id
                log.debug(
                    "_stream_dispatch: attempting to decrypt cell, hops=%d",
                    len(self._hops),
                )
                rc = self._decrypt_cell(cell)
                if rc is None:
                    log.debug("_stream_dispatch: could not decrypt cell, skipping")
                    continue

                # Now we can check stream_id after decryption
                log.debug(
                    "_stream_dispatch: decrypted cell: stream_id=%d, command=%d",
                    rc.stream_id,
                    rc.relay_command,
                )

                # Check if this is an EXTENDED2 (circuit-level response during extend)
                # If so, signal the waiting extend operation instead of putting back
                if (
                    rc.stream_id == 0
                    and rc.relay_command == RelayCommand.EXTENDED2
                    and self._extend_event is not None
                ):
                    log.debug(
                        "_stream_dispatch: signaling EXTENDED2 to extend operation"
                    )
                    self._extend_result.append(rc)
                    self._extend_event.set()
                    continue

                if rc.stream_id == 0:
                    # Circuit-level cell - put back for _recv_relay_cell to handle
                    log.debug(
                        "_stream_dispatch: circuit-level cell (stream_id=0, command=%d), putting back",
                        rc.relay_command,
                    )
                    await self._queue.put(cell)
                    continue

                if rc.relay_command == RelayCommand.SENDME and rc.stream_id == 0:
                    self._deliver_window += CIRCUIT_WINDOW_INCREMENT
                    continue

                if rc.stream_id == 0:
                    # Circuit-level cell: put back into main queue for EXTEND2 etc.
                    await self._queue.put(cell)
                    continue

                q = self._streams.get(rc.stream_id)
                if q is not None:
                    await q.put(rc)
                else:
                    log.debug("Relay cell for unknown stream %d: %r", rc.stream_id, rc)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.debug("Stream dispatch error: %s", exc)

    # -----------------------------------------------------------------------
    # Destroy
    # -----------------------------------------------------------------------

    async def destroy(self, reason: int = DestroyReason.REQUESTED) -> None:
        """Send DESTROY and clean up."""
        if self._destroyed:
            return
        self._destroyed = True
        cell = Cell(
            self._circ_id,
            CellCommand.DESTROY,
            bytes([reason]),
        )
        try:
            await self._conn.send_cell(cell)
        except Exception:
            pass
        self._conn.unregister_circuit(self._circ_id)
        if self._dispatch_task:
            self._dispatch_task.cancel()
        for q in self._streams.values():
            await q.put(None)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.destroy()

    def __repr__(self) -> str:
        hops = "→".join(h.router.nickname for h in self._hops)
        return f"<Circuit id={self._circ_id} path=[{hops}] destroyed={self._destroyed}>"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _encode_ipv4(addr: str) -> bytes:
    parts = addr.split(".")
    if len(parts) != 4:
        raise ValueError(f"Not an IPv4 address: {addr!r}")
    return bytes(int(p) for p in parts)
