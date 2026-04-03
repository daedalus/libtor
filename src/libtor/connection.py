"""
OR (onion router) connection.

Handles:
  - TLS connection to a Tor relay
  - Link protocol negotiation (VERSIONS cells)
  - NETINFO exchange
  - Cell send/receive multiplexed by circuit ID
  - CERTS cell (stored but not verified in this implementation)
"""

import asyncio
import logging
import ssl
import struct
import time

from .cells import PAYLOAD_LEN, Cell, CellCommand
from .exceptions import TorError

log = logging.getLogger(__name__)

# We support link protocols 3, 4, 5.
SUPPORTED_LINK_PROTOCOLS = [5, 4, 3]


class ORConnection:
    """
    Async connection to a single Tor relay (OR).

    Cells are dispatched to registered circuit handlers by circuit ID.
    """

    def __init__(self, host: str, port: int, timeout: float = 30.0):
        self.host = host
        self.port = port
        self.timeout = timeout

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._link_version: int = 4

        # Map circ_id → asyncio.Queue  (cells destined for that circuit)
        self._circuit_queues: dict[int, asyncio.Queue] = {}
        self._dispatch_task: asyncio.Task | None = None
        self._closed = False

        self._next_circ_id = (
            0x80000001  # Start at 0x80000001 so first circuit gets 0x80000001
        )

    # -----------------------------------------------------------------------
    # Connection lifecycle
    # -----------------------------------------------------------------------

    async def connect(self) -> None:
        """Establish TLS connection and complete link-protocol handshake."""
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        # Require TLS 1.2+ (Tor spec §2)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2

        log.debug("Connecting to OR %s:%d", self.host, self.port)
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.host, self.port, ssl=ssl_ctx),
            timeout=self.timeout,
        )
        log.debug("TLS connected to %s:%d", self.host, self.port)

        await self._link_handshake()

        # Start background dispatcher
        self._dispatch_task = asyncio.create_task(
            self._dispatch_loop(), name=f"dispatch-{self.host}"
        )

    async def close(self) -> None:
        """Close the connection and clean up."""
        if self._closed:
            return
        self._closed = True
        if self._dispatch_task:
            self._dispatch_task.cancel()
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
        # Wake up any waiting circuits
        for q in self._circuit_queues.values():
            await q.put(None)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *_):
        await self.close()

    # -----------------------------------------------------------------------
    # Link protocol negotiation
    # -----------------------------------------------------------------------

    async def _link_handshake(self) -> None:
        """Negotiate link protocol version, exchange CERTS and NETINFO."""
        # Send VERSIONS cell (circ_id=0, variable length)
        versions_payload = struct.pack(
            "!" + "H" * len(SUPPORTED_LINK_PROTOCOLS),
            *SUPPORTED_LINK_PROTOCOLS,
        )
        await self._send_raw(
            Cell(0, CellCommand.VERSIONS, versions_payload), link_version=3
        )

        # Read cells until we've received VERSIONS
        got_versions = False
        deadline = asyncio.get_event_loop().time() + self.timeout

        while not got_versions:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TorError("Link handshake timed out waiting for VERSIONS")
            cell = await asyncio.wait_for(
                self._read_cell_raw(link_version=3),
                timeout=remaining,
            )
            if cell is None:
                raise TorError("Connection closed during link handshake")

            if cell.command == CellCommand.VERSIONS:
                got_versions = True
                self._link_version = self._negotiate_version(cell.payload)
                log.debug("Negotiated link protocol v%d", self._link_version)
                # Send NETINFO after receiving VERSIONS
                await self._send_netinfo()
            elif cell.command == CellCommand.NETINFO:
                # Relay sent NETINFO first, just acknowledge with our NETINFO
                await self._send_netinfo()
            elif cell.command == CellCommand.CERTS:
                pass  # Accept without verification (transport-level TLS is enough)
            elif cell.command == CellCommand.AUTH_CHALLENGE:
                pass  # Clients don't need to respond
            elif cell.command in (CellCommand.VPADDING, CellCommand.PADDING):
                pass  # Ignore padding
            else:
                log.debug("Unexpected cell during handshake: %s", cell)

    def _negotiate_version(self, payload: bytes) -> int:
        """Choose highest mutually supported link protocol version."""
        peer_versions = set()
        for i in range(0, len(payload) - 1, 2):
            v = struct.unpack("!H", payload[i : i + 2])[0]
            peer_versions.add(v)
        for v in SUPPORTED_LINK_PROTOCOLS:
            if v in peer_versions:
                return v
        raise TorError(
            f"No supported link protocol version in peer set: {peer_versions}"
        )

    async def _send_netinfo(self) -> None:
        """Send a NETINFO cell."""
        now = int(time.time())
        # Other address: our apparent address (we use 0.0.0.0 as placeholder)
        other_addr = b"\x04\x04\x00\x00\x00\x00"  # type=IPv4, len=4, 0.0.0.0
        # My addresses: none declared
        my_addrs = b"\x00"  # num=0
        payload = struct.pack("!I", now) + other_addr + my_addrs
        await self.send_cell(Cell(0, CellCommand.NETINFO, payload))

    # -----------------------------------------------------------------------
    # Cell I/O
    # -----------------------------------------------------------------------

    async def send_cell(self, cell: Cell) -> None:
        """Encode and write a cell."""
        data = cell.to_bytes(link_version=self._link_version)
        log.debug(
            "send_cell: sending %s (payload %d bytes: %s)",
            cell,
            len(data),
            data.hex()[:40] + "..." if len(data) > 40 else data.hex(),
        )
        self._writer.write(data)
        await self._writer.drain()

    async def _send_raw(self, cell: Cell, link_version: int) -> None:
        data = cell.to_bytes(link_version=link_version)
        self._writer.write(data)
        await self._writer.drain()

    async def _read_cell_raw(self, link_version: int) -> Cell | None:
        """Read exactly one cell from the stream."""
        if link_version >= 4:
            header_len = 5  # circ_id(4) + cmd(1)
        else:
            header_len = 3  # circ_id(2) + cmd(1)

        header = await self._reader.readexactly(header_len)

        if link_version >= 4:
            circ_id = struct.unpack("!I", header[:4])[0]
            command = header[4]
        else:
            circ_id = struct.unpack("!H", header[:2])[0]
            command = header[2]

        if command == CellCommand.VERSIONS or command >= 128:
            # Variable-length: read 2-byte length then body
            length_bytes = await self._reader.readexactly(2)
            length = struct.unpack("!H", length_bytes)[0]
            payload = await self._reader.readexactly(length)
        else:
            payload = await self._reader.readexactly(PAYLOAD_LEN)

        return Cell(circ_id=circ_id, command=command, payload=payload)

    # -----------------------------------------------------------------------
    # Dispatch loop
    # -----------------------------------------------------------------------

    async def _dispatch_loop(self) -> None:
        """Read cells forever and dispatch by circuit ID."""
        log.debug("_dispatch_loop: starting")
        total_cells = 0
        try:
            while not self._closed:
                log.debug("_dispatch_loop: reading cell")
                cell = await self._read_cell_raw(self._link_version)
                if cell is None:
                    log.debug("_dispatch_loop: got None, exiting")
                    break

                total_cells += 1
                log.debug(
                    "_dispatch_loop: got cell circ_id=%d cmd=%s (total: %d)",
                    cell.circ_id,
                    cell.command,
                    total_cells,
                )
                if cell.command in (CellCommand.PADDING, CellCommand.VPADDING):
                    continue  # Global padding – ignore

                q = self._circuit_queues.get(cell.circ_id)
                if q is not None:
                    log.debug(
                        "_dispatch_loop: putting cell to queue for circ_id=%d (queue size before: %d)",
                        cell.circ_id,
                        q.qsize(),
                    )
                    await q.put(cell)
                    log.debug(
                        "_dispatch_loop: put complete, queue size now: %d", q.qsize()
                    )
                else:
                    log.debug("Unhandled cell for circ_id=%d: %r", cell.circ_id, cell)
        except asyncio.CancelledError:
            log.debug("_dispatch_loop: cancelled")
            pass
        except Exception as exc:
            log.debug("Dispatch loop error: %s", exc)
        finally:
            log.debug(
                "_dispatch_loop: cleaning up, total cells processed: %d", total_cells
            )
            # Signal all waiting circuits
            for q in self._circuit_queues.values():
                await q.put(None)

    # -----------------------------------------------------------------------
    # Circuit registration
    # -----------------------------------------------------------------------

    def alloc_circuit_id(self) -> int:
        """Allocate a fresh circuit ID (client-initiated: high bit set)."""
        cid = self._next_circ_id
        self._next_circ_id += 1
        if self._next_circ_id >= 0xFFFFFFFF:
            self._next_circ_id = 0x80000000
        return cid

    def register_circuit(self, circ_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._circuit_queues[circ_id] = q
        return q

    def unregister_circuit(self, circ_id: int) -> None:
        self._circuit_queues.pop(circ_id, None)

    async def recv_cell(
        self, circ_id: int, timeout: float | None = None
    ) -> Cell | None:
        """
        Wait for the next cell on a given circuit.
        Returns None if the connection was closed.
        """
        q = self._circuit_queues.get(circ_id)
        if q is None:
            raise TorError(f"Circuit {circ_id} not registered")
        if timeout is not None:
            return await asyncio.wait_for(q.get(), timeout=timeout)
        return await q.get()
