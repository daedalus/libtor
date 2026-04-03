"""
TorStream – bidirectional byte stream over a Tor circuit.

Implements RELAY_DATA send, RELAY_END close, and stream-level SENDME
flow control (tor-spec.txt §7.4).
"""

import asyncio
import logging
from typing import TYPE_CHECKING

from .cells import EndReason, RelayCell, RelayCommand
from .exceptions import DestroyedError, StreamError

if TYPE_CHECKING:
    from .circuit import Circuit

log = logging.getLogger(__name__)

MAX_DATA_LEN = 498  # Max bytes per RELAY_DATA cell
STREAM_WINDOW = 500
SENDME_THRESHOLD = 450  # Send SENDME when window drops to this


class TorStream:
    """
    A single TCP-like stream multiplexed over a Tor circuit.

    Do not instantiate directly; use ``Circuit.open_stream()``.
    """

    def __init__(
        self,
        circuit: "Circuit",
        stream_id: int,
        queue: asyncio.Queue,
        _prefill: RelayCell | None = None,
    ):
        self._circuit = circuit
        self._stream_id = stream_id
        self._queue = queue
        self._closed = False
        self._recv_buf = bytearray()
        self._deliver_window = STREAM_WINDOW
        self._package_window = STREAM_WINDOW

        if _prefill is not None:
            self._recv_buf.extend(_prefill.data)

    # -----------------------------------------------------------------------
    # Send
    # -----------------------------------------------------------------------

    async def send(self, data: bytes) -> int:
        """
        Send data over the stream.
        Splits into MAX_DATA_LEN chunks and sends RELAY_DATA cells.
        Returns total bytes sent.
        """
        if self._closed:
            raise DestroyedError("Stream is closed")

        total = 0
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + MAX_DATA_LEN]
            await self._circuit._send_relay_cell(
                relay_command=RelayCommand.DATA,
                stream_id=self._stream_id,
                data=chunk,
            )
            self._package_window -= 1
            offset += len(chunk)
            total += len(chunk)

            if self._package_window <= 0:
                # Wait for SENDME from exit
                await self._wait_for_sendme()

        return total

    async def write(self, data: bytes) -> int:
        """Alias for send() to match file-like interface."""
        return await self.send(data)

    async def read(self, n: int = 65536, timeout: float | None = None) -> bytes:
        """Alias for recv() to match file-like interface."""
        return await self.recv(n, timeout)

    async def sendall(self, data: bytes) -> None:
        """Send all data, handling chunking internally."""
        await self.send(data)

    # -----------------------------------------------------------------------
    # Receive
    # -----------------------------------------------------------------------

    async def recv(self, n: int = 65536, timeout: float | None = None) -> bytes:
        """
        Receive up to n bytes.
        Returns b'' on clean close.
        """
        if self._recv_buf:
            chunk = bytes(self._recv_buf[:n])
            del self._recv_buf[:n]
            return chunk

        while not self._recv_buf:
            try:
                cell = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except TimeoutError:
                raise TimeoutError(f"recv() timed out after {timeout}s")

            if cell is None:
                self._closed = True
                return b""

            if cell.relay_command == RelayCommand.END:
                self._closed = True
                reason = cell.data[0] if cell.data else EndReason.DONE
                log.debug("Stream %d END reason=%d", self._stream_id, reason)
                return b""

            if cell.relay_command == RelayCommand.SENDME:
                self._package_window += 50
                continue

            if cell.relay_command == RelayCommand.DATA:
                self._recv_buf.extend(cell.data)
                self._deliver_window -= 1
                if self._deliver_window <= SENDME_THRESHOLD:
                    await self._send_sendme()
                    self._deliver_window += 50
                continue

            log.debug(
                "Unexpected relay cmd %d on stream %d",
                cell.relay_command,
                self._stream_id,
            )

        chunk = bytes(self._recv_buf[:n])
        del self._recv_buf[:n]
        return chunk

    async def recv_all(self, timeout: float | None = None) -> bytes:
        """Receive until the stream is closed."""
        buf = bytearray()
        while True:
            chunk = await self.recv(65536, timeout=timeout)
            if not chunk:
                break
            buf.extend(chunk)
        return bytes(buf)

    # -----------------------------------------------------------------------
    # HTTP helper
    # -----------------------------------------------------------------------

    async def http_get(
        self,
        host: str,
        path: str = "/",
        extra_headers: dict | None = None,
        timeout: float = 30.0,
    ) -> bytes:
        """
        Convenience: send an HTTP/1.0 GET and return the response body.

        Example::

            body = await stream.http_get("example.com", "/")
        """
        headers = {
            "Host": host,
            "User-Agent": "torpy/0.1",
            "Connection": "close",
        }
        if extra_headers:
            headers.update(extra_headers)

        header_lines = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
        request = f"GET {path} HTTP/1.0\r\n{header_lines}\r\n\r\n".encode()
        await self.send(request)

        raw = await self.recv_all(timeout=timeout)
        # Strip HTTP headers
        if b"\r\n\r\n" in raw:
            _, _, body = raw.partition(b"\r\n\r\n")
            return body
        return raw

    # -----------------------------------------------------------------------
    # Close
    # -----------------------------------------------------------------------

    async def close(self) -> None:
        """Send RELAY_END and unregister."""
        if self._closed:
            return
        self._closed = True
        try:
            await self._circuit._send_relay_cell(
                relay_command=RelayCommand.END,
                stream_id=self._stream_id,
                data=bytes([EndReason.DONE]),
            )
        except Exception:
            pass
        self._circuit.close_stream(self._stream_id)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        await self.close()

    # -----------------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------------

    async def _send_sendme(self) -> None:
        await self._circuit._send_relay_cell(
            relay_command=RelayCommand.SENDME,
            stream_id=self._stream_id,
            data=b"",
        )

    async def _wait_for_sendme(self) -> None:
        """Block until we receive a SENDME from the exit."""
        while self._package_window <= 0:
            cell = await self._queue.get()
            if cell is None:
                raise DestroyedError("Circuit closed while waiting for SENDME")
            if cell.relay_command == RelayCommand.SENDME:
                self._package_window += 50
            elif cell.relay_command == RelayCommand.END:
                self._closed = True
                raise StreamError("Stream ended while waiting for SENDME")
            else:
                self._recv_buf.extend(cell.data)

    def __repr__(self) -> str:
        return (
            f"<TorStream id={self._stream_id} "
            f"circuit={self._circuit._circ_id} closed={self._closed}>"
        )
