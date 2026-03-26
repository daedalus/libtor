"""
libtor - A pure Python Tor protocol implementation.

Usage:
    from libtor import TorClient

    async with TorClient() as tor:
        async with tor.create_circuit() as circuit:
            async with circuit.open_stream("example.com", 80) as stream:
                await stream.send(b"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n")
                data = await stream.recv(4096)
"""

from typing import TYPE_CHECKING

from .cells import Cell, CellCommand, DestroyReason, EndReason, RelayCell, RelayCommand
from .circuit import Circuit
from .client import TorClient
from .crypto import CircuitKeys
from .directory import RouterInfo
from .exceptions import (
    CellError,
    CircuitError,
    DestroyedError,
    DirectoryError,
    HandshakeError,
    RelayError,
    StreamError,
    TorError,
)
from .stream import TorStream

__version__ = "0.1.0"
__all__ = [
    "TorClient",
    "Circuit",
    "TorStream",
    "RouterInfo",
    "Cell",
    "CellCommand",
    "RelayCell",
    "RelayCommand",
    "DestroyReason",
    "EndReason",
    "CircuitKeys",
    "TorError",
    "HandshakeError",
    "CircuitError",
    "StreamError",
    "DirectoryError",
    "CellError",
    "RelayError",
    "DestroyedError",
]

if TYPE_CHECKING:
    from .cells import Cell, RelayCell
    from .circuit import Circuit
    from .client import TorClient
    from .crypto import CircuitKeys
    from .directory import RouterInfo
    from .stream import TorStream
