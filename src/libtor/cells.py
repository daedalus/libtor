"""
Tor cell definitions, constants, and (de)serialization.

References:
  - tor-spec.txt §3 (Cell Packet Format)
  - tor-spec.txt §6 (Flow Control)
  - tor-spec.txt §7 (Relay Cells)
"""

import struct
from dataclasses import dataclass
from enum import IntEnum

from .exceptions import CellError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CELL_SIZE = 514  # Fixed-length cell size (link protocol v3+)
PAYLOAD_LEN = 509  # Payload bytes in a fixed cell
VAR_HEADER_LEN = 5  # circ_id(4) + command(1)  for variable-length cells
RELAY_PAYLOAD_LEN = 498  # Payload of a RELAY cell after relay header

# Minimum Tor link protocol version we support
MIN_LINK_PROTOCOL = 3
MAX_LINK_PROTOCOL = 5


# ---------------------------------------------------------------------------
# Command codes  (tor-spec.txt §3)
# ---------------------------------------------------------------------------


class CellCommand(IntEnum):
    PADDING = 0
    CREATE = 1
    CREATED = 2
    RELAY = 3
    DESTROY = 4
    CREATE_FAST = 5
    CREATED_FAST = 6
    NETINFO = 8
    RELAY_EARLY = 9
    CREATE2 = 10
    CREATED2 = 11
    PADDING_NEGOTIATE = 12
    # Variable-length cells (≥128)
    VERSIONS = 7
    VPADDING = 128
    CERTS = 129
    AUTH_CHALLENGE = 130
    AUTHENTICATE = 131
    AUTHORIZE = 132


# ---------------------------------------------------------------------------
# Relay command codes  (tor-spec.txt §6.1)
# ---------------------------------------------------------------------------


class RelayCommand(IntEnum):
    """Relay commands as per tor-spec.txt §6.1"""

    BEGIN = 1
    DATA = 2
    END = 3
    CONNECTED = 4
    SENDME = 5
    EXTEND = 6
    EXTENDED = 7
    TRUNCATE = 8
    TRUNCATED = 9
    DROP = 10
    RESOLVE = 11
    RESOLVED = 12
    BEGIN_DIR = 13
    EXTEND2 = 14
    EXTENDED2 = 15
    # v2 rendezvous (not implemented)
    # ESTABLISH_INTRO = 16
    # ESTABLISH_RENDEZVOUS = 17
    # INTRO_ESTABLISHED = 18
    # RENDEZVOUS_ESTABLISHED = 19
    # JOIN = 20
    # CONFLUX_LINK = 21
    # CONFLUX_ESTABLISHED = 22
    # CONFLUX_LINK_DONE = 23


# ---------------------------------------------------------------------------
# Destroy reason codes  (tor-spec.txt §5.4)
# ---------------------------------------------------------------------------


class DestroyReason(IntEnum):
    NONE = 0
    PROTOCOL = 1
    INTERNAL = 2
    REQUESTED = 3
    HIBERNATING = 4
    RESOURCELIMIT = 5
    CONNECTFAILED = 6
    OR_IDENTITY = 7
    OR_CONN_CLOSED = 8
    FINISHED = 9
    TIMEOUT = 10
    DESTROYED = 11
    NOSUCHSERVICE = 12


# ---------------------------------------------------------------------------
# End reason codes  (tor-spec.txt §6.3)
# ---------------------------------------------------------------------------


class EndReason(IntEnum):
    """End reason codes as per tor-spec.txt §6.3"""

    MISC = 1
    RESOLVEFAILED = 2
    CONNECTREFUSED = 3
    EXITPOLICY = 4
    DESTROY = 5
    DONE = 6
    TIMEOUT = 7
    NOROUTE = 8
    HIBERNATING = 9
    INTERNAL = 10
    RESOURCELIMIT = 11
    CONNRESET = 12
    TORPROTOCOL = 13
    NOTDIRECTORY = 14
    # Extended reasons
    ALREADY_SOCKS_REJECTED = 15
    CANT_EXTEND = 16
    NET_UNREACHABLE = 17
    SOCKS_PROTOCOL = 18
    CACHE_CONTROL = 13  # Duplicate for compatibility


# ---------------------------------------------------------------------------
# Cell dataclass
# ---------------------------------------------------------------------------


@dataclass
class Cell:
    """A raw Tor cell (fixed or variable length)."""

    circ_id: int
    command: int
    payload: bytes = b""

    # ---- serialisation ----------------------------------------------------

    def to_bytes(self, link_version: int = 4) -> bytes:
        """Encode the cell to bytes for transmission."""
        if self.command == CellCommand.VERSIONS or self.command >= 128:
            return self._encode_variable(link_version)
        return self._encode_fixed(link_version)

    def _encode_fixed(self, link_version: int) -> bytes:
        if link_version >= 4:
            circ_bytes = struct.pack("!I", self.circ_id)  # 4-byte circ_id
        else:
            circ_bytes = struct.pack("!H", self.circ_id)  # 2-byte circ_id

        payload = self.payload.ljust(PAYLOAD_LEN, b"\x00")[:PAYLOAD_LEN]
        return circ_bytes + struct.pack("!B", self.command) + payload

    def _encode_variable(self, link_version: int) -> bytes:
        if link_version >= 4:
            circ_bytes = struct.pack("!I", self.circ_id)
        else:
            circ_bytes = struct.pack("!H", self.circ_id)
        length = struct.pack("!H", len(self.payload))
        return circ_bytes + struct.pack("!B", self.command) + length + self.payload

    # ---- deserialisation --------------------------------------------------

    @staticmethod
    def from_bytes(data: bytes, link_version: int = 4) -> "Cell":
        """Decode a cell from raw bytes."""
        if link_version >= 4:
            if len(data) < 5:
                raise CellError("Cell too short")
            circ_id = struct.unpack("!I", data[:4])[0]
            command = data[4]
            rest = data[5:]
            header_len = 5
        else:
            if len(data) < 3:
                raise CellError("Cell too short")
            circ_id = struct.unpack("!H", data[:2])[0]
            command = data[2]
            rest = data[3:]
            header_len = 3

        if command == CellCommand.VERSIONS or command >= 128:
            # Variable-length
            if len(rest) < 2:
                raise CellError("Variable cell too short for length field")
            length = struct.unpack("!H", rest[:2])[0]
            payload = rest[2 : 2 + length]
        else:
            payload = rest[:PAYLOAD_LEN]

        return Cell(circ_id=circ_id, command=command, payload=payload)

    def __repr__(self) -> str:
        try:
            cmd_name = CellCommand(self.command).name
        except ValueError:
            cmd_name = f"0x{self.command:02x}"
        return (
            f"<Cell circ_id={self.circ_id} cmd={cmd_name} payload={len(self.payload)}B>"
        )


# ---------------------------------------------------------------------------
# RelayCell  (unpacked relay payload)
# ---------------------------------------------------------------------------


@dataclass
class RelayCell:
    """
    The decrypted, parsed relay payload.

    Wire layout (tor-spec.txt §6.1):
      relay_command  [1 byte]
      recognized     [2 bytes] – 0x0000 when fully unwrapped
      stream_id      [2 bytes]
      digest         [4 bytes]
      length         [2 bytes]
      data           [length bytes]
    """

    relay_command: int
    stream_id: int
    data: bytes = b""
    recognized: int = 0
    digest: bytes = b"\x00\x00\x00\x00"

    HEADER_LEN = 11  # 1+2+2+4+2

    def to_payload(self) -> bytes:
        """Encode to a 509-byte relay payload (digest left as zeros for MAC)."""
        header = struct.pack(
            "!BHH",
            self.relay_command,
            self.recognized,
            self.stream_id,
        )
        # digest placeholder (4 bytes) + length
        length = struct.pack("!H", len(self.data))
        payload = header + b"\x00\x00\x00\x00" + length + self.data
        return payload.ljust(RELAY_PAYLOAD_LEN + self.HEADER_LEN, b"\x00")

    @classmethod
    def from_payload(cls, payload: bytes) -> "RelayCell":
        if len(payload) < cls.HEADER_LEN:
            raise CellError(f"Relay payload too short: {len(payload)}")
        relay_command = payload[0]
        recognized = struct.unpack("!H", payload[1:3])[0]
        stream_id = struct.unpack("!H", payload[3:5])[0]
        digest = payload[5:9]
        length = struct.unpack("!H", payload[9:11])[0]
        data = payload[11 : 11 + length]
        return cls(
            relay_command=relay_command,
            stream_id=stream_id,
            data=data,
            recognized=recognized,
            digest=digest,
        )

    def __repr__(self) -> str:
        try:
            cmd_name = RelayCommand(self.relay_command).name
        except ValueError:
            cmd_name = f"0x{self.relay_command:02x}"
        return (
            f"<RelayCell cmd={cmd_name} stream={self.stream_id} data={len(self.data)}B>"
        )
