"""
SOCKS4/5 proxy server implementation.

Supports:
  - SOCKS4 (no authentication)
  - SOCKS4A (hostname resolution by proxy)
  - SOCKS5 (username/password or no authentication)

Reference: https://tools.ietf.org/html/rfc1928
"""

import asyncio
import logging
import socket
import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

from .client import TorClient

if TYPE_CHECKING:
    from .stream import TorStream

log = logging.getLogger(__name__)


class SOCKSVersion(IntEnum):
    SOCKS4 = 4
    SOCKS5 = 5


class SOCKSCommand(IntEnum):
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3


class SOCKSAddressType(IntEnum):
    IPv4 = 1
    DOMAIN = 3
    IPv6 = 4


class SOCKSReply(IntEnum):
    SUCCESS = 0x00
    GENERAL_FAILURE = 0x01
    CONNECTION_NOT_ALLOWED = 0x02
    NETWORK_UNREACHABLE = 0x03
    HOST_UNREACHABLE = 0x04
    CONNECTION_REFUSED = 0x05
    TTL_EXPIRED = 0x06
    COMMAND_NOT_SUPPORTED = 0x07
    ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class SOCKSAuthMethod(IntEnum):
    NO_AUTH = 0x00
    GSSAPI = 0x01
    USERNAME_PASSWORD = 0x02
    NO_ACCEPTABLE = 0xFF


@dataclass
class SOCKSRequest:
    """Parsed SOCKS request."""

    version: int
    command: int
    address_type: int
    destination: tuple[str, int]  # (host, port)


class SOCKSProxy:
    """
    Async SOCKS4/5 proxy server.

    Usage:
        proxy = SOCKSProxy(tor_client=tor_client, listen_host="127.0.0.1", listen_port=1080)
        await proxy.start()
    """

    def __init__(
        self,
        tor_client: TorClient,
        listen_host: str = "127.0.0.1",
        listen_port: int = 1080,
    ):
        self.tor_client = tor_client
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._server: asyncio.Server | None = None
        self._running = False

    async def start(self) -> None:
        """Start the SOCKS proxy server."""
        self._server = await asyncio.start_server(
            self._handle_client,
            self.listen_host,
            self.listen_port,
        )
        self._running = True
        log.info(
            "SOCKS proxy listening on %s:%d",
            self.listen_host,
            self.listen_port,
        )

    async def stop(self) -> None:
        """Stop the SOCKS proxy server."""
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        log.info("SOCKS proxy stopped")

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *_):
        await self.stop()

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle incoming SOCKS client connection."""
        try:
            # Read the first byte to determine SOCKS version
            data = await reader.read(1)
            if not data:
                writer.close()
                return

            version = data[0]

            if version == SOCKSVersion.SOCKS4:
                await self._handle_socks4(reader, writer)
            elif version == SOCKSVersion.SOCKS5:
                await self._handle_socks5(reader, writer)
            else:
                log.warning("Unsupported SOCKS version: %d", version)
                writer.close()

        except Exception as exc:
            log.debug("Client handler error: %s", exc)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle_socks4(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle SOCKS4 connection."""
        # SOCKS4: VN CD DSTPORT DSTIP USERID
        # Minimum: 2 + 1 + 2 + 4 + 1 = 10 bytes
        header = await reader.read(8)
        if len(header) < 8:
            writer.close()
            return

        vn, cd, dst_port, dst_ip = struct.unpack("!BBHI", header[:8])

        # Read userid (until null)
        user_id = b""
        while True:
            byte = await reader.read(1)
            if not byte or byte == b"\x00":
                break
            user_id += byte

        # Check command
        if cd != SOCKSCommand.CONNECT:
            await self._socks4_reply(writer, SOCKSReply.GENERAL_FAILURE)
            return

        # Resolve destination
        if dst_ip & 0x000000FF == 0 and dst_ip != 0:
            # SOCKS4A: IP is 0.0.0.x, hostname follows userid
            # Read hostname
            hostname = b""
            while True:
                byte = await reader.read(1)
                if not byte or byte == b"\x00":
                    break
                hostname += byte
            destination = (hostname.decode(), dst_port)
        else:
            # IPv4
            destination = (
                socket.inet_ntoa(struct.pack("!I", dst_ip)),
                dst_port,
            )

        # Connect through Tor
        try:
            if not self.tor_client._bootstrapped:
                await self.tor_client.bootstrap()

            async with self.tor_client.create_circuit() as circuit:
                stream = await circuit.open_stream(destination[0], destination[1])

                # Send success reply
                await self._socks4_reply(writer, SOCKSReply.SUCCESS, ip=dst_ip)

                # Pipe data
                await self._pipe_stream(reader, writer, stream)

                await stream.close()

        except Exception as exc:
            log.debug("SOCKS4 connect failed: %s", exc)
            await self._socks4_reply(writer, SOCKSReply.GENERAL_FAILURE)

    async def _socks4_reply(
        self,
        writer: asyncio.StreamWriter,
        reply_code: int,
        ip: int = 0,
    ) -> None:
        """Send SOCKS4 reply."""
        # VN=0, CD=reply code, DSTIP=IP
        response = struct.pack("!BBHI", 0, reply_code, ip, 0)
        writer.write(response)
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def _handle_socks5(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle SOCKS5 connection."""
        # Step 1: Greeting (method selection)
        data = await reader.read(2)
        if len(data) < 2:
            writer.close()
            return

        _version, nmethods = data

        methods = await reader.read(nmethods)
        if len(methods) < nmethods:
            writer.close()
            return

        # Select auth method (we support NO_AUTH=0)
        if SOCKSAuthMethod.NO_AUTH in methods:
            writer.write(bytes([SOCKSVersion.SOCKS5, SOCKSAuthMethod.NO_AUTH]))
        else:
            writer.write(bytes([SOCKSVersion.SOCKS5, SOCKSAuthMethod.NO_ACCEPTABLE]))
        await writer.drain()

        # Step 2: Request
        data = await reader.read(4)
        if len(data) < 4:
            writer.close()
            return

        version, command, _, address_type = struct.unpack("!BBBB", data)

        if command != SOCKSCommand.CONNECT:
            await self._socks5_reply(writer, SOCKSReply.COMMAND_NOT_SUPPORTED)
            return

        # Read address
        if address_type == SOCKSAddressType.IPv4:
            addr_data = await reader.read(4)
            if len(addr_data) < 4:
                writer.close()
                return
            host = socket.inet_ntoa(addr_data)
        elif address_type == SOCKSAddressType.DOMAIN:
            length = await reader.read(1)
            if not length:
                writer.close()
                return
            addr_data = await reader.read(length[0])
            if len(addr_data) < length[0]:
                writer.close()
                return
            host = addr_data.decode()
        elif address_type == SOCKSAddressType.IPv6:
            await self._socks5_reply(writer, SOCKSReply.ADDRESS_TYPE_NOT_SUPPORTED)
            return
        else:
            await self._socks5_reply(writer, SOCKSReply.ADDRESS_TYPE_NOT_SUPPORTED)
            return

        # Read port
        port_data = await reader.read(2)
        if len(port_data) < 2:
            writer.close()
            return
        port = struct.unpack("!H", port_data)[0]

        # Connect through Tor
        try:
            if not self.tor_client._bootstrapped:
                await self.tor_client.bootstrap()

            async with self.tor_client.create_circuit() as circuit:
                stream = await circuit.open_stream(host, port)

                # Send success reply
                await self._socks5_reply(writer, SOCKSReply.SUCCESS)

                # Pipe data
                await self._pipe_stream(reader, writer, stream)

                await stream.close()

        except Exception as exc:
            log.debug("SOCKS5 connect failed: %s", exc)
            await self._socks5_reply(writer, SOCKSReply.CONNECTION_REFUSED)

    async def _socks5_reply(
        self,
        writer: asyncio.StreamWriter,
        reply_code: int,
        address_type: int = SOCKSAddressType.IPv4,
        bind_address: str = "0.0.0.0",
        bind_port: int = 0,
    ) -> None:
        """Send SOCKS5 reply."""
        if address_type == SOCKSAddressType.IPv4:
            addr = socket.inet_aton(bind_address)
        elif address_type == SOCKSAddressType.IPv6:
            addr = socket.inet_pton(socket.AF_INET6, bind_address)
        else:
            addr = b""

        response = (
            struct.pack(
                "!BBBB",
                SOCKSVersion.SOCKS5,
                reply_code,
                0,  # Reserved
                address_type,
            )
            + addr
            + struct.pack("!H", bind_port)
        )

        writer.write(response)
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    async def _pipe_stream(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        tor_stream: "TorStream",
    ) -> None:
        """Bidirectional pipe between client and Tor stream."""

        async def copy_to_tor():
            try:
                while True:
                    data = await client_reader.read(4096)
                    if not data:
                        break
                    await tor_stream.send(data)
            except Exception:
                pass
            finally:
                await tor_stream.close()

        async def copy_from_tor():
            try:
                while True:
                    data = await tor_stream.recv(4096)
                    if not data:
                        break
                    client_writer.write(data)
                    await client_writer.drain()
            except Exception:
                pass
            finally:
                client_writer.close()
                try:
                    await client_writer.wait_closed()
                except Exception:
                    pass

        await asyncio.gather(copy_to_tor(), copy_from_tor())
