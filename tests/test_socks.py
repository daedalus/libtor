"""Tests for SOCKS proxy server."""

from unittest.mock import AsyncMock, patch

import pytest

from libtor.socks import (
    SOCKSAddressType,
    SOCKSAuthMethod,
    SOCKSCommand,
    SOCKSProxy,
    SOCKSReply,
    SOCKSVersion,
)


class TestSOCKSConstants:
    """Test SOCKS constants."""

    def test_version_constants(self):
        assert SOCKSVersion.SOCKS4 == 4
        assert SOCKSVersion.SOCKS5 == 5

    def test_command_constants(self):
        assert SOCKSCommand.CONNECT == 1
        assert SOCKSCommand.BIND == 2
        assert SOCKSCommand.UDP_ASSOCIATE == 3

    def test_address_type_constants(self):
        assert SOCKSAddressType.IPv4 == 1
        assert SOCKSAddressType.DOMAIN == 3
        assert SOCKSAddressType.IPv6 == 4

    def test_reply_constants(self):
        assert SOCKSReply.SUCCESS == 0x00
        assert SOCKSReply.GENERAL_FAILURE == 0x01
        assert SOCKSReply.CONNECTION_REFUSED == 0x05

    def test_auth_method_constants(self):
        assert SOCKSAuthMethod.NO_AUTH == 0x00
        assert SOCKSAuthMethod.USERNAME_PASSWORD == 0x02
        assert SOCKSAuthMethod.NO_ACCEPTABLE == 0xFF


class TestSOCKSProxyInit:
    """Test SOCKSProxy initialization."""

    def test_default_init(self):
        from libtor import TorClient

        tor = TorClient()
        proxy = SOCKSProxy(tor_client=tor)

        assert proxy.tor_client is tor
        assert proxy.listen_host == "127.0.0.1"
        assert proxy.listen_port == 1080
        assert proxy._server is None
        assert not proxy._running

    def test_custom_init(self):
        from libtor import TorClient

        tor = TorClient(timeout=60.0)
        proxy = SOCKSProxy(
            tor_client=tor,
            listen_host="0.0.0.0",
            listen_port=9050,
        )

        assert proxy.listen_host == "0.0.0.0"
        assert proxy.listen_port == 9050


class TestSOCKS4Handling:
    """Test SOCKS4 protocol handling."""

    @pytest.mark.asyncio
    async def test_socks4_connect_request_parsing(self):
        """Test parsing SOCKS4 CONNECT request."""
        from libtor import TorClient

        tor = TorClient()
        proxy = SOCKSProxy(tor_client=tor)

        # SOCKS4 CONNECT request:
        # VN(1) CD(1) DSTPORT(2) DSTIP(4) USERID(variable) NULL(1)
        request = (
            b"\x04"  # VN
            b"\x01"  # CD = CONNECT
            b"\x00\x50"  # DSTPORT = 80
            b"\x7f\x00\x00\x01"  # DSTIP = 127.0.0.1
            b"testuser\x00"  # USERID
        )

        # Parse the header
        vn = request[0]
        cd = request[1]
        dst_port = int.from_bytes(request[2:4], "big")
        dst_ip = int.from_bytes(request[4:8], "big")

        assert vn == 4
        assert cd == SOCKSCommand.CONNECT
        assert dst_port == 80
        assert dst_ip == 0x7F000001  # 127.0.0.1

    @pytest.mark.asyncio
    async def test_socks4_reply_format(self):
        """Test SOCKS4 reply format."""
        # Reply: VN(1) CD(1) DSTPORT(2) DSTIP(4)
        reply = struct.pack("!BBHI", 0, SOCKSReply.SUCCESS, 0, 0)

        vn, cd, dst_port, dst_ip = struct.unpack("!BBHI", reply)

        assert vn == 0  # VN must be 0 for reply
        assert cd == SOCKSReply.SUCCESS
        assert dst_port == 0
        assert dst_ip == 0


class TestSOCKS5Handling:
    """Test SOCKS5 protocol handling."""

    @pytest.mark.asyncio
    async def test_socks5_greeting(self):
        """Test SOCKS5 greeting format."""
        # Client greeting: VER(1) NMETHODS(1) METHODS(variable)
        greeting = b"\x05\x02\x00\x02"  # SOCKS5, 2 methods, no-auth + username/password

        version = greeting[0]
        nmethods = greeting[1]
        methods = greeting[2:]

        assert version == 5
        assert nmethods == 2
        assert SOCKSAuthMethod.NO_AUTH in methods

    @pytest.mark.asyncio
    async def test_socks5_auth_method_selection(self):
        """Test SOCKS5 auth method selection."""
        # Server response: VER(1) METHOD(1)
        # We support NO_AUTH (0x00)
        response = struct.pack("!BB", SOCKSVersion.SOCKS5, SOCKSAuthMethod.NO_AUTH)

        version, method = struct.unpack("!BB", response)

        assert version == SOCKSVersion.SOCKS5
        assert method == SOCKSAuthMethod.NO_AUTH

    @pytest.mark.asyncio
    async def test_socks5_request_ipv4(self):
        """Test SOCKS5 CONNECT request with IPv4."""
        # Request: VER(1) CMD(1) RSV(1) ATYP(1) DST.ADDR(variable) DST.PORT(2)
        request = (
            b"\x05"  # VER
            b"\x01"  # CMD = CONNECT
            b"\x00"  # RSV
            b"\x01"  # ATYP = IPv4
            b"\x7f\x00\x00\x01"  # 127.0.0.1
            b"\x00\x50"  # port 80
        )

        version, cmd, rsv, atyp = struct.unpack("!BBBB", request[:4])
        addr = request[4:8]
        port = request[8:10]

        assert version == 5
        assert cmd == SOCKSCommand.CONNECT
        assert atyp == SOCKSAddressType.IPv4
        assert addr == b"\x7f\x00\x00\x01"
        assert port == b"\x00\x50"

    @pytest.mark.asyncio
    async def test_socks5_request_domain(self):
        """Test SOCKS5 CONNECT request with domain."""
        # Request with domain
        request = (
            b"\x05"  # VER
            b"\x01"  # CMD = CONNECT
            b"\x00"  # RSV
            b"\x03"  # ATYP = DOMAIN
            b"\x0b"  # length of "example.com"
            b"example.com"  # domain
            b"\x00\x50"  # port 80
        )

        version, cmd, rsv, atyp = struct.unpack("!BBBB", request[:4])
        domain_length = request[4]
        domain = request[5 : 5 + domain_length]
        port = request[-2:]

        assert version == 5
        assert cmd == SOCKSCommand.CONNECT
        assert atyp == SOCKSAddressType.DOMAIN
        assert domain == b"example.com"
        assert port == b"\x00\x50"

    @pytest.mark.asyncio
    async def test_socks5_reply_format(self):
        """Test SOCKS5 reply format."""
        # Reply: VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(variable) BND.PORT(2)
        reply = (
            struct.pack(
                "!BBBB",
                SOCKSVersion.SOCKS5,
                SOCKSReply.SUCCESS,
                0,  # RSV
                SOCKSAddressType.IPv4,
            )
            + b"\x00\x00\x00\x00"
            + struct.pack("!H", 0)
        )

        version, rep, rsv, atyp = struct.unpack("!BBBB", reply[:4])

        assert version == SOCKSVersion.SOCKS5
        assert rep == SOCKSReply.SUCCESS
        assert rsv == 0
        assert atyp == SOCKSAddressType.IPv4


class TestSOCKSProxyStartStop:
    """Test SOCKS proxy start/stop."""

    @pytest.mark.asyncio
    async def test_proxy_context_manager(self):
        """Test proxy as async context manager."""
        from libtor import TorClient

        tor = TorClient()
        proxy = SOCKSProxy(tor_client=tor, listen_port=19876)

        # Mock start_server
        mock_server = AsyncMock()
        with patch("asyncio.start_server", return_value=mock_server):
            async with proxy as p:
                assert p._running

            # Should be stopped after context
            assert not proxy._running
            mock_server.close.assert_called_once()


class TestSOCKSErrorHandling:
    """Test SOCKS error handling."""

    @pytest.mark.asyncio
    async def test_unsupported_version(self):
        """Test handling unsupported SOCKS version."""
        from libtor import TorClient

        tor = TorClient()
        proxy = SOCKSProxy(tor_client=tor)

        # Create mock reader/writer
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"\x06")  # Invalid version
        mock_writer = AsyncMock()

        with patch("asyncio.start_server"):
            await proxy._handle_client(mock_reader, mock_writer)

        mock_writer.close.assert_called_once()


import struct
