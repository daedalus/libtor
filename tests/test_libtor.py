import pytest

from libtor import (
    Cell,
    CellCommand,
    CellError,
    CircuitError,
    DestroyedError,
    DestroyReason,
    DirectoryError,
    EndReason,
    HandshakeError,
    RelayCell,
    RelayCommand,
    RelayError,
    StreamError,
    TorError,
)
from libtor.directory import ConsensuParser, MicrodescParser, RouterInfo


class TestExceptions:
    def test_tor_error_is_base(self):
        assert issubclass(HandshakeError, TorError)
        assert issubclass(CircuitError, TorError)
        assert issubclass(StreamError, TorError)
        assert issubclass(DirectoryError, TorError)
        assert issubclass(CellError, TorError)
        assert issubclass(RelayError, TorError)
        assert issubclass(DestroyedError, TorError)

    def test_circuit_error_message(self):
        err = CircuitError("test error")
        assert str(err) == "test error"
        assert isinstance(err, TorError)

    def test_stream_error_message(self):
        err = StreamError("stream closed")
        assert str(err) == "stream closed"
        assert isinstance(err, TorError)

    def test_handshake_error_message(self):
        err = HandshakeError("handshake failed")
        assert str(err) == "handshake failed"
        assert isinstance(err, TorError)

    def test_directory_error_message(self):
        err = DirectoryError("directory unavailable")
        assert str(err) == "directory unavailable"
        assert isinstance(err, TorError)

    def test_cell_error_message(self):
        err = CellError("cell parse error")
        assert str(err) == "cell parse error"
        assert isinstance(err, TorError)

    def test_relay_error_message(self):
        err = RelayError("relay command failed")
        assert str(err) == "relay command failed"
        assert isinstance(err, TorError)

    def test_destroyed_error_message(self):
        err = DestroyedError("circuit destroyed")
        assert str(err) == "circuit destroyed"
        assert isinstance(err, TorError)


class TestTorClientImport:
    def test_import_tor_client(self):
        from libtor import TorClient

        assert TorClient is not None

    def test_import_circuit(self):
        from libtor import Circuit

        assert Circuit is not None

    def test_import_tor_stream(self):
        from libtor import TorStream

        assert TorStream is not None

    def test_version_exists(self):
        import libtor

        assert hasattr(libtor, "__version__")
        assert libtor.__version__ == "0.1.0"

    def test_all_exports(self):
        import libtor

        expected = [
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
        for name in expected:
            assert name in libtor.__all__


class TestCell:
    def test_cell_fixed_encoding(self):
        cell = Cell(circ_id=1, command=CellCommand.RELAY, payload=b"test")
        data = cell.to_bytes(link_version=4)
        assert len(data) == 514

    def test_cell_variable_encoding(self):
        cell = Cell(circ_id=0, command=CellCommand.VERSIONS, payload=b"\x00\x05")
        data = cell.to_bytes(link_version=4)
        assert data[0:4] == b"\x00\x00\x00\x00"
        assert data[4] == CellCommand.VERSIONS

    def test_cell_from_bytes(self):
        payload = b"x" * 509
        data = b"\x00\x00\x00\x01" + bytes([CellCommand.RELAY]) + payload
        cell = Cell.from_bytes(data, link_version=4)
        assert cell.circ_id == 1
        assert cell.command == CellCommand.RELAY

    def test_cell_too_short(self):
        with pytest.raises(CellError, match="too short"):
            Cell.from_bytes(b"ab", link_version=4)

    def test_cell_repr(self):
        cell = Cell(circ_id=1, command=CellCommand.RELAY, payload=b"test")
        r = repr(cell)
        assert "RELAY" in r
        assert "circ_id=1" in r


class TestRelayCell:
    def test_relay_cell_to_payload(self):
        rc = RelayCell(relay_command=RelayCommand.BEGIN, stream_id=1, data=b"test")
        payload = rc.to_payload()
        assert len(payload) == 509

    def test_relay_cell_from_payload(self):
        header = (
            struct.pack("!BHH", RelayCommand.BEGIN, 0, 1)
            + b"\x00\x00\x00\x00"
            + struct.pack("!H", 4)
            + b"test"
        )
        rc = RelayCell.from_payload(header + b"test")
        assert rc.relay_command == RelayCommand.BEGIN
        assert rc.stream_id == 1
        assert rc.data == b"test"

    def test_relay_cell_payload_too_short(self):
        with pytest.raises(CellError, match="too short"):
            RelayCell.from_payload(b"short")

    def test_relay_cell_repr(self):
        rc = RelayCell(relay_command=RelayCommand.DATA, stream_id=1, data=b"test")
        r = repr(rc)
        assert "DATA" in r
        assert "stream=1" in r


class TestCellCommands:
    def test_cell_command_values(self):
        assert CellCommand.PADDING == 0
        assert CellCommand.RELAY == 3
        assert CellCommand.CREATE_FAST == 5
        assert CellCommand.VERSIONS == 7


class TestRelayCommands:
    def test_relay_command_values(self):
        assert RelayCommand.BEGIN == 1
        assert RelayCommand.DATA == 2
        assert RelayCommand.END == 3
        assert RelayCommand.CONNECTED == 4


class TestDestroyReason:
    def test_destroy_reason_values(self):
        assert DestroyReason.NONE == 0
        assert DestroyReason.REQUESTED == 3
        assert DestroyReason.DESTROYED == 11


class TestEndReason:
    def test_end_reason_values(self):
        assert EndReason.MISC == 1
        assert EndReason.DONE == 6
        assert EndReason.CONNRESET == 12


class TestRouterInfo:
    def test_router_info_creation(self):
        router = RouterInfo(
            nickname="test",
            identity=b"a" * 20,
            digest=b"b" * 20,
            address="127.0.0.1",
            or_port=9001,
            dir_port=8080,
            bandwidth=1000,
            flags=["Fast", "Valid"],
        )
        assert router.nickname == "test"
        assert router.address == "127.0.0.1"
        assert router.is_fast
        assert router.is_valid

    def test_router_info_is_guard(self):
        router = RouterInfo(
            nickname="test",
            identity=b"a" * 20,
            digest=b"b" * 20,
            address="127.0.0.1",
            or_port=9001,
            dir_port=8080,
            flags=["Guard", "Fast", "Valid"],
        )
        assert router.is_guard

    def test_router_info_is_exit(self):
        router = RouterInfo(
            nickname="test",
            identity=b"a" * 20,
            digest=b"b" * 20,
            address="127.0.0.1",
            or_port=9001,
            dir_port=8080,
            flags=["Exit", "Fast", "Valid"],
        )
        assert router.is_exit

    def test_router_info_identity_hex(self):
        router = RouterInfo(
            nickname="test",
            identity=b"\xaa\xbb\xcc",
            digest=b"b" * 20,
            address="127.0.0.1",
            or_port=9001,
            dir_port=8080,
        )
        assert router.identity_hex == "AABBCC"

    def test_router_info_repr(self):
        router = RouterInfo(
            nickname="test",
            identity=b"a" * 20,
            digest=b"b" * 20,
            address="127.0.0.1",
            or_port=9001,
            dir_port=8080,
            flags=["Fast", "Valid"],
        )
        r = repr(router)
        assert "test" in r


class TestConsensuParser:
    def test_parse_empty(self):
        routers = ConsensuParser.parse("")
        assert routers == []

    def test_parse_valid(self):
        text = "r testrouter AAAAAAAAAAAAAAAAAAAAAAAA bbbbbbbbbbbbbbbbbbbbbbbb 2024-01-01T00:00:00 127.0.0.1 9001 8080\ns Fast Valid Guard Exit\nw Bandwidth=1000000\n"
        routers = ConsensuParser.parse(text)
        assert len(routers) == 1
        assert routers[0].nickname == "testrouter"
        assert routers[0].address == "127.0.0.1"
        assert routers[0].or_port == 9001
        assert routers[0].is_fast

    def test_parse_multiple(self):
        text = "r router1 AAAAAAAAAAAAAAAAAAAAAAAA bbbbbbbbbbbbbbbbbbbbbbbb 2024-01-01T00:00:00 127.0.0.1 9001 8080\ns Fast Valid\nr router2 CCCCCCCCCCCCCCCCCCCCCCCC dddddddddddddddddddddddd 2024-01-01T00:00:00 127.0.0.2 9001 8080\ns Fast Exit\n"
        routers = ConsensuParser.parse(text)
        assert len(routers) == 2

    def test_parse_invalid_line(self):
        text = "invalid line here\nr testrouter AAAAAAAAAAAAAAAAAAAAAAAA bbbbbbbbbbbbbbbbbbbbbbbb 2024-01-01T00:00:00 127.0.0.1 9001 8080\n"
        routers = ConsensuParser.parse(text)
        assert len(routers) == 1
        assert routers[0].nickname == "testrouter"
        assert routers[0].address == "127.0.0.1"
        assert routers[0].or_port == 9001
        assert routers[0].is_fast

    def test_parse_multiple(self):
        text = "r router1 AAAAAAAAAAAAAAAAAAAAAAAA bbbbbbbbbbbbbbbbbbbbbbbb 2024-01-01T00:00:00 127.0.0.1 9001 8080\ns Fast Valid\nr router2 CCCCCCCCCCCCCCCCCCCCCCCC dddddddddddddddddddddddd 2024-01-01T00:00:00 127.0.0.2 9001 8080\ns Fast Exit\n"
        routers = ConsensuParser.parse(text)
        assert len(routers) == 2

    def test_parse_invalid_line(self):
        text = "invalid line here\nr testrouter AAAAAAAAAAAAAAAAAAAAAAAA bbbbbbbbbbbbbbbbbbbbbbbb 2024-01-01T00:00:00 127.0.0.1 9001 8080\n"
        routers = ConsensuParser.parse(text)
        assert len(routers) == 1


class TestMicrodescParser:
    def test_extract_ntor_key_present(self):
        text = (
            """
onion-key
ntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
"""
            + "extra"
        )
        key = MicrodescParser.extract_ntor_key(text)
        assert key is not None

    def test_extract_ntor_key_missing(self):
        text = "no ntor key here"
        key = MicrodescParser.extract_ntor_key(text)
        assert key is None


import struct
