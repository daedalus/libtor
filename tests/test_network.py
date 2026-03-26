"""Network integration tests for libtor.

These tests are designed to work when:
1. Network is available (direct or via Tor proxy)
2. Tor daemon is running

Run with: pytest tests/test_network.py -v -m network
Skip with: pytest tests/test_network.py -v -m "not network"
"""

import asyncio

import pytest

# Import conditionally - these may skip if network unavailable
from libtor import TorClient
from libtor.directory import DirectoryClient


def pytest_configure(config):
    """Add custom marker for network tests."""
    config.addinivalue_line("markers", "network: tests requiring network connectivity")


class TestBootstrap:
    """Test consensus fetching and bootstrapping."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_fetch_consensus(self):
        """Fetch consensus from directory authorities."""
        dir_client = DirectoryClient(timeout=60.0)

        routers = await asyncio.wait_for(dir_client.fetch_consensus(), timeout=120.0)

        # Should get relays
        assert len(routers) > 100, f"Expected many relays, got {len(routers)}"

        # Should have guards and exits
        guards = dir_client.get_guards()
        exits = dir_client.get_exits()

        assert len(guards) > 0, "Should have guards"
        assert len(exits) > 0, "Should have exits"

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_bootstrap(self):
        """Test full bootstrap."""
        client = TorClient(timeout=60.0, directory_timeout=60.0)

        await asyncio.wait_for(client.bootstrap(), timeout=120.0)

        assert client._dir.routers is not None
        assert len(client._dir.routers) > 100


class TestCircuitCreation:
    """Test circuit creation."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_create_circuit(self):
        """Create a basic circuit."""
        client = TorClient(timeout=60.0, directory_timeout=60.0)

        await asyncio.wait_for(client.bootstrap(), timeout=120.0)

        async with asyncio.wait_for(client.create_circuit(), timeout=60.0) as circuit:
            assert len(circuit._hops) >= 2


class TestStreamOperations:
    """Test stream operations."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_http_get(self):
        """HTTP GET through Tor."""
        client = TorClient(timeout=60.0, directory_timeout=60.0)

        await asyncio.wait_for(client.bootstrap(), timeout=120.0)

        body = await asyncio.wait_for(client.fetch("http://example.com/"), timeout=60.0)

        assert body is not None
        assert len(body) > 0
        # Example.com should return HTML
        assert b"<!DOCTYPE" in body or b"<html" in body.lower()


class TestGuardPersistence:
    """Test guard state persistence."""

    @pytest.mark.asyncio
    @pytest.mark.network
    async def test_guard_state_file_created(self, tmp_path):
        """Test that guard state file is created."""
        import json
        import os

        state_file = tmp_path / "guard_state.json"
        client = TorClient(
            timeout=60.0, directory_timeout=60.0, guard_state_file=str(state_file)
        )

        async with client:
            await asyncio.wait_for(client.bootstrap(), timeout=120.0)

            async with asyncio.wait_for(
                client.create_circuit(), timeout=60.0
            ) as circuit:
                pass

        # File should exist
        assert os.path.exists(state_file), "Guard state file should be created"

        # Should be valid JSON
        with open(state_file) as f:
            data = json.load(f)
            assert "guards" in data


@pytest.mark.network
def test_network_available():
    """Quick test to verify network connectivity."""
    import socket

    # Quick DNS check
    try:
        socket.gethostbyname("example.com")
        print("DNS resolution working")
    except socket.gaierror:
        pytest.skip("No network connectivity")

    return True
