import asyncio

import pytest


@pytest.fixture
def event_loop() -> asyncio.AbstractEventLoop:
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def sample_router_info() -> "RouterInfo":
    """Sample router info for testing."""
    from libtor.directory import RouterInfo

    return RouterInfo(
        identity=b"a" * 20,
        nickname="test relay",
        address="127.0.0.1",
        or_port=9001,
        dir_port=8080,
        bandwidth=1000000,
        flags=["Fast", "Running", "Stable"],
    )


@pytest.fixture
def mock_ntor_key() -> bytes:
    """Mock ntor key for testing."""
    return b"b" * 32
