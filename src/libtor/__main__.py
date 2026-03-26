"""CLI entry point for libtor."""


async def main() -> int:
    """Simple CLI entry point."""
    print("libtor - Pure Python Tor Protocol")
    print("Use as a library: from libtor import TorClient")
    return 0


if __name__ == "__main__":
    import asyncio

    raise SystemExit(asyncio.run(main()))
