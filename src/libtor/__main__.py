"""CLI entry point for libtor."""

import argparse
import asyncio
import logging

from libtor import Config, SOCKSProxy, TorClient, setup_logging


async def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="libtor - Pure Python Tor Protocol")
    parser.add_argument(
        "--config",
        "-c",
        help="Path to config file",
    )
    parser.add_argument(
        "--socks",
        type=int,
        metavar="PORT",
        help="Start SOCKS proxy on specified port",
    )
    parser.add_argument(
        "--socks-host",
        default="127.0.0.1",
        help="SOCKS proxy listen host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--hops",
        type=int,
        help="Number of circuit hops",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging level",
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["socks", "fetch", "resolve"],
        help="Command to run",
    )
    parser.add_argument("args", nargs=argparse.REMAINDER, help="Command arguments")

    args = parser.parse_args()

    # Load configuration
    if args.config:
        config = Config.from_file(args.config)
    else:
        config = Config.from_default_locations()

    # Override with CLI arguments
    if args.socks:
        config.socks.enabled = True
        config.socks.port = args.socks
    if args.socks_host:
        config.socks.host = args.socks_host
    if args.hops:
        config.tor.hops = args.hops
    if args.log_level:
        config.log_level = args.log_level

    # Setup logging
    setup_logging(config)

    log = logging.getLogger(__name__)

    # Handle commands
    if args.command == "socks" or (not args.command and config.socks.enabled):
        # Start SOCKS proxy
        log.info("Starting Tor client...")
        async with TorClient(
            hops=config.tor.hops,
            timeout=config.tor.timeout,
            directory_timeout=config.tor.directory_timeout,
            guard_state_file=config.tor.guard_state_file,
        ) as tor:
            log.info("Bootstrapping Tor client...")
            await tor.bootstrap()

            log.info(
                "Starting SOCKS proxy on %s:%d",
                config.socks.host,
                config.socks.port,
            )
            async with SOCKSProxy(
                tor_client=tor,
                listen_host=config.socks.host,
                listen_port=config.socks.port,
            ) as proxy:
                log.info("SOCKS proxy is running. Press Ctrl+C to stop.")
                await asyncio.Event().wait()

    elif args.command == "fetch":
        # Simple HTTP fetch
        url = args.args[0] if args.args else "http://example.com/"
        async with TorClient() as tor:
            await tor.bootstrap()
            body = await tor.fetch(url)
            print(body.decode())

    elif args.command == "resolve":
        # DNS resolve
        hostname = args.args[0] if args.args else "example.com"
        async with TorClient() as tor:
            await tor.bootstrap()
            ips = await tor.resolve(hostname)
            for ip in ips:
                print(ip)

    else:
        # Default: print help
        print("libtor - Pure Python Tor Protocol")
        print()
        print("Usage:")
        print("  python -m libtor                    # Print this help")
        print("  python -m libtor socks               # Start SOCKS proxy")
        print("  python -m libtor --socks 1080        # Start SOCKS on port 1080")
        print("  python -m libtor fetch <url>        # Fetch URL through Tor")
        print("  python -m libtor resolve <hostname>  # Resolve hostname through Tor")
        print()
        print("Configuration: Use config.yml or environment variables")

    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
