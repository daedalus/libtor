"""
Configuration management for libtor.

Supports:
  - YAML configuration files
  - Environment variable overrides
  - Default values
"""

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)


@dataclass
class TorConfig:
    """Tor client configuration."""

    hops: int = 3
    timeout: float = 30.0
    directory_timeout: float = 30.0
    guard_state_file: str | None = None


@dataclass
class SOCKSConfig:
    """SOCKS proxy server configuration."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 1080


@dataclass
class DirectoryConfig:
    """Directory client configuration."""

    fallback_dirs: list[tuple[str, int]] = field(default_factory=list)
    min_bandwidth_guard: int = 100
    min_bandwidth_exit: int = 50
    require_stable_exits: bool = False


@dataclass
class Config:
    """
    Main configuration class.

    Usage:
        config = Config.from_file("config.yml")
        config = Config.from_env()
        config = Config()  # defaults
    """

    tor: TorConfig = field(default_factory=TorConfig)
    socks: SOCKSConfig = field(default_factory=SOCKSConfig)
    directory: DirectoryConfig = field(default_factory=DirectoryConfig)

    # Logging
    log_level: str = "INFO"
    log_file: str | None = None

    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
        """Load configuration from a YAML file."""
        path = Path(path)
        if not path.exists():
            log.warning("Config file not found: %s, using defaults", path)
            return cls()

        try:
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            return cls.from_dict(data)
        except Exception as exc:
            log.error("Failed to load config from %s: %s", path, exc)
            return cls()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Config":
        """Create Config from a dictionary."""
        config = cls()

        # Tor config
        if "tor" in data:
            tor_data = data["tor"]
            config.tor = TorConfig(
                hops=tor_data.get("hops", config.tor.hops),
                timeout=tor_data.get("timeout", config.tor.timeout),
                directory_timeout=tor_data.get(
                    "directory_timeout", config.tor.directory_timeout
                ),
                guard_state_file=tor_data.get(
                    "guard_state_file", config.tor.guard_state_file
                ),
            )

        # SOCKS config
        if "socks" in data:
            socks_data = data["socks"]
            config.socks = SOCKSConfig(
                enabled=socks_data.get("enabled", config.socks.enabled),
                host=socks_data.get("host", config.socks.host),
                port=socks_data.get("port", config.socks.port),
            )

        # Directory config
        if "directory" in data:
            dir_data = data["directory"]
            config.directory = DirectoryConfig(
                min_bandwidth_guard=dir_data.get(
                    "min_bandwidth_guard", config.directory.min_bandwidth_guard
                ),
                min_bandwidth_exit=dir_data.get(
                    "min_bandwidth_exit", config.directory.min_bandwidth_exit
                ),
                require_stable_exits=dir_data.get(
                    "require_stable_exits", config.directory.require_stable_exits
                ),
            )

        # Logging config
        if "logging" in data:
            log_data = data["logging"]
            config.log_level = log_data.get("level", config.log_level)
            config.log_file = log_data.get("file", config.log_file)

        return config

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        config = cls()

        # TOR_HOPS
        if hops := os.environ.get("LIBTOR_HOPS"):
            config.tor.hops = int(hops)

        # TOR_TIMEOUT
        if timeout := os.environ.get("LIBTOR_TIMEOUT"):
            config.tor.timeout = float(timeout)

        # TOR_DIRECTORY_TIMEOUT
        if directory_timeout := os.environ.get("LIBTOR_DIRECTORY_TIMEOUT"):
            config.tor.directory_timeout = float(directory_timeout)

        # TOR_GUARD_STATE_FILE
        if guard_state_file := os.environ.get("LIBTOR_GUARD_STATE_FILE"):
            config.tor.guard_state_file = guard_state_file

        # SOCKS_ENABLED
        if socks_enabled := os.environ.get("LIBTOR_SOCKS_ENABLED"):
            config.socks.enabled = socks_enabled.lower() in ("1", "true", "yes")

        # SOCKS_HOST
        if socks_host := os.environ.get("LIBTOR_SOCKS_HOST"):
            config.socks.host = socks_host

        # SOCKS_PORT
        if socks_port := os.environ.get("LIBTOR_SOCKS_PORT"):
            config.socks.port = int(socks_port)

        # LOG_LEVEL
        if log_level := os.environ.get("LIBTOR_LOG_LEVEL"):
            config.log_level = log_level.upper()

        return config

    @classmethod
    def from_default_locations(cls) -> "Config":
        """Search for config file in default locations."""
        search_paths = [
            Path.cwd() / "config.yml",
            Path.cwd() / "config.yaml",
            Path.home() / ".libtor" / "config.yml",
            Path.home() / ".libtor" / "config.yaml",
            Path("/etc/libtor/config.yml"),
            Path("/etc/libtor/config.yaml"),
        ]

        for path in search_paths:
            if path.exists():
                log.info("Loading config from: %s", path)
                return cls.from_file(path)

        # Try environment variable
        if env_path := os.environ.get("LIBTOR_CONFIG"):
            return cls.from_file(env_path)

        # Try to load from env
        config = cls.from_env()
        if any(
            os.environ.get(name)
            for name in [
                "LIBTOR_HOPS",
                "LIBTOR_SOCKS_ENABLED",
                "LIBTOR_LOG_LEVEL",
            ]
        ):
            log.info("Using configuration from environment variables")

        return config

    def to_dict(self) -> dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "tor": {
                "hops": self.tor.hops,
                "timeout": self.tor.timeout,
                "directory_timeout": self.tor.directory_timeout,
                "guard_state_file": self.tor.guard_state_file,
            },
            "socks": {
                "enabled": self.socks.enabled,
                "host": self.socks.host,
                "port": self.socks.port,
            },
            "directory": {
                "min_bandwidth_guard": self.directory.min_bandwidth_guard,
                "min_bandwidth_exit": self.directory.min_bandwidth_exit,
                "require_stable_exits": self.directory.require_stable_exits,
            },
            "logging": {
                "level": self.log_level,
                "file": self.log_file,
            },
        }

    def save(self, path: str | Path) -> None:
        """Save configuration to a YAML file."""
        path = Path(path)
        with open(path, "w") as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False)
        log.info("Configuration saved to: %s", path)


def setup_logging(config: Config) -> None:
    """Configure logging based on config."""
    level = getattr(logging, config.log_level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler()]

    if config.log_file:
        handlers.append(logging.FileHandler(config.log_file))

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=handlers,
    )
