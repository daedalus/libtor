"""Tests for configuration module."""

import os

import yaml

from libtor.config import (
    Config,
    DirectoryConfig,
    SOCKSConfig,
    TorConfig,
    setup_logging,
)


class TestTorConfig:
    """Test TorConfig dataclass."""

    def test_defaults(self):
        config = TorConfig()
        assert config.hops == 3
        assert config.timeout == 30.0
        assert config.directory_timeout == 30.0
        assert config.guard_state_file is None  # Stored in libtor.db

    def test_custom(self):
        config = TorConfig(hops=2, timeout=60.0)
        assert config.hops == 2
        assert config.timeout == 60.0


class TestSOCKSConfig:
    """Test SOCKSConfig dataclass."""

    def test_defaults(self):
        config = SOCKSConfig()
        assert config.enabled is False
        assert config.host == "127.0.0.1"
        assert config.port == 1080

    def test_custom(self):
        config = SOCKSConfig(enabled=True, host="0.0.0.0", port=9050)
        assert config.enabled is True
        assert config.host == "0.0.0.0"
        assert config.port == 9050


class TestDirectoryConfig:
    """Test DirectoryConfig dataclass."""

    def test_defaults(self):
        config = DirectoryConfig()
        assert config.fallback_dirs == []
        assert config.min_bandwidth_guard == 100
        assert config.min_bandwidth_exit == 50
        assert config.require_stable_exits is False


class TestConfigFromDict:
    """Test Config.from_dict()."""

    def test_full_config(self):
        data = {
            "tor": {
                "hops": 2,
                "timeout": 60.0,
                "directory_timeout": 120.0,
                "guard_state_file": "/tmp/guard.json",
            },
            "socks": {
                "enabled": True,
                "host": "0.0.0.0",
                "port": 9050,
            },
            "directory": {
                "min_bandwidth_guard": 500,
                "min_bandwidth_exit": 200,
                "require_stable_exits": True,
            },
            "logging": {
                "level": "DEBUG",
                "file": "/var/log/libtor.log",
            },
        }

        config = Config.from_dict(data)

        assert config.tor.hops == 2
        assert config.tor.timeout == 60.0
        assert config.socks.enabled is True
        assert config.socks.port == 9050
        assert config.directory.require_stable_exits is True
        assert config.log_level == "DEBUG"

    def test_partial_config(self):
        data = {
            "tor": {
                "hops": 4,
            },
            "socks": {
                "port": 1081,
            },
        }

        config = Config.from_dict(data)

        assert config.tor.hops == 4
        assert config.tor.timeout == 30.0  # default
        assert config.socks.port == 1081
        assert config.socks.host == "127.0.0.1"  # default


class TestConfigFromFile:
    """Test Config.from_file()."""

    def test_load_from_file(self, tmp_path):
        config_file = tmp_path / "config.yml"
        config_data = {
            "tor": {"hops": 2},
            "socks": {"enabled": True, "port": 9050},
        }

        with open(config_file, "w") as f:
            yaml.dump(config_data, f)

        config = Config.from_file(config_file)

        assert config.tor.hops == 2
        assert config.socks.enabled is True
        assert config.socks.port == 9050

    def test_missing_file(self, tmp_path):
        config = Config.from_file(tmp_path / "nonexistent.yml")
        # Should return default config
        assert config.tor.hops == 3


class TestConfigFromEnv:
    """Test Config.from_env()."""

    def test_env_overrides(self, monkeypatch):
        monkeypatch.setenv("LIBTOR_HOPS", "4")
        monkeypatch.setenv("LIBTOR_TIMEOUT", "120.0")
        monkeypatch.setenv("LIBTOR_SOCKS_ENABLED", "true")
        monkeypatch.setenv("LIBTOR_SOCKS_PORT", "1081")
        monkeypatch.setenv("LIBTOR_LOG_LEVEL", "DEBUG")

        config = Config.from_env()

        assert config.tor.hops == 4
        assert config.tor.timeout == 120.0
        assert config.socks.enabled is True
        assert config.socks.port == 1081
        assert config.log_level == "DEBUG"

    def test_env_not_set(self, monkeypatch):
        # Ensure no env vars are set
        for key in list(os.environ.keys()):
            if key.startswith("LIBTOR_"):
                monkeypatch.delenv(key)

        config = Config.from_env()

        # Should have defaults
        assert config.tor.hops == 3
        assert config.socks.enabled is False


class TestConfigFromDefaultLocations:
    """Test Config.from_default_locations()."""

    def test_search_paths(self, tmp_path, monkeypatch):
        # Create config in current directory
        config_file = tmp_path / "config.yml"
        with open(config_file, "w") as f:
            yaml.dump({"tor": {"hops": 5}}, f)

        # Change to tmp directory
        monkeypatch.chdir(tmp_path)

        config = Config.from_default_locations()
        assert config.tor.hops == 5

    def test_env_var(self, tmp_path, monkeypatch):
        config_file = tmp_path / "my_config.yml"
        with open(config_file, "w") as f:
            yaml.dump({"tor": {"hops": 6}}, f)

        monkeypatch.setenv("LIBTOR_CONFIG", str(config_file))

        config = Config.from_default_locations()
        assert config.tor.hops == 6


class TestConfigToDict:
    """Test Config.to_dict()."""

    def test_to_dict(self):
        config = Config()
        config.tor.hops = 2
        config.socks.enabled = True
        config.socks.port = 9050

        data = config.to_dict()

        assert data["tor"]["hops"] == 2
        assert data["socks"]["enabled"] is True
        assert data["socks"]["port"] == 9050


class TestConfigSave:
    """Test Config.save()."""

    def test_save(self, tmp_path):
        config = Config()
        config.tor.hops = 7
        config.socks.port = 9999

        config_file = tmp_path / "saved.yml"
        config.save(config_file)

        # Should be able to load it back
        loaded = Config.from_file(config_file)
        assert loaded.tor.hops == 7
        assert loaded.socks.port == 9999


class TestSetupLogging:
    """Test setup_logging()."""

    def test_setup_logging(self):
        config = Config()
        config.log_level = "DEBUG"

        # Reset root logger
        logging.root.setLevel(logging.NOTSET)
        for h in logging.root.handlers[:]:
            logging.root.removeHandler(h)

        setup_logging(config)

        # Should have debug level
        assert logging.root.level == logging.DEBUG

    def test_setup_logging_to_file(self, tmp_path):
        config = Config()
        config.log_level = "INFO"
        log_file = tmp_path / "test.log"
        config.log_file = str(log_file)

        # Reset root logger
        logging.root.setLevel(logging.NOTSET)
        for h in logging.root.handlers[:]:
            logging.root.removeHandler(h)

        setup_logging(config)

        # File handler should be added
        assert any(isinstance(h, logging.FileHandler) for h in logging.root.handlers)


import logging
