"""
Directory client – fetches and parses the Tor network consensus.

References:
  - dir-spec.txt §3 (Consensus documents)
  - dir-spec.txt §4 (Router descriptors)
  - dir-spec.txt §6 (Microdescriptors)

Implements a directory cache for obtaining fresh relay descriptors and ntor keys.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime

from .exceptions import DirectoryError
from .logging_ import trace, debug, setup_logging

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hard-coded directory authorities (from src/app/config/auth_dirs.inc)
# These are the well-known directory authorities operated by the Tor Project.
# ---------------------------------------------------------------------------

DIRECTORY_AUTHORITIES = [
    ("moria1", "128.31.0.39", 9131),
    ("tor26", "86.59.21.38", 80),
    ("dizum", "194.109.206.212", 80),
    ("gabelmoo", "131.188.40.189", 80),
    ("dannenberg", "193.23.244.244", 80),
    ("maatuska", "171.25.193.9", 80),
    ("Faravahar", "154.35.175.225", 80),
    ("longclaw", "199.58.81.140", 80),
    ("bastet", "204.13.164.118", 80),
]

# Fallback directory mirrors (subset – for consensus fetching)
FALLBACK_DIRS = [
    ("128.31.0.39", 9131),  # moria1 - works for microdesc
    ("185.220.101.47", 80),
    ("45.66.33.45", 80),
    ("193.187.88.42", 80),
    ("51.77.234.247", 80),
]

# Directory servers for descriptor fetching (using fallback dirs)
DIR_SERVERS = FALLBACK_DIRS


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class RouterInfo:
    """Describes a single Tor relay from the consensus."""

    nickname: str
    identity: bytes  # 20-byte SHA-1 fingerprint (raw)
    digest: bytes  # 20-byte descriptor digest
    address: str
    or_port: int
    dir_port: int
    flags: list[str] = field(default_factory=list)
    bandwidth: int = 0
    ntor_onion_key: bytes | None = None  # 32-byte Curve25519 key
    version: str = ""
    microdesc_digest: str | None = (
        None  # base64-encoded microdesc digest (for fetching microdesc)
    )
    exit_policy_summary: str | None = (
        None  # exit policy summary: "accept portlist" or "reject portlist"
    )
    _descriptor: "RouterDescriptor | None" = field(
        default_factory=lambda: None, repr=False
    )
    _exit_policy: list[tuple[str, str, str]] | None = field(
        default_factory=lambda: None, repr=False
    )

    @property
    def identity_hex(self) -> str:
        return self.identity.hex().upper()

    @property
    def descriptor(self) -> "RouterDescriptor | None":
        """Lazily fetch and cache the router descriptor (containing ntor key)."""
        if self._descriptor is not None:
            return self._descriptor
        return None

    @property
    def is_guard(self) -> bool:
        return "Guard" in self.flags

    @property
    def is_exit(self) -> bool:
        return "Exit" in self.flags

    @property
    def is_fast(self) -> bool:
        return "Fast" in self.flags

    @property
    def is_stable(self) -> bool:
        return "Stable" in self.flags

    @property
    def is_valid(self) -> bool:
        return "Valid" in self.flags

    def can_exit_to(self, port: int, target_ip: str | None = None) -> bool:
        """Check if this relay can exit to the given port.

        Parses the exit policy summary (p line) from consensus.
        Returns True if the policy accepts the port, False if rejected.

        Format: "accept portlist" or "reject portlist"
        PortList is comma-separated ranges, e.g., "80,443,8080-8090"
        """
        if self.exit_policy_summary is None:
            return False

        try:
            action, portlist = self.exit_policy_summary.split(" ", 1)
            return self._check_port_in_list(port, portlist, accept=(action == "accept"))
        except Exception:
            return False

    def _check_port_in_list(self, port: int, portlist: str, accept: bool) -> bool:
        """Check if a port is in the port list.

        PortList format: comma-separated list of ports and ranges
        e.g., "80,443,8080-8090"

        Default is accept if no rule matches (per Tor spec).
        """
        default_accept = True  # Per Tor spec: if no rule matches, accept
        if not portlist or portlist == "*":
            return accept if not accept else True  # accept *:* or reject *:*

        for part in portlist.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = part.split("-", 1)
                    if start.isdigit() and end.isdigit():
                        if start.isdigit() and end.isdigit():
                            if start.isdigit() and end.isdigit():
                                if int(start) <= port <= int(end):
                                    return accept
                except ValueError:
                    continue
            else:
                if part.isdigit():
                    if int(part) == port:
                        return accept

        return default_accept

    async def fetch_exit_policy(
        self, directory_servers: list
    ) -> list[tuple[str, int, str]] | None:
        """Fetch exit policy from server descriptor.

        Returns list of (action, address_pattern, port_pattern) tuples.
        """
        if self._exit_policy is not None:
            return self._exit_policy

        from .directory import ServerDescParser

        for ds in directory_servers:
            if len(ds) == 2:
                host, port = ds
            else:
                _, host, port = ds

            try:
                client = DirectoryClient(timeout=10)
                text, _ = await client._http_get(
                    host, port, f"/tor/server/fp/{self.identity_hex}"
                )
                if text:
                    self._exit_policy = ServerDescParser.extract_exit_policy(text)
                    return self._exit_policy
            except Exception:
                continue

        return None

    def can_exit_to(self, port: int, target_ip: str | None = None) -> bool:
        """Check if this relay can exit to the given port.

        First tries to use the exit policy from server descriptor (if fetched).
        Falls back to exit_policy_summary from consensus.
        Returns True if policy allows, False if rejected.
        """
        # Try full policy from server descriptor first
        if self._exit_policy is not None:
            return self._check_exit_policy(port, target_ip, self._exit_policy)

        # Try summary from consensus
        if self.exit_policy_summary is not None:
            try:
                action, portlist = self.exit_policy_summary.split(" ", 1)
                return self._check_port_in_list(
                    port, portlist, accept=(action == "accept")
                )
            except Exception:
                pass

        # If no policy info, assume can exit (optimistic)
        return True

    def _check_exit_policy(
        self, port: int, target_ip: str | None, policy: list[tuple[str, str, str]]
    ) -> bool:
        """Check exit policy for given port and IP.

        Per Tor spec: rules are evaluated in order, first match wins.
        If no rule matches, the default is ACCEPT.
        """
        default_accept = True

        for action, addr_pattern, port_pattern in policy:
            # Check address pattern (simplified: just check if it matches target_ip)
            # For now, we just check port since addr_pattern is complex
            # TODO: implement proper address pattern matching

            # Check port pattern
            if not self._check_port_in_pattern(port, port_pattern):
                continue

            # Match found
            return action == "accept"

        return default_accept

    def _check_port_in_pattern(self, port: int, port_pattern: str) -> bool:
        """Check if a port matches a port pattern.

        Patterns can be:
        - A single port: "80"
        - A range: "80-443"
        - A wildcard: "*"
        """
        port_pattern = port_pattern.strip()

        if port_pattern == "*":
            return True

        if "-" in port_pattern:
            try:
                start, end = port_pattern.split("-", 1)
                return int(start) <= port <= int(end)
            except ValueError:
                return False
        else:
            try:
                return int(port_pattern) == port
            except ValueError:
                return False

    def __repr__(self) -> str:
        return (
            f"<RouterInfo {self.nickname} {self.address}:{self.or_port} "
            f"flags={','.join(self.flags)}>"
        )

    async def fetch_descriptor(
        self, directory_servers: list
    ) -> "RouterDescriptor | None":
        """Lazily fetch router descriptor to get ntor key.

        Per torpy approach: fetch on-demand when the key is needed.
        """
        if self._descriptor is not None:
            return self._descriptor

        from .directory import ServerDescParser

        for ds in directory_servers:
            if len(ds) == 2:
                host, port = ds
            else:
                _, host, port = ds

            try:
                from .directory import DirectoryClient

                client = DirectoryClient(timeout=10)
                text, _ = await client._http_get(
                    host, port, f"/tor/server/fp/{self.identity_hex}"
                )
                if text:
                    ntor_key = ServerDescParser.extract_ntor_key(text)
                    if ntor_key:
                        self._descriptor = RouterDescriptor(ntor_key=ntor_key)
                        return self._descriptor
            except Exception:
                continue

        return None

    def get_ntor_key(self) -> bytes | None:
        """Get cached ntor key from descriptor."""
        if self._descriptor is not None:
            return self._descriptor.ntor_key
        return self.ntor_onion_key


# ---------------------------------------------------------------------------
# Guard state persistence
# ---------------------------------------------------------------------------


@dataclass
class GuardState:
    """Persistent guard selection state per tor-spec §2.3.

    Stored and loaded to maintain consistent guard selection across runs.
    Stored in libtor.db by default.
    """

    filename: str = "guard_state.json"

    guards: list[str] = field(default_factory=list)  # List of identity_hex
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Parameters controlling guard selection
    USE_SECONDS: int = 2592000  # 30 days
    TOTAL_TIMEOUT: int = 900  # 15 minutes
    FAIL_TIMEOUT: int = 900  # 15 minutes
    MAX_ADVERTISED_BANDWIDTH: int = 2000000

    # Sample period for testing reachability
    TESTING_ENABLE: int = 0
    SAMPLE_PERIOD: int = 86400
    SAMPLE_SIZE: int = 3

    def add_guard(self, identity_hex: str) -> None:
        """Add a guard to the persistent list."""
        if identity_hex not in self.guards:
            self.guards.insert(0, identity_hex)
            # Keep max 60 guards (per spec)
            if len(self.guards) > 60:
                self.guards = self.guards[:60]
            self.timestamp = datetime.now(UTC)

    def remove_guard(self, identity_hex: str) -> None:
        """Remove a guard (e.g., due to failures)."""
        if identity_hex in self.guards:
            self.guards.remove(identity_hex)
            self.timestamp = datetime.now(UTC)

    def save(
        self, conn: sqlite3.Connection | None = None, path: str | None = None
    ) -> None:
        """Save guard state to database or file."""
        if conn is not None:
            try:
                conn.execute(
                    """INSERT OR REPLACE INTO guard_state
                       (id, guards, timestamp, use_seconds, total_timeout, fail_timeout)
                       VALUES (1, ?, ?, ?, ?, ?)""",
                    (
                        json.dumps(self.guards),
                        self.timestamp.isoformat(),
                        self.USE_SECONDS,
                        self.TOTAL_TIMEOUT,
                        self.FAIL_TIMEOUT,
                    ),
                )
                conn.commit()
                log.debug("Guard state saved to database")
            except Exception as exc:
                log.warning("Failed to save guard state to DB: %s", exc)
        else:
            filepath = path or self.filename
            data = {
                "guards": self.guards,
                "timestamp": self.timestamp.isoformat(),
                "USE_SECONDS": self.USE_SECONDS,
                "TOTAL_TIMEOUT": self.TOTAL_TIMEOUT,
                "FAIL_TIMEOUT": self.FAIL_TIMEOUT,
            }
            try:
                with open(filepath, "w") as f:
                    json.dump(data, f, indent=2)
                log.debug("Guard state saved to %s", filepath)
            except Exception as exc:
                log.warning("Failed to save guard state: %s", exc)

    @classmethod
    def load(
        cls, conn: sqlite3.Connection | None = None, path: str | None = None
    ) -> "GuardState":
        """Load guard state from database or file, or return empty state."""
        if conn is not None:
            try:
                cursor = conn.execute(
                    "SELECT guards, timestamp, use_seconds, total_timeout, fail_timeout FROM guard_state WHERE id = 1"
                )
                row = cursor.fetchone()
                if row:
                    state = cls()
                    state.guards = json.loads(row[0])
                    state.timestamp = datetime.fromisoformat(row[1])
                    state.USE_SECONDS = row[2] or 2592000
                    state.TOTAL_TIMEOUT = row[3] or 900
                    state.FAIL_TIMEOUT = row[4] or 900
                    log.debug(
                        "Guard state loaded from database: %d guards", len(state.guards)
                    )
                    return state
            except Exception as exc:
                log.warning("Failed to load guard state from DB: %s", exc)
            return cls()

        filepath = path or cls().filename
        if not os.path.exists(filepath):
            return cls()
        try:
            with open(filepath) as f:
                data = json.load(f)
            state = cls()
            state.guards = data.get("guards", [])
            ts = data.get("timestamp")
            if ts:
                state.timestamp = datetime.fromisoformat(ts)
            log.debug(
                "Guard state loaded from %s: %d guards", filepath, len(state.guards)
            )
            return state
        except Exception as exc:
            log.warning("Failed to load guard state: %s", exc)
            return cls()


class GuardSelection:
    """
    Guard selection algorithm per tor-spec §2.3.

    Maintains a persistent list of guards and selects from them weighted by
    bandwidth, preferring to keep the same guards across sessions.
    """

    def __init__(
        self,
        state: GuardState | None = None,
        conn: sqlite3.Connection | None = None,
        state_file: str | None = None,
    ):
        self._conn = conn
        self._state = state or GuardState.load(conn=conn, path=state_file)
        self._state_file = state_file or self._state.filename

    @property
    def state(self) -> GuardState:
        return self._state

    def save(self) -> None:
        """Persist guard state to database or file."""
        self._state.save(conn=self._conn, path=self._state_file)

    def select(
        self,
        routers: list[RouterInfo],
    ) -> RouterInfo | None:
        """
        Select a guard relay.

        Args:
            routers: Available routers from consensus

        Returns:
            Selected RouterInfo or None if no guards available
        """
        # Filter to valid guards
        guards = [
            r
            for r in routers
            if r.is_guard and r.is_fast and r.is_valid and r.bandwidth > 0
        ]

        if not guards:
            return None

        # If we have persistent guards, prioritize them
        persistent_hex = set(self._state.guards)
        persistent_guards = [r for r in guards if r.identity_hex in persistent_hex]

        # If we have persistent guards still marked as Guard, use them
        if persistent_guards:
            return self._weighted_choice(persistent_guards)

        # Otherwise select from all valid guards and update state
        selected = self._weighted_choice(guards)
        if selected:
            self._state.add_guard(selected.identity_hex)
            self.save()

        return selected

    def record_failure(self, identity_hex: str) -> None:
        """
        Record a guard failure and possibly remove the guard.

        Per Tor C implementation (entrynodes.c: entry_guard_failed):
        - Called when a circuit fails at the first hop
        - Marks the guard as failed in the guard selection
        - Guard will be retried after a cooldown period

        Our implementation:
        - Removes guard from persistent list (like Tor)
        - Saves state for persistence across runs
        """
        self._state.remove_guard(identity_hex)
        self.save()
        log.info("Guard %s removed due to failure", identity_hex[:16])

    def record_handshake_failure(self, identity_hex: str) -> None:
        """
        Record a handshake failure for a guard.

        Called when ntor handshake fails (typically stale key).
        Similar to entry_guard_failed() in Tor but specific to key failures.

        Per Tor C implementation:
        - circuit_build_failed() -> entry_guard_failed() -> entry_guards_note_guard_failure()
        - Guard is marked as failed and circuit retries with different guard
        """
        self._state.remove_guard(identity_hex)
        self.save()
        log.info(
            "Guard %s removed due to handshake failure (stale ntor key?)",
            identity_hex[:16],
        )

    def _weighted_choice(self, relays: list[RouterInfo]) -> RouterInfo | None:
        """Select a relay weighted by bandwidth."""
        if not relays:
            return None
        if len(relays) == 1:
            return relays[0]
        total = sum(r.bandwidth for r in relays)
        if total == 0:
            return random.choice(relays)
        pick = random.randint(0, total - 1)
        acc = 0
        for r in relays:
            acc += r.bandwidth
            if acc > pick:
                return r
        return relays[-1]


# ---------------------------------------------------------------------------
# Consensus parser
# ---------------------------------------------------------------------------


class ConsensuParser:
    """Parse a Tor network-status consensus document (v3)."""

    # Regex patterns
    # r line format: r nickname identity digest timestamp IP or_port dir_port
    # timestamp can be "2026-03-30 17:26:18" (space) or "2026-03-30T17:26:18" (T)
    # We capture timestamp as a single group (allowing either format)
    _RE_R = re.compile(r"^r (\S+) (\S+) (\S+) (\S+(?:\s+\S+)?) (\S+) (\d+) (\d+)")
    _RE_S = re.compile(r"^s (.+)")
    _RE_W = re.compile(r"^w Bandwidth=(\d+)")
    _RE_M = re.compile(r"^m ([A-Za-z0-9]+)")  # microdesc digest (base64, no trailing =)
    _RE_P = re.compile(r"^p (accept|reject) (.+)")  # exit policy summary

    @classmethod
    def parse(cls, text: str) -> list[RouterInfo]:
        """Return a list of RouterInfo from a consensus document."""
        routers: list[RouterInfo] = []
        current: RouterInfo | None = None

        for line in text.splitlines():
            m = cls._RE_R.match(line)
            if m:
                if current is not None:
                    routers.append(current)
                nickname = m.group(1)
                try:
                    identity = base64.b64decode(m.group(2) + "==")
                    digest = base64.b64decode(m.group(3) + "==")
                except Exception:
                    current = None
                    continue
                # group(4) is timestamp - we don't need it
                address = m.group(5)
                or_port = int(m.group(6))
                dir_port = int(m.group(7))
                current = RouterInfo(
                    nickname=nickname,
                    identity=identity,
                    digest=digest,
                    address=address,
                    or_port=or_port,
                    dir_port=dir_port,
                )
                continue

            if current is None:
                continue

            m = cls._RE_S.match(line)
            if m:
                current.flags = m.group(1).split()
                continue

            m = cls._RE_W.match(line)
            if m:
                current.bandwidth = int(m.group(1))
                continue

            # Parse microdescriptor digest from "m" line
            m_match = cls._RE_M.match(line)
            if m_match:
                # Store the microdesc digest in the router's digest field
                # (we'll use it to fetch the microdescriptor later)
                current.microdesc_digest = m_match.group(1)
                continue

            # Parse exit policy summary from "p" line
            p_match = cls._RE_P.match(line)
            if p_match:
                current.exit_policy_summary = f"{p_match.group(1)} {p_match.group(2)}"
                continue

        if current is not None:
            routers.append(current)

        return routers


# ---------------------------------------------------------------------------
# Router descriptor (lazy-fetched for ntor key)
# ---------------------------------------------------------------------------


@dataclass
class RouterDescriptor:
    """Router descriptor containing ntor onion key.

    Lazily fetched when needed (like torpy's approach).
    """

    ntor_key: bytes | None = None
    onion_key: bytes | None = None  # Legacy RSA key (not used in ntor handshake)


# ---------------------------------------------------------------------------
# Server descriptor parser (ntor key extraction)
# ---------------------------------------------------------------------------


class ServerDescParser:
    """Extract ntor-onion-key from a server descriptor."""

    _RE_NTOR = re.compile(r"^ntor-onion-key (\S+)")
    _RE_ACCEPT = re.compile(r"^accept (\S+):(\S+)")
    _RE_REJECT = re.compile(r"^reject (\S+):(\S+)")

    @classmethod
    def extract_ntor_key(cls, text: str) -> bytes | None:
        for line in text.splitlines():
            m = cls._RE_NTOR.match(line)
            if m:
                try:
                    return base64.b64decode(m.group(1) + "==")
                except Exception:
                    return None
        return None

    @classmethod
    def extract_exit_policy(cls, text: str) -> list[tuple[str, str, str]]:
        """Extract exit policy from server descriptor.

        Returns list of (action, address_pattern, port_pattern) tuples.
        """
        policy = []
        for line in text.splitlines():
            m = cls._RE_ACCEPT.match(line)
            if m:
                policy.append(("accept", m.group(1), m.group(2)))
                continue
            m = cls._RE_REJECT.match(line)
            if m:
                policy.append(("reject", m.group(1), m.group(2)))
        return policy


# ---------------------------------------------------------------------------
# Microdescriptor parser (ntor key extraction)
# ---------------------------------------------------------------------------


class MicrodescParser:
    """Extract ntor-onion-key from a microdescriptor."""

    _RE_NTOR = re.compile(r"^ntor-onion-key (\S+)")

    @classmethod
    def extract_ntor_key(cls, text: str) -> bytes | None:
        for line in text.splitlines():
            m = cls._RE_NTOR.match(line)
            if m:
                try:
                    return base64.b64decode(m.group(1) + "==")
                except Exception:
                    return None
        return None


# ---------------------------------------------------------------------------
# Directory client
# ---------------------------------------------------------------------------


class DirectoryClient:
    """
    Async directory client.

    Fetches the consensus and (optionally) individual microdescriptors.
    """

    CONSENSUS_PATH = "/tor/status-vote/current/consensus"
    CONSENSUS_MICRO_PATH = "/tor/status-vote/current/consensus-microdesc"
    MICRO_PATH = "/tor/micro/d/"
    CONSENSUS_TTL = 3600  # Cache consensus for 1 hour

    def __init__(
        self, timeout: float = 30.0, desc_cache: "DescriptorCache | None" = None
    ):
        self._timeout = timeout
        self._routers: list[RouterInfo] = []
        self._consensus_cache: tuple[float, list[RouterInfo]] | None = None
        self._desc_cache = desc_cache

    @property
    def routers(self) -> list[RouterInfo]:
        return self._routers

    def _get_cached_consensus(self) -> list[RouterInfo] | None:
        """Return cached consensus if not expired."""
        # Try in-memory cache first
        if self._consensus_cache is not None:
            cached_time, routers = self._consensus_cache
            if time.time() - cached_time < self.CONSENSUS_TTL:
                return routers

        # Try loading from database
        if self._desc_cache:
            cached = self._desc_cache.load_consensus()
            if cached:
                data, fetched_at = cached
                try:
                    routers = ConsensuParser.parse(data)
                    if routers:
                        self._consensus_cache = (fetched_at, routers)
                        self._routers = routers
                        return routers
                except Exception as exc:
                    log.debug("Failed to parse cached consensus: %s", exc)

        return None

    def _set_cached_consensus(
        self, routers: list[RouterInfo], raw_text: str = "", max_age: int | None = None
    ) -> None:
        """Cache the consensus with current timestamp."""
        self._consensus_cache = (time.time(), routers)
        self._routers = routers

        # Save to database if we have raw text
        if self._desc_cache and raw_text:
            ttl = max_age if max_age is not None else self.CONSENSUS_TTL
            self._desc_cache.save_consensus(raw_text, ttl)

    # ---- public API -------------------------------------------------------

    async def fetch_consensus(
        self,
        authorities: list[tuple[str, str, int]] | None = None,
        force_refresh: bool = False,
    ) -> list[RouterInfo]:
        """
        Fetch the consensus from directory authorities (or fallbacks).
        Returns a list of RouterInfo objects.

        First tries to fetch the microdescriptor consensus (has fresher ntor keys),
        then falls back to regular consensus if that's not available.

        Uses cached consensus if available and not expired.
        """
        # Check cache first
        if not force_refresh:
            cached = self._get_cached_consensus()
            if cached is not None:
                log.debug("Using cached consensus (%d routers)", len(cached))
                self._routers = cached
                return cached

        sources = list(authorities or DIRECTORY_AUTHORITIES)
        random.shuffle(sources)
        sources += FALLBACK_DIRS  # type: ignore[arg-type]

        # First try to get microdescriptor consensus (has fresher keys)
        for entry in sources:
            if len(entry) == 3:
                _name, host, port = entry
            else:
                host, port = entry

            try:
                log.debug("Fetching microdesc consensus from %s:%d", host, port)
                text, max_age = await self._http_get(
                    host, port, self.CONSENSUS_MICRO_PATH
                )
                routers = ConsensuParser.parse(text)
                if routers:
                    microdesc_count = sum(1 for r in routers if r.microdesc_digest)
                    log.info(
                        "Fetched microdesc consensus: %d relays (%d with microdesc digest) from %s:%d",
                        len(routers),
                        microdesc_count,
                        host,
                        port,
                    )
                    self._set_cached_consensus(routers, raw_text=text, max_age=max_age)
                    return routers
            except Exception as exc:
                log.debug(
                    "Microdesc consensus fetch from %s:%d failed: %s", host, port, exc
                )
                continue

        # Fall back to regular consensus
        for entry in sources:
            if len(entry) == 3:
                _name, host, port = entry
            else:
                host, port = entry

            try:
                log.debug("Fetching consensus from %s:%d", host, port)
                text, max_age = await self._http_get(host, port, self.CONSENSUS_PATH)
                routers = ConsensuParser.parse(text)
                if routers:
                    log.info(
                        "Fetched consensus: %d relays from %s:%d",
                        len(routers),
                        host,
                        port,
                    )
                    self._set_cached_consensus(routers, raw_text=text, max_age=max_age)
                    return routers
            except Exception as exc:
                log.debug("Consensus fetch from %s:%d failed: %s", host, port, exc)
                continue

        raise DirectoryError("Could not fetch consensus from any directory authority")

    async def fetch_ntor_key(
        self,
        router: RouterInfo,
        directory_host: str = "131.188.40.189",
        directory_port: int = 80,
    ) -> bytes | None:
        """
        Fetch the ntor-onion-key for a relay via its server descriptor.
        Returns the 32-byte key or None.
        """
        identity_hex = router.identity.hex().upper()
        path = f"/tor/server/fp/{identity_hex}"
        try:
            text, _ = await self._http_get(directory_host, directory_port, path)
            return ServerDescParser.extract_ntor_key(text)
        except Exception as exc:
            log.debug("Server desc fetch failed for %s: %s", router.nickname, exc)
            return None

    # ---- helpers ----------------------------------------------------------

    async def _http_get(self, host: str, port: int, path: str) -> str:
        """Minimal async HTTP/1.0 GET (no TLS – directory servers accept plain)."""
        request = (
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: libtor/0.1\r\n\r\n"
        ).encode()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self._timeout,
        )
        try:
            writer.write(request)
            await writer.drain()
            # Read until connection closes (dir servers use chunked or close after response)
            chunks = []
            while True:
                chunk = await asyncio.wait_for(
                    reader.read(65536),
                    timeout=self._timeout,
                )
                if not chunk:
                    break
                chunks.append(chunk)
            response = b"".join(chunks)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        text = response.decode("utf-8", errors="replace")
        # Strip HTTP headers
        if "\r\n\r\n" in text:
            _, _, body = text.partition("\r\n\r\n")
            return body
        return text

    # ---- router selection -------------------------------------------------

    def get_guards(self, min_bandwidth: int = 100) -> list[RouterInfo]:
        return [
            r
            for r in self._routers
            if r.is_guard and r.is_fast and r.is_valid and r.bandwidth >= min_bandwidth
        ]

    def get_middle_relays(self, min_bandwidth: int = 50) -> list[RouterInfo]:
        return [
            r
            for r in self._routers
            if r.is_fast and r.is_valid and r.bandwidth >= min_bandwidth
        ]

    def get_exits(
        self,
        min_bandwidth: int = 50,
        require_stable: bool = False,
    ) -> list[RouterInfo]:
        relays = [
            r
            for r in self._routers
            if r.is_exit and r.is_fast and r.is_valid and r.bandwidth >= min_bandwidth
        ]
        if require_stable:
            relays = [r for r in relays if r.is_stable]
        return relays

    def weighted_choice(self, relays: list[RouterInfo]) -> RouterInfo:
        """Select a relay weighted by bandwidth."""
        if not relays:
            raise DirectoryError("No relays available for selection")
        total = sum(r.bandwidth for r in relays) or len(relays)
        pick = random.randint(0, total - 1)
        acc = 0
        for r in relays:
            acc += r.bandwidth or 1
            if acc > pick:
                return r
        return relays[-1]


# ---------------------------------------------------------------------------
# Directory Cache for Fresh Descriptors (SQLite)
# ---------------------------------------------------------------------------

import sqlite3


@dataclass
class CachedDescriptor:
    """A cached server descriptor with ntor key."""

    identity: bytes  # 20-byte identity
    ntor_onion_key: bytes  # 32-byte Curve25519
    fetched_at: float  # Unix timestamp


class DescriptorCache:
    """
    Directory cache for obtaining fresh relay descriptors.

    Per dir-spec.txt:
    - Clients SHOULD cache descriptors and update them periodically
    - Descriptors should be refreshed when expired or when needed
    - Server descriptors contain the current ntor-onion-key

    Uses SQLite for persistence with TTL-based eviction.
    """

    # Cache TTL (seconds) - descriptors are valid for 24-48 hours
    CACHE_TTL = 12 * 60 * 60  # 12 hours

    # Stale key cooldown - don't retry for 1 hour after marking stale
    STALE_COOLDOWN = 60 * 60  # 1 hour

    # Maximum concurrent fetches
    MAX_CONCURRENT_FETCHES = 5

    # Unified cache DB location
    DEFAULT_CACHE_DB = "libtor.db"

    def __init__(self, timeout: float = 10.0, cache_file: str | None = None):
        self._timeout = timeout
        self._cache_db = cache_file or self.DEFAULT_CACHE_DB
        self._conn: sqlite3.Connection | None = None

        # Initialize database
        self._init_db()

    def _init_db(self) -> None:
        """Initialize SQLite database."""
        try:
            self._conn = sqlite3.connect(self._cache_db)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS ntor_keys (
                    identity BLOB PRIMARY KEY,
                    ntor_key BLOB NOT NULL,
                    fetched_at REAL NOT NULL
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS stale_keys (
                    identity BLOB PRIMARY KEY,
                    marked_at REAL NOT NULL,
                    cooldown_until REAL NOT NULL
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS consensus (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    data TEXT NOT NULL,
                    fetched_at REAL NOT NULL,
                    ttl INTEGER DEFAULT 3600
                )
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS guard_state (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    guards TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    use_seconds INTEGER DEFAULT 2592000,
                    total_timeout INTEGER DEFAULT 900,
                    fail_timeout INTEGER DEFAULT 900
                )
            """)
            self._conn.commit()

            # Evict expired entries and expired cooldowns
            self._evict_expired()

            log.debug("Initialized descriptor cache DB: %s", self._cache_db)
        except Exception as exc:
            log.warning("Failed to initialize cache DB: %s", exc)

    def _evict_expired(self) -> None:
        """Remove entries older than CACHE_TTL."""
        if not self._conn:
            return
        try:
            cutoff = time.time() - self.CACHE_TTL
            cursor = self._conn.execute(
                "DELETE FROM ntor_keys WHERE fetched_at < ?", (cutoff,)
            )
            if cursor.rowcount > 0:
                log.info("Evicted %d expired ntor keys", cursor.rowcount)
            self._conn.commit()
        except Exception as exc:
            log.warning("Failed to evict expired keys: %s", exc)

    def save_consensus(self, data: str, ttl: int = 3600) -> None:
        """Save consensus data to database with TTL."""
        if not self._conn:
            return
        try:
            self._conn.execute(
                "INSERT OR REPLACE INTO consensus (id, data, fetched_at, ttl) VALUES (1, ?, ?, ?)",
                (data, time.time(), ttl),
            )
            self._conn.commit()
            log.debug("Saved consensus to cache (TTL: %ds)", ttl)
        except Exception as exc:
            log.warning("Failed to save consensus: %s", exc)

    def load_consensus(self) -> tuple[str, float] | None:
        """Load consensus data from database if not expired."""
        if not self._conn:
            return None
        try:
            cursor = self._conn.execute(
                "SELECT data, fetched_at, ttl FROM consensus WHERE id = 1"
            )
            row = cursor.fetchone()
            if row:
                # Use stored TTL instead of hardcoded value
                ttl = row[2] if row[2] else 3600
                if (time.time() - row[1]) < ttl:
                    log.debug(
                        "Loaded consensus from cache (age: %.0fs, TTL: %ds)",
                        time.time() - row[1],
                        ttl,
                    )
                    return (row[0], row[1])
        except:
            pass
        return None

    @property
    def is_fresh(self) -> bool:
        """Check if the cache has recent data."""
        if not self._conn:
            return False
        try:
            cursor = self._conn.execute(
                "SELECT fetched_at FROM ntor_keys ORDER BY fetched_at DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if row:
                return (time.time() - row[0]) < self.CACHE_TTL
        except:
            pass
        return False

    def get_ntor_key(self, identity: bytes) -> bytes | None:
        """Get cached ntor key for a relay (excluding stale/expired keys)."""
        if not self._conn:
            return None

        # Check if marked as stale
        cursor = self._conn.execute(
            "SELECT 1 FROM stale_keys WHERE identity = ?", (identity,)
        )
        if cursor.fetchone():
            return None

        # Get key if not expired
        try:
            cursor = self._conn.execute(
                "SELECT ntor_key, fetched_at FROM ntor_keys WHERE identity = ?",
                (identity,),
            )
            row = cursor.fetchone()
            if row and (time.time() - row[1]) < self.CACHE_TTL:
                return row[0]
        except:
            pass
        return None

    def set_ntor_key(self, identity: bytes, ntor_key: bytes) -> None:
        """Cache an ntor key for a relay."""
        if not self._conn:
            return

        try:
            # Remove from stale if it was there
            self._conn.execute("DELETE FROM stale_keys WHERE identity = ?", (identity,))

            # Insert/update key
            self._conn.execute(
                "INSERT OR REPLACE INTO ntor_keys (identity, ntor_key, fetched_at) VALUES (?, ?, ?)",
                (identity, ntor_key, time.time()),
            )
            self._conn.commit()
        except Exception as exc:
            log.warning("Failed to save ntor key: %s", exc)

    def mark_stale(self, identity: bytes) -> None:
        """Mark a key as stale (handshake failed) with cooldown period."""
        if not self._conn:
            return

        try:
            now = time.time()
            cooldown_until = now + self.STALE_COOLDOWN
            self._conn.execute(
                "INSERT OR REPLACE INTO stale_keys (identity, marked_at, cooldown_until) VALUES (?, ?, ?)",
                (identity, now, cooldown_until),
            )
            self._conn.commit()
            log.info(
                "Marked ntor key for %s as stale (cooldown until %s)",
                identity.hex()[:16],
                time.strftime("%H:%M:%S", time.localtime(cooldown_until)),
            )
        except Exception as exc:
            log.warning("Failed to mark key as stale: %s", exc)

    def is_stale(self, identity: bytes) -> bool:
        """Check if a key is marked as stale and still in cooldown period."""
        if not self._conn:
            return False
        try:
            now = time.time()
            # Remove expired cooldowns
            self._conn.execute(
                "DELETE FROM stale_keys WHERE cooldown_until < ?", (now,)
            )
            # Check if still in cooldown
            cursor = self._conn.execute(
                "SELECT cooldown_until FROM stale_keys WHERE identity = ?", (identity,)
            )
            row = cursor.fetchone()
            if row:
                remaining = row[0] - now
                if remaining > 0:
                    log.debug(
                        "Key %s still in stale cooldown (%.0f min remaining)",
                        identity.hex()[:16],
                        remaining / 60,
                    )
                    return True
            return False
        except:
            return False

    def get_stale_count(self) -> int:
        """Return number of stale keys."""
        if not self._conn:
            return 0
        try:
            cursor = self._conn.execute("SELECT COUNT(*) FROM stale_keys")
            return cursor.fetchone()[0]
        except:
            return 0

    def get_key_count(self) -> int:
        """Return number of cached keys."""
        if not self._conn:
            return 0
        try:
            cursor = self._conn.execute("SELECT COUNT(*) FROM ntor_keys")
            return cursor.fetchone()[0]
        except:
            return 0

    @property
    def conn(self) -> sqlite3.Connection | None:
        """Return the database connection."""
        return self._conn

    def close(self) -> None:
        """Close database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    async def fetch_all_descriptors(
        self,
        routers: list[RouterInfo],
        directory_servers: list[tuple[str, str, int]],
    ) -> None:
        """
        Fetch server descriptors for routers from directory servers.

        This populates the cache with fresh ntor keys.
        Uses a small batch and short timeouts to avoid hanging.
        """
        if not routers:
            return

        log.info("Fetching descriptors for %d relays", len(routers))

        # Shuffle servers
        servers = list(directory_servers)
        random.shuffle(servers)

        # Fetch sequentially with short timeout
        fresh_count = 0
        for router in routers[:10]:  # Limit to first 10
            for name, host, port in servers[:3]:  # Try first 3 servers
                try:
                    debug(
                        f"DEBUG get_fresh_ntor_key: fetching from {host}:{port}",
                        flush=True,
                        file=sys.stderr,
                    )
                    md, _ = await self._http_get(
                        host, port, f"/tor/micro/d/{router.microdesc_digest}"
                    )
                    # Check for valid response - must start with HTTP/1.x 2xx
                    if (
                        md
                        and (md.startswith("HTTP/1.0 2") or md.startswith("HTTP/1.1 2"))
                        and len(md) > 100
                    ):
                        key = MicrodescParser.extract_ntor_key(md)
                        if key:
                            self.set_ntor_key(router.identity, key)
                            log.debug(
                                "Got ntor key from microdesc for %s", router.nickname
                            )
                            debug(
                                f"DEBUG get_fresh_ntor_key: got key from microdesc!",
                                flush=True,
                                file=sys.stderr,
                            )
                            return key
                    else:
                        debug(
                            f"DEBUG get_fresh_ntor_key: microdesc response invalid or empty",
                            flush=True,
                            file=sys.stderr,
                        )
                except Exception as e:
                    debug(
                        f"DEBUG get_fresh_ntor_key: microdesc fetch failed: {e}",
                        flush=True,
                        file=sys.stderr,
                    )
                    continue

        self._last_consensus = time.time()
        log.info(
            "Descriptor cache updated: %d/%d fresh keys",
            fresh_count,
            min(len(routers), 10),
        )

    async def get_fresh_ntor_key(
        self,
        router: RouterInfo,
        directory_servers: list[tuple[str, int]] | list[tuple[str, str, int]],
    ) -> bytes | None:
        """
        Get a fresh ntor key for a relay.

        First checks cache, then tries microdescriptor fetch (fresher), then falls back to server descriptor.

        Args:
            router: Router to get key for
            directory_servers: List of (host, port) or (name, host, port)
        """
        import sys

        debug(
            f"DEBUG get_fresh_ntor_key: starting for {router.nickname}",
            flush=True,
            file=sys.stderr,
        )

        # Check cache first
        cached_key = self.get_ntor_key(router.identity)
        debug(
            f"DEBUG get_fresh_ntor_key: cached_key={cached_key is not None}",
            flush=True,
            file=sys.stderr,
        )
        if cached_key:
            debug(
                f"DEBUG get_fresh_ntor_key: returning cached key!",
                flush=True,
                file=sys.stderr,
            )
            return cached_key

        # Try microdescriptor first (fresher keys)
        if router.microdesc_digest:
            debug(
                f"DEBUG get_fresh_ntor_key: trying microdesc, digest={router.microdesc_digest[:20]}...",
                flush=True,
                file=sys.stderr,
            )
            for ds in directory_servers:
                if len(ds) == 2:
                    host, port = ds
                else:
                    _, host, port = ds

                try:
                    debug(
                        f"DEBUG get_fresh_ntor_key: fetching from {host}:{port}",
                        flush=True,
                        file=sys.stderr,
                    )
                    md, _ = await self._http_get(
                        host, port, f"/tor/micro/d/{router.microdesc_digest}"
                    )
                    # Check for valid response
                    if md and len(md) > 100:
                        key = MicrodescParser.extract_ntor_key(md)
                        if key:
                            self.set_ntor_key(router.identity, key)
                            log.debug(
                                "Got ntor key from microdesc for %s", router.nickname
                            )
                            debug(
                                f"DEBUG get_fresh_ntor_key: got key from microdesc!",
                                flush=True,
                                file=sys.stderr,
                            )
                            return key
                except Exception as e:
                    debug(
                        f"DEBUG get_fresh_ntor_key: microdesc fetch failed: {e}",
                        flush=True,
                        file=sys.stderr,
                    )
                    continue

        debug(
            f"DEBUG get_fresh_ntor_key: trying server descriptor for {router.nickname}",
            flush=True,
            file=sys.stderr,
        )

        # Fall back to server descriptor - try multiple servers
        debug(
            f"DEBUG get_fresh_ntor_key: trying server descriptor for {router.nickname}",
            flush=True,
            file=sys.stderr,
        )
        for ds in directory_servers:
            if len(ds) == 2:
                host, port = ds
            else:
                _, host, port = ds

            try:
                debug(
                    f"DEBUG get_fresh_ntor_key: fetching server desc from {host}:{port}",
                    flush=True,
                    file=sys.stderr,
                )
                text, _ = await self._http_get(
                    host, port, f"/tor/server/fp/{router.identity_hex}"
                )
                debug(
                    f"DEBUG get_fresh_ntor_key: got server desc response, length={len(text)}",
                    flush=True,
                    file=sys.stderr,
                )

                # Check for valid response
                if text and len(text) > 200 and not text.startswith("HTTP/1.0 404"):
                    key = ServerDescParser.extract_ntor_key(text)
                    if key:
                        self.set_ntor_key(router.identity, key)
                        debug(
                            f"DEBUG get_fresh_ntor_key: extracted ntor key from server desc!",
                            flush=True,
                            file=sys.stderr,
                        )
                        return key
                    else:
                        debug(
                            f"DEBUG get_fresh_ntor_key: no ntor key in server desc",
                            flush=True,
                            file=sys.stderr,
                        )
            except Exception as e:
                debug(
                    f"DEBUG get_fresh_ntor_key: server desc fetch failed: {e}",
                    flush=True,
                    file=sys.stderr,
                )
                continue

        # Last resort: try to use the key from the consensus if available
        debug(
            f"DEBUG get_fresh_ntor_key: trying consensus key for {router.nickname}",
            flush=True,
            file=sys.stderr,
        )
        if router.ntor_onion_key:
            debug(
                f"DEBUG get_fresh_ntor_key: using ntor key from consensus!",
                flush=True,
                file=sys.stderr,
            )
            return router.ntor_onion_key

        debug(
            f"DEBUG get_fresh_ntor_key: returning None for {router.nickname}",
            flush=True,
            file=sys.stderr,
        )
        return None

    async def _http_get(
        self, host: str, port: int, path: str
    ) -> tuple[str, int | None]:
        """Minimal async HTTP/1.0 GET.

        Returns (body, max_age) where max_age is TTL in seconds from Cache-Control header.
        """
        request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: libtor/0.1\r\n\r\n".encode()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self._timeout,
        )
        try:
            writer.write(request)
            await writer.drain()
            chunks = []
            while True:
                chunk = await asyncio.wait_for(
                    reader.read(8192),
                    timeout=self._timeout,
                )
                if not chunk:
                    break
                chunks.append(chunk)
            response = b"".join(chunks)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        text = response.decode("utf-8", errors="replace")

        # Parse headers to get max-age from Cache-Control
        max_age: int | None = None
        if "\r\n\r\n" in text:
            header_part, _, body = text.partition("\r\n\r\n")

            # Parse Cache-Control header
            for line in header_part.split("\r\n"):
                line_lower = line.lower()
                if line_lower.startswith("cache-control:"):
                    # Parse max-age=XXX
                    value = line.split(":", 1)[1].strip()
                    for part in value.split(","):
                        part = part.strip()
                        if part.startswith("max-age="):
                            try:
                                max_age = int(part.split("=")[1])
                            except (ValueError, IndexError):
                                pass
                elif line_lower.startswith("expires:"):
                    # Also try parsing Expires header
                    if max_age is None:
                        try:
                            from email.utils import parsedate_to_datetime

                            exp_date = parsedate_to_datetime(
                                line.split(":", 1)[1].strip()
                            )
                            import datetime

                            now = datetime.datetime.now(datetime.timezone.utc)
                            max_age = int((exp_date - now).total_seconds())
                        except Exception:
                            pass

            return body, max_age

        return text, max_age

    async def refresh_if_needed(
        self,
        routers: list[RouterInfo],
        directory_servers: list[tuple[str, str, int]],
    ) -> None:
        """Refresh the cache if it's stale."""
        if not self.is_fresh and routers:
            log.info("Descriptor cache stale, refreshing...")
            await self.fetch_all_descriptors(routers, directory_servers)
