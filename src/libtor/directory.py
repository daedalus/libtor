"""
Directory client – fetches and parses the Tor network consensus.

References:
  - dir-spec.txt §3 (Consensus documents)
  - dir-spec.txt §6 (Microdescriptors)

Hard-coded directory authority fallbacks are used to bootstrap.
"""

import asyncio
import base64
import logging
import random
import re
from dataclasses import dataclass, field

from .exceptions import DirectoryError

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
    ("185.220.101.47", 80),
    ("45.66.33.45", 80),
    ("193.187.88.42", 80),
    ("178.20.55.18", 80),
    ("51.77.234.247", 80),
]


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

    @property
    def identity_hex(self) -> str:
        return self.identity.hex().upper()

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

    def __repr__(self) -> str:
        return (
            f"<RouterInfo {self.nickname} {self.address}:{self.or_port} "
            f"flags={','.join(self.flags)}>"
        )


# ---------------------------------------------------------------------------
# Consensus parser
# ---------------------------------------------------------------------------


class ConsensuParser:
    """Parse a Tor network-status consensus document (v3)."""

    # Regex patterns
    # r line format: r nickname identity digest time IP or_port dir_port
    _RE_R = re.compile(r"^r (\S+) (\S+) (\S+) \S+ (\S+) (\d+) (\d+)")
    _RE_S = re.compile(r"^s (.+)")
    _RE_W = re.compile(r"^w Bandwidth=(\d+)")

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
                address = m.group(4)
                or_port = int(m.group(5))
                dir_port = int(m.group(6))
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

        if current is not None:
            routers.append(current)

        return routers


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

    CONSENSUS_PATH = "/tor/status-vote/current/consensus-microdesc"
    MICRO_PATH = "/tor/micro/d/"

    def __init__(self, timeout: float = 30.0):
        self._timeout = timeout
        self._routers: list[RouterInfo] = []

    @property
    def routers(self) -> list[RouterInfo]:
        return self._routers

    # ---- public API -------------------------------------------------------

    async def fetch_consensus(
        self,
        authorities: list[tuple[str, str, int]] | None = None,
    ) -> list[RouterInfo]:
        """
        Fetch the consensus from directory authorities (or fallbacks).
        Returns a list of RouterInfo objects.
        """
        sources = list(authorities or DIRECTORY_AUTHORITIES)
        random.shuffle(sources)
        sources += FALLBACK_DIRS  # type: ignore[arg-type]

        for entry in sources:
            if len(entry) == 3:
                _name, host, port = entry
            else:
                host, port = entry

            try:
                log.debug("Fetching consensus from %s:%d", host, port)
                text = await self._http_get(host, port, self.CONSENSUS_PATH)
                routers = ConsensuParser.parse(text)
                if routers:
                    log.info(
                        "Fetched consensus: %d relays from %s:%d",
                        len(routers),
                        host,
                        port,
                    )
                    self._routers = routers
                    return routers
            except Exception as exc:
                log.debug("Consensus fetch from %s:%d failed: %s", host, port, exc)
                continue

        raise DirectoryError("Could not fetch consensus from any directory authority")

    async def fetch_ntor_key(
        self,
        router: RouterInfo,
        directory_host: str,
        directory_port: int,
    ) -> bytes | None:
        """
        Fetch the ntor-onion-key for a relay via its microdescriptor.
        Returns the 32-byte key or None.
        """
        digest_b64 = base64.b64encode(router.digest).decode().rstrip("=")
        path = self.MICRO_PATH + digest_b64
        try:
            text = await self._http_get(directory_host, directory_port, path)
            return MicrodescParser.extract_ntor_key(text)
        except Exception as exc:
            log.debug("Microdesc fetch failed for %s: %s", router.nickname, exc)
            return None

    # ---- helpers ----------------------------------------------------------

    async def _http_get(self, host: str, port: int, path: str) -> str:
        """Minimal async HTTP/1.0 GET (no TLS – directory servers accept plain)."""
        request = (
            f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: torpy/0.1\r\n\r\n"
        ).encode()

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=self._timeout,
        )
        try:
            writer.write(request)
            await writer.drain()
            response = await asyncio.wait_for(
                reader.read(10 * 1024 * 1024),  # 10 MB max
                timeout=self._timeout,
            )
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
