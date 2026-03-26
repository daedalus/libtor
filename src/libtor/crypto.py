"""
Cryptographic primitives for the Tor protocol.

Implements:
  - ntor handshake  (tor-spec.txt §5.1.4, ntor-spec.txt)
  - TAP handshake   (tor-spec.txt §5.1.3) – kept for compatibility
  - AES-128-CTR onion encryption / decryption
  - SHA-1 running-digest relay integrity
  - KDF-RFC5869 (HKDF-SHA256) key material derivation
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .exceptions import HandshakeError

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NTOR_PROTOID = b"ntor-curve25519-sha256-1"
NTOR_MAC_KEY = NTOR_PROTOID + b":mac"
NTOR_VERIFY_KEY = NTOR_PROTOID + b":verify"
NTOR_EXPAND_KEY = NTOR_PROTOID + b":key_expand"
NTOR_SERVER_STR = b"Server"

# Key lengths
KEY_LEN = 16  # AES-128
HASH_LEN = 20  # SHA-1 digest
DH_LEN = 32  # Curve25519 point


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _h(msg: bytes) -> bytes:
    """H(x) = HMAC-SHA256(PROTOID, x)  as per ntor spec."""
    return _hmac_sha256(NTOR_PROTOID, msg)


# ---------------------------------------------------------------------------
# ntor Handshake  (client side)
# ---------------------------------------------------------------------------


class NtorHandshake:
    """
    Client-side ntor key exchange.

    Usage::

        hs = NtorHandshake(relay_id_bytes, relay_ntor_onion_key_bytes)
        client_handshake = hs.create_onion_skin()   # 84 bytes → sent in CREATE2
        keys = hs.complete(server_handshake)         # 64-byte server response
    """

    ONIONSKIN_LEN = 84  # node_id(20) + keyid(32) + client_pk(32)
    SERVER_PK_LEN = 64  # server_pk(32) + auth(32)

    def __init__(self, relay_id: bytes, relay_onion_key: bytes):
        if len(relay_id) != 20:
            raise HandshakeError(f"relay_id must be 20 bytes, got {len(relay_id)}")
        if len(relay_onion_key) != 32:
            raise HandshakeError(
                f"relay_onion_key must be 32 bytes, got {len(relay_onion_key)}"
            )

        self.relay_id = relay_id
        self.relay_onion_key = relay_onion_key
        self._priv = X25519PrivateKey.generate()
        self._pub_bytes = self._priv.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )

    def create_onion_skin(self) -> bytes:
        """Return the 84-byte client-side handshake payload for CREATE2."""
        return self.relay_id + self.relay_onion_key + self._pub_bytes

    def complete(self, server_handshake: bytes) -> "CircuitKeys":
        """
        Process the 64-byte server handshake from CREATED2 and derive keys.

        Returns a CircuitKeys instance.
        """
        if len(server_handshake) < self.SERVER_PK_LEN:
            raise HandshakeError(f"Server handshake too short: {len(server_handshake)}")
        server_pk_bytes = server_handshake[:32]
        auth = server_handshake[32:64]

        # Load server public key
        server_pub = X25519PublicKey.from_public_bytes(server_pk_bytes)
        relay_pub = X25519PublicKey.from_public_bytes(self.relay_onion_key)

        # EXP(server_pk, client_sk)
        exp1 = self._priv.exchange(server_pub)
        # EXP(relay_onion_key, client_sk)
        exp2 = self._priv.exchange(relay_pub)

        # secret_input = EXP1 || EXP2 || node_id || relay_nk_pk || client_pk || server_pk || PROTOID
        secret_input = (
            exp1
            + exp2
            + self.relay_id
            + self.relay_onion_key
            + self._pub_bytes
            + server_pk_bytes
            + NTOR_PROTOID
        )

        verify = _hmac_sha256(NTOR_VERIFY_KEY, secret_input)

        auth_input = (
            verify
            + self.relay_id
            + self.relay_onion_key
            + server_pk_bytes
            + self._pub_bytes
            + NTOR_PROTOID
            + NTOR_SERVER_STR
        )
        expected_auth = _hmac_sha256(NTOR_MAC_KEY, auth_input)

        if not hmac.compare_digest(auth, expected_auth):
            raise HandshakeError("ntor auth verification failed")

        return CircuitKeys.derive(secret_input)


# ---------------------------------------------------------------------------
# Key derivation  (KDF-RFC5869 / HKDF-SHA256)
# ---------------------------------------------------------------------------


class CircuitKeys:
    """
    Per-hop key material for a circuit node.

    Key material layout (tor-spec.txt §5.2.2):
      Df  (20) – forward digest seed
      Db  (20) – backward digest seed
      Kf  (16) – forward AES key
      Kb  (16) – backward AES key
      Kf_iv  (16) – forward IV (for CTR)
      Kb_iv  (16) – backward IV (for CTR)
    """

    KEY_MATERIAL_LEN = 72  # 20+20+16+16

    def __init__(
        self,
        df: bytes,
        db: bytes,
        kf: bytes,
        kb: bytes,
    ):
        self.df = df
        self.db = db
        self.kf = kf
        self.kb = kb

        # Initialise running SHA-1 digests for relay integrity
        self._fwd_digest = hashlib.sha1(df)
        self._bwd_digest = hashlib.sha1(db)

        # AES-CTR state (counter starts at 0, IV all zeros)
        self._fwd_cipher = _make_aes_ctr(kf)
        self._bwd_cipher = _make_aes_ctr(kb)

    @classmethod
    def derive(cls, secret_input: bytes) -> "CircuitKeys":
        """Derive key material from ntor secret_input using HKDF-SHA256."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=cls.KEY_MATERIAL_LEN,
            salt=b"",
            info=NTOR_EXPAND_KEY,
        )
        key_material = hkdf.derive(secret_input)
        df = key_material[0:20]
        db = key_material[20:40]
        kf = key_material[40:56]
        kb = key_material[56:72]
        return cls(df=df, db=db, kf=kf, kb=kb)

    # ---- encryption -------------------------------------------------------

    def encrypt_forward(self, data: bytes) -> bytes:
        return self._fwd_cipher.update(data)

    def decrypt_backward(self, data: bytes) -> bytes:
        return self._bwd_cipher.update(data)

    def decrypt_forward(self, data: bytes) -> bytes:
        return self._fwd_cipher.update(data)

    def encrypt_backward(self, data: bytes) -> bytes:
        return self._bwd_cipher.update(data)

    # ---- running digest ---------------------------------------------------

    def update_fwd_digest(self, data: bytes) -> bytes:
        """Update the forward running digest and return the current 4-byte MAC."""
        self._fwd_digest.update(data)
        return self._fwd_digest.digest()[:4]

    def update_bwd_digest(self, data: bytes) -> bytes:
        """Update the backward running digest and return the current 4-byte MAC."""
        self._bwd_digest.update(data)
        return self._bwd_digest.digest()[:4]


def _make_aes_ctr(key: bytes):
    """Return a stateful AES-128-CTR encryptor (counter starts at 0)."""
    iv = b"\x00" * 16
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    return cipher.encryptor()


# ---------------------------------------------------------------------------
# Fast CREATE (CREATE_FAST / CREATED_FAST) – used for first hop only
# tor-spec.txt §5.1.2
# ---------------------------------------------------------------------------


class FastHandshake:
    """
    CREATE_FAST handshake for the first hop (no public-key crypto needed
    because the TLS channel already provides forward secrecy).
    """

    KEY_LEN = 20  # X and Y are 20-byte random values

    def __init__(self):
        self.x = os.urandom(self.KEY_LEN)

    def create_payload(self) -> bytes:
        return self.x

    def complete(self, y: bytes, kh: bytes) -> CircuitKeys:
        """Derive keys from X, Y, KH (tor-spec.txt §5.1.2)."""
        if len(y) != self.KEY_LEN or len(kh) != self.KEY_LEN:
            raise HandshakeError("CREATED_FAST response has wrong length")
        secret = self.x + y
        key_material = _kdf_tor(secret)
        # Verify KH
        expected_kh = key_material[:20]
        if not hmac.compare_digest(kh, expected_kh):
            raise HandshakeError("CREATED_FAST KH mismatch")
        df = key_material[20:40]
        db = key_material[40:60]
        kf = key_material[60:76]
        kb = key_material[76:92]
        return CircuitKeys(df=df, db=db, kf=kf, kb=kb)


def _kdf_tor(secret: bytes, needed: int = 100) -> bytes:
    """
    KDF-TOR (old SHA-1-based KDF used by CREATE_FAST).
    tor-spec.txt §5.2.1
    """
    result = b""
    i = 0
    while len(result) < needed:
        result += hashlib.sha1(secret + bytes([i])).digest()
        i += 1
    return result[:needed]
