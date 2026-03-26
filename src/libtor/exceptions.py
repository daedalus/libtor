"""Custom exceptions for the torpy library."""


class TorError(Exception):
    """Base exception for all Tor-related errors."""


class HandshakeError(TorError):
    """Raised when a cryptographic handshake fails."""


class CircuitError(TorError):
    """Raised when circuit creation or operation fails."""


class StreamError(TorError):
    """Raised when a stream operation fails."""


class DirectoryError(TorError):
    """Raised when fetching/parsing the directory consensus fails."""


class CellError(TorError):
    """Raised when a Tor cell cannot be parsed or is invalid."""


class RelayError(TorError):
    """Raised when a relay command fails."""


class DestroyedError(TorError):
    """Raised when trying to use a destroyed circuit or stream."""
