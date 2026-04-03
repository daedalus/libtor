import logging
import sys


# Verbosity levels
# 0 = ERROR only
# 1 = WARNING
# 2 = INFO (default)
# 3 = DEBUG
# 4 = TRACE (most verbose)
VERBOSITY = 2


def setup_logging(level: int = 2) -> None:
    """Configure logging based on verbosity level.

    Args:
        level: Verbosity level (0-4)
            0 = ERROR only
            1 = WARNING
            2 = INFO (default)
            3 = DEBUG
            4 = TRACE (most verbose)
    """
    global VERBOSITY
    VERBOSITY = level

    # Map verbosity to logging levels
    level_map = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
        4: logging.DEBUG,  # TRACE also uses DEBUG but with TRACE prefix
    }

    log_level = level_map.get(level, logging.INFO)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        format="%(message)s" if level < 3 else "%(levelname)s:%(name)s:%(message)s",
        stream=sys.stderr,
    )


def trace(*args, **kwargs):
    """Log at TRACE level (verbose protocol debug)."""
    if VERBOSITY >= 4:
        print("TRACE:", *args, **kwargs)


def debug(*args, **kwargs):
    """Log at DEBUG level."""
    if VERBOSITY >= 3:
        print(*args, **kwargs)


def info(*args, **kwargs):
    """Log at INFO level."""
    if VERBOSITY >= 2:
        print(*args, **kwargs)


def warning(*args, **kwargs):
    """Log at WARNING level."""
    if VERBOSITY >= 1:
        print("WARNING:", *args, **kwargs, file=sys.stderr)


def error(*args, **kwargs):
    """Log at ERROR level."""
    print("ERROR:", *args, **kwargs, file=sys.stderr)
