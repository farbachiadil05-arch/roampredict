"""Validation of everything that comes from outside the program.

BSSIDs arrive from Windows, from beacons in the air, from the SQLite store, from
the config file and from the command line.  Every one of them goes through
:func:`normalize_bssid` (or :func:`bssid_from_bytes`) before it is used, so the
rest of the code can rely on the canonical lower-case ``aa:bb:cc:dd:ee:ff`` form.
"""

from __future__ import annotations

import re

__all__ = [
    "ValidationError",
    "normalize_bssid",
    "bssid_from_bytes",
    "bssid_to_bytes",
    "is_valid_bssid",
    "validate_ssid",
    "validate_profile_name",
    "ssid_from_bytes",
    "SSID_MAX_BYTES",
    "PROFILE_NAME_MAX",
]

SSID_MAX_BYTES = 32
PROFILE_NAME_MAX = 255  # WLAN profile names live in WCHAR[256] buffers

# Two hex digits, then five more groups using the SAME separator (":" "-" or none).
_BSSID_RE = re.compile(r"[0-9A-Fa-f]{2}([:-]?)[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}")


class ValidationError(ValueError):
    """Raised when an input value is malformed."""


def _format(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def _check_unicast(raw: bytes, original: object) -> None:
    if raw == b"\x00" * 6:
        raise ValidationError(f"BSSID {original!r} is all zeros")
    if raw[0] & 0x01:
        # Group bit set: broadcast (ff:ff:...) or multicast. An access point's
        # BSSID is always a unicast address, so this can only be bad input.
        raise ValidationError(f"BSSID {original!r} is a broadcast/multicast address")


def normalize_bssid(value: object) -> str:
    """Return ``value`` as ``aa:bb:cc:dd:ee:ff`` or raise :class:`ValidationError`.

    Accepts ``:`` or ``-`` separators (used consistently) or 12 bare hex digits.
    Rejects all-zero, broadcast and multicast addresses.
    """
    if not isinstance(value, str):
        raise ValidationError(f"BSSID must be a string, got {type(value).__name__}")
    text = value.strip()
    if not _BSSID_RE.fullmatch(text):
        raise ValidationError(f"not a valid BSSID: {value!r}")
    raw = bytes.fromhex(text.replace(":", "").replace("-", ""))
    _check_unicast(raw, value)
    return _format(raw)


def bssid_from_bytes(raw: bytes | bytearray | memoryview) -> str:
    """Convert 6 raw bytes (as Windows returns them) to the canonical form."""
    data = bytes(raw)
    if len(data) != 6:
        raise ValidationError(f"BSSID must be 6 bytes, got {len(data)}")
    _check_unicast(data, data.hex(":"))
    return _format(data)


def bssid_to_bytes(bssid: str) -> bytes:
    """Validate ``bssid`` and return its 6 raw bytes."""
    return bytes.fromhex(normalize_bssid(bssid).replace(":", ""))


def is_valid_bssid(value: object) -> bool:
    try:
        normalize_bssid(value)
    except ValidationError:
        return False
    return True


def validate_ssid(value: object) -> str:
    """An SSID from config/CLI: non-empty text of at most 32 bytes in UTF-8."""
    if not isinstance(value, str):
        raise ValidationError(f"SSID must be a string, got {type(value).__name__}")
    if not value:
        raise ValidationError("SSID must not be empty")
    if "\x00" in value:
        raise ValidationError("SSID must not contain NUL characters")
    if len(value.encode("utf-8")) > SSID_MAX_BYTES:
        raise ValidationError(f"SSID {value!r} is longer than {SSID_MAX_BYTES} bytes")
    return value


def validate_profile_name(value: object) -> str:
    """A saved Windows WLAN profile name (we only ever pass the NAME to Windows)."""
    if not isinstance(value, str):
        raise ValidationError(f"profile name must be a string, got {type(value).__name__}")
    if not value or len(value) > PROFILE_NAME_MAX:
        raise ValidationError(f"profile name must be 1..{PROFILE_NAME_MAX} characters")
    if any(ord(ch) < 32 for ch in value):
        raise ValidationError("profile name must not contain control characters")
    return value


def ssid_from_bytes(raw: bytes) -> str:
    """Decode raw SSID bytes for display and comparison (never fails)."""
    return bytes(raw).decode("utf-8", errors="replace")
