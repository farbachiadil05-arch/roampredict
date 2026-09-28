"""Platform adapters.

Always import as ``roampredict.platform`` (never run files in this folder
directly), so this package cannot be confused with Python's own ``platform``.
"""

from roampredict.platform.base import (
    Band,
    BssEntry,
    CommandResult,
    ConnectResult,
    InterfaceInfo,
    L3Snapshot,
    LinkStatus,
    NetworkOps,
    PingResult,
    RoamCapabilities,
    WlanAdapter,
    WlanError,
    WlanEvent,
    WlanEventKind,
    WlanPermissionError,
    WlanUnavailableError,
    freq_to_channel,
)

__all__ = [
    "Band",
    "BssEntry",
    "CommandResult",
    "ConnectResult",
    "InterfaceInfo",
    "L3Snapshot",
    "LinkStatus",
    "NetworkOps",
    "PingResult",
    "RoamCapabilities",
    "WlanAdapter",
    "WlanError",
    "WlanEvent",
    "WlanEventKind",
    "WlanPermissionError",
    "WlanUnavailableError",
    "freq_to_channel",
]
