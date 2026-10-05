"""Structured event log (JSON lines) plus short human-readable console lines.

Every decision is logged with its score breakdown; every switch with its
measured timings.  Nothing secret ever reaches this module (RoamPredict never
has a password, username or certificate), and :func:`scrub` removes any
field whose name even looks like one, as a second line of defence.

Console output is plain ASCII on purpose: a Windows console redirected to a
file uses a legacy code page and would choke on characters like arrows.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from typing import IO, Any

__all__ = ["Telemetry", "scrub"]

_FORBIDDEN = ("password", "passwd", "secret", "username", "identity", "credential", "token", "certificate", "keymaterial", "psk")

_CONSOLE_KINDS = frozenset(
    {
        "start",
        "stop",
        "state",
        "decision",
        "would_switch",
        "not_verified",
        "switch_result",
        "windows_roam",
        "prediction_check",
        "connected",
        "link_down",
        "net_down",
        "net_up",
        "ip_change",
        "warning",
        "error",
        "kill_switch",
    }
)


def scrub(value: Any) -> Any:
    """Recursively drop dict entries whose key looks credential-related."""
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if any(bad in str(key).lower() for bad in _FORBIDDEN):
                out[key] = "[removed]"
            else:
                out[key] = scrub(item)
        return out
    if isinstance(value, (list, tuple)):
        return [scrub(v) for v in value]
    return value


class Telemetry:
    def __init__(
        self,
        log_path: Path | None = None,
        *,
        console: bool = True,
        verbose: bool = False,
        keep_in_memory: bool = False,
        stream: IO[str] | None = None,
    ) -> None:
        self._fh: IO[str] | None = None
        if log_path is not None:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = open(log_path, "a", encoding="utf-8")  # noqa: SIM115 - closed in close()
        self._console = console
        self._verbose = verbose
        self._stream = stream
        self._lock = threading.Lock()
        self.counters: Counter[str] = Counter()
        self.memory: list[dict[str, Any]] | None = [] if keep_in_memory else None

    def emit(self, kind: str, message: str = "", **fields: Any) -> None:
        record = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": kind}
        if message:
            record["msg"] = message
        record.update(scrub(fields))
        with self._lock:
            self.counters[kind] += 1
            if self.memory is not None:
                self.memory.append(record)
            if self._fh is not None:
                self._fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
                self._fh.flush()
            if self._console and (self._verbose or kind in _CONSOLE_KINDS):
                stream = self._stream or sys.stdout
                text = f"{time.strftime('%H:%M:%S')} {kind.upper():<16} {message}"
                stream.write(text.encode("ascii", errors="replace").decode("ascii") + "\n")
                stream.flush()

    def events(self, kind: str | None = None) -> list[dict[str, Any]]:
        if self.memory is None:
            return []
        return [e for e in self.memory if kind is None or e["kind"] == kind]

    def close(self) -> None:
        with self._lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None
