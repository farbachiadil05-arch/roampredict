"""``roampredict doctor``: can RoamPredict work on this laptop?

Checks Windows version, admin rights, wlanapi.dll, the Wi-Fi adapter, the
current connection, Location permission (Windows 11 24H2+), which fast-roaming
features the APs advertise, the saved profile, the IP configuration, the
driver's own roaming setting, and RoamPredict's data folder.  Read-only: it
never changes a setting and never connects anywhere.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = ["Check", "DoctorSettings", "run_doctor", "format_checks", "roaming_settings"]


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # OK | WARN | FAIL | INFO | SKIP
    detail: str
    hint: str = ""


@dataclass(frozen=True)
class DoctorSettings:
    data_dir: Path
    kill_file: Path
    dry_run: bool = True
    allowed_ssids: tuple[str, ...] = ()
    allowed_profiles: tuple[str, ...] = ()
    interface: str | None = None


_PS_ROAMING = (
    "[Console]::OutputEncoding=[Text.Encoding]::UTF8; "
    "Get-NetAdapterAdvancedProperty -ErrorAction Stop | "
    "Where-Object { $_.DisplayName -match 'roam' -or $_.RegistryKeyword -match 'roam' } | "
    "Select-Object InterfaceDescription,DisplayName,DisplayValue,RegistryKeyword | ConvertTo-Json -Compress"
)


def roaming_settings(description: str | None) -> list[dict[str, str]] | str:
    """The driver's roaming-related advanced properties (read-only PowerShell).

    Returns the matching properties, or an error message.  No user input is
    ever placed into the PowerShell command.
    """
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    exe = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    try:
        proc = subprocess.run(  # noqa: S603 - fixed command, absolute path, no shell
            [exe, "-NoProfile", "-NonInteractive", "-Command", _PS_ROAMING],
            capture_output=True,
            timeout=40,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"PowerShell not available: {exc}"
    out = proc.stdout.decode("utf-8", errors="replace").strip()
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        return f"Get-NetAdapterAdvancedProperty failed: {err[0] if err else proc.returncode}"
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "unexpected PowerShell output"
    items = data if isinstance(data, list) else [data]
    rows = [{k: str(v) for k, v in item.items()} for item in items if isinstance(item, dict)]
    if description:
        rows = [r for r in rows if r.get("InterfaceDescription", "").lower() == description.lower()] or rows
    return rows


def _check_python() -> Check:
    v = sys.version_info
    ok = v >= (3, 11)
    return Check("Python", "OK" if ok else "FAIL", f"{v.major}.{v.minor}.{v.micro}", "" if ok else "install Python 3.11 or newer")


def _check_os() -> Check:
    if sys.platform != "win32":
        return Check("Operating system", "INFO", f"{sys.platform}: not Windows", "only the simulator and the tests run here")
    ver = sys.getwindowsversion()  # type: ignore[attr-defined]
    build = ver.build
    if ver.major < 10:
        return Check("Operating system", "FAIL", f"Windows {ver.major}.{ver.minor} (build {build})", "needs Windows 10 or 11")
    name = "Windows 11" if build >= 22000 else "Windows 10"
    detail = f"{name} (build {build})"
    if build >= 26100:
        detail += " - 24H2 or newer: BSSID/scan data needs Location permission"
    hint = "" if build >= 22000 else "Windows 10 no longer receives regular security updates"
    return Check("Operating system", "OK", detail, hint)


def _check_admin() -> Check:
    from roampredict.net.l3 import is_admin

    if is_admin():
        return Check("Admin rights", "OK", "running elevated (ARP flush and DHCP renew possible)")
    return Check(
        "Admin rights",
        "WARN",
        "not elevated: ARP flush and DHCP renew will be skipped (everything else works)",
        'for those two steps, open PowerShell with "Run as administrator"',
    )


def _check_storage(settings: DoctorSettings) -> list[Check]:
    checks = []
    try:
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        probe = settings.data_dir / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        conn = sqlite3.connect(":memory:")
        version = conn.execute("select sqlite_version()").fetchone()[0]
        conn.close()
        checks.append(Check("Data folder", "OK", f"{settings.data_dir} (SQLite {version})"))
    except OSError as exc:
        checks.append(Check("Data folder", "FAIL", f"{settings.data_dir}: {exc}", "set paths.data_dir in the config"))
    if settings.kill_file.exists():
        checks.append(Check("Kill switch", "WARN", f"ACTIVE ({settings.kill_file})", "roampredict unkill"))
    else:
        checks.append(Check("Kill switch", "OK", "not active"))
    mode = "dry-run (only logs what it would do)" if settings.dry_run else "ACTIVE (will request switches)"
    checks.append(Check("Mode", "INFO", mode, "" if settings.dry_run else "stop at any time: roampredict kill"))
    if importlib.util.find_spec("matplotlib") is not None:
        checks.append(Check("matplotlib", "OK", "installed (for roampredict simulate --plot)"))
    else:
        checks.append(Check("matplotlib", "INFO", "not installed (only needed for the simulator plot)", 'pip install -e ".[sim]"'))
    return checks


def _check_windows_wifi(settings: DoctorSettings) -> list[Check]:
    from roampredict.net.l3 import WindowsNetworkOps
    from roampredict.platform.base import WlanError, WlanPermissionError
    from roampredict.platform.windows_wlan import WindowsWlanAdapter, list_interfaces

    checks: list[Check] = []
    try:
        interfaces = list_interfaces()
    except (WlanError, OSError) as exc:
        return [Check("wlanapi.dll", "FAIL", str(exc), "is the WLAN AutoConfig service running? Get-Service WlanSvc")]
    checks.append(Check("wlanapi.dll", "OK", "loaded, WlanOpenHandle works"))
    if not interfaces:
        return checks + [Check("Wi-Fi adapter", "FAIL", "none found", "is Wi-Fi switched on / the driver installed?")]
    for info in interfaces:
        checks.append(Check("Wi-Fi adapter", "OK", f"{info.description} ({info.state}) {info.guid}"))

    try:
        adapter = WindowsWlanAdapter(settings.interface)
    except (WlanError, OSError) as exc:
        return checks + [Check("Adapter", "FAIL", str(exc))]
    try:
        try:
            link = adapter.link_status()
        except WlanPermissionError as exc:
            checks.append(Check("Current connection", "FAIL", str(exc)))
            link = None
        if link is not None and link.connected:
            source = "driver RSSI" if link.rssi_source == "rssi" else "ESTIMATED from signal quality"
            checks.append(
                Check(
                    "Current connection",
                    "OK",
                    f"'{link.ssid}' via {link.bssid}, profile '{link.profile_name}', {link.auth}, "
                    f"802.1X {'on' if link.onex else 'off'}, {link.rssi_dbm:.0f} dBm ({source}), channel {link.channel}",
                )
            )
            if link.rssi_source != "rssi":
                checks.append(Check("RSSI", "WARN", "the driver does not report dBm; using quality/2 - 100", "trends still work, levels are approximate"))
        elif link is not None:
            checks.append(Check("Current connection", "WARN", "not connected to Wi-Fi", "connect to your campus network first"))

        try:
            entries = adapter.bss_list()
            checks.append(Check("BSS list / Location", "OK", f"{len(entries)} BSSIDs visible"))
        except WlanPermissionError as exc:
            entries = []
            checks.append(Check("BSS list / Location", "FAIL", str(exc)))
        if link is not None and link.connected and entries:
            same = sorted((e for e in entries if e.ssid == link.ssid), key=lambda e: -e.rssi_dbm)
            known = [e for e in same if e.capabilities.ft is not None]

            def count(attr: str) -> str:
                return f"{sum(1 for e in known if getattr(e.capabilities, attr))}/{len(known)}"

            if known:
                checks.append(
                    Check(
                        "Fast roaming (advertised)",
                        "INFO",
                        f"APs of '{link.ssid}': 802.11r {count('ft')}, 802.11k {count('rrm_neighbor_report')}, "
                        f"802.11v {count('bss_transition')}, pre-auth {count('rsn_preauth')}",
                        "PMKSA caching is never advertised - measure it with: roampredict report",
                    )
                )
            else:
                checks.append(
                    Check(
                        "Fast roaming (advertised)",
                        "INFO",
                        "Windows returned no information elements, so 802.11r cannot be detected here",
                        "check manually: netsh wlan show networks mode=bssid",
                    )
                )
            for e in same[:8]:
                checks.append(Check("  AP", "INFO", f"{e.bssid} ch {e.channel} {e.rssi_dbm:.0f} dBm {e.capabilities.flags()}"))

        if link is not None and link.connected:
            try:
                names = adapter.profile_names()
            except WlanError as exc:
                names = []
                checks.append(Check("Saved profile", "WARN", f"cannot list profiles: {exc}"))
            if link.profile_name in names:
                checks.append(Check("Saved profile", "OK", f"'{link.profile_name}' is saved (only its name is used)"))
            elif names:
                checks.append(Check("Saved profile", "WARN", f"'{link.profile_name}' not in the profile list"))
            allowed = link.ssid in settings.allowed_ssids and (
                not settings.allowed_profiles or link.profile_name in settings.allowed_profiles
            )
            if allowed:
                checks.append(Check("Allow-list", "OK", f"'{link.ssid}' is allow-listed: --active would act here"))
            else:
                checks.append(
                    Check("Allow-list", "INFO", f"'{link.ssid}' is not allow-listed: RoamPredict will only observe", "add it to safety.allowed_ssids")
                )
            try:
                net = WindowsNetworkOps()
                snap = net.snapshot(adapter.interface().guid)
                if snap.usable:
                    checks.append(
                        Check("IP configuration", "OK", f"{snap.ipv4}/{snap.prefix_len} via {snap.gateway} on '{snap.friendly_name}' (DHCP {snap.dhcp_server})")
                    )
                    ping = net.ping(snap.gateway or "", 1000)
                    if ping.ok:
                        checks.append(Check("Gateway ping", "OK", f"{snap.gateway} replied in {ping.rtt_ms:.0f} ms"))
                    else:
                        checks.append(
                            Check("Gateway ping", "WARN", f"no reply from {snap.gateway} ({ping.error})", "some campuses block ping; RoamPredict then checks the IP address after a switch instead")
                        )
                else:
                    checks.append(Check("IP configuration", "WARN", "no usable IPv4 address/gateway on the Wi-Fi adapter"))
            except OSError as exc:
                checks.append(Check("IP configuration", "WARN", f"cannot read: {exc}"))

        rows = roaming_settings(adapter.interface().description)
        if isinstance(rows, str):
            checks.append(Check("Driver roaming setting", "INFO", rows))
        elif rows:
            for r in rows:
                checks.append(
                    Check(
                        "Driver roaming setting",
                        "INFO",
                        f"{r.get('DisplayName')} = {r.get('DisplayValue')} (keyword {r.get('RegistryKeyword')})",
                        "the official knob for earlier roaming; RoamPredict never changes it",
                    )
                )
        else:
            checks.append(Check("Driver roaming setting", "INFO", "the driver exposes no roaming setting (or uses another name)"))
    finally:
        adapter.close()
    return checks


def _check_code() -> Check:
    from roampredict.buildinfo import code_identity

    return Check("RoamPredict code", "INFO", code_identity().removeprefix("code "))


def run_doctor(settings: DoctorSettings) -> list[Check]:
    checks = [_check_code(), _check_python(), _check_os()]
    if sys.platform == "win32":
        checks.append(_check_admin())
        checks += _check_windows_wifi(settings)
    else:
        checks.append(Check("Wi-Fi checks", "SKIP", "not Windows", "try: roampredict simulate"))
    checks += _check_storage(settings)
    return checks


def format_checks(checks: Sequence[Check]) -> str:
    lines = ["RoamPredict doctor"]
    for c in checks:
        lines.append(f"  [{c.status:^4}] {c.name:<26} {c.detail}")
        if c.hint:
            lines.append(f"  {'':6} {'':<26} -> {c.hint}")
    failed = sum(1 for c in checks if c.status == "FAIL")
    warned = sum(1 for c in checks if c.status == "WARN")
    lines.append(f"\n{failed} problem(s), {warned} warning(s).")
    return "\n".join(line.encode("ascii", errors="replace").decode("ascii") for line in lines)
