"""IP layer on Windows: adapter address/gateway, gateway ping, ARP flush, DHCP renew.

Everything that can be read through an API is read through an API, so nothing
depends on the language of Windows (``ipconfig``/``netsh`` output is
translated - e.g. Italian on an Italian Windows):

* ``GetAdaptersAddresses``   - IPv4 address, prefix, gateway, DHCP server of the
                               Wi-Fi adapter (matched by its interface GUID)
* ``IcmpSendEcho``           - gateway ping; no admin rights needed
* ``FlushIpNetTable2``       - clears the ARP cache of the Wi-Fi interface only;
                               same effect as ``netsh interface ip delete arpcache``
                               but scoped to one interface.  Needs admin.  If the
                               API fails for another reason, the netsh command is
                               used as a fallback.
* ``ipconfig /renew "<adapter name>"`` - DHCP renew.  Probably needs admin (check
                               with a normal PowerShell).  Skipped without admin.

Commands run with an argument list (never ``shell=True``) and absolute paths
under %SystemRoot%\\System32, so PATH tricks cannot swap the executable.
"""

from __future__ import annotations

import ctypes
import ipaddress
import os
import socket
import subprocess
import sys
import time
from ctypes import POINTER, byref, sizeof

from roampredict.platform import win32_structs as w
from roampredict.platform.base import CommandResult, L3Snapshot, NetworkOps, PingResult

__all__ = ["WindowsNetworkOps", "parse_adapter_addresses", "system_tool", "is_admin"]


def system_tool(name: str) -> str:
    """Absolute path of a Windows system executable (e.g. netsh.exe)."""
    root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
    return os.path.join(root, "System32", name)


def is_admin() -> bool:
    """True if this process runs elevated (Windows) or as root (elsewhere)."""
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except (AttributeError, OSError):
            return False
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() == 0)


def _decode(raw: bytes) -> str:
    for codec in ("oem", "utf-8"):
        try:
            return raw.decode(codec, errors="replace")
        except LookupError:
            continue
    return raw.decode("latin-1")


def _read_utf16z(address: int, max_chars: int = 256) -> str:
    """Read a NUL-terminated UTF-16 string (Windows wchar_t*) byte by byte."""
    units = []
    for i in range(max_chars):
        unit = w.WCHAR.from_address(address + 2 * i).value
        if unit == 0:
            break
        units.append(unit)
    return b"".join(u.to_bytes(2, "little") for u in units).decode("utf-16-le", errors="replace")


def _sockaddr_ipv4(address: int) -> str | None:
    if not address:
        return None
    sa = w.SOCKADDR_IN.from_address(address)
    if sa.sin_family != w.AF_INET:
        return None
    return socket.inet_ntoa(bytes(sa.sin_addr))


def parse_adapter_addresses(address: int, interface_guid: str) -> L3Snapshot | None:
    """Walk an ``IP_ADAPTER_ADDRESSES`` linked list and pick our adapter."""
    wanted = interface_guid.strip().strip("{}").upper()
    node = address
    while node:
        a = w.IP_ADAPTER_ADDRESSES_LH.from_address(node)
        name = ctypes.string_at(a.AdapterName).decode("ascii", errors="replace") if a.AdapterName else ""
        if name.strip().strip("{}").upper() == wanted:
            ipv4 = prefix = None
            candidates: list[tuple[str, int]] = []
            u = a.FirstUnicastAddress
            while u:
                ua = w.IP_ADAPTER_UNICAST_ADDRESS_LH.from_address(u)
                ip = _sockaddr_ipv4(ua.Address.lpSockaddr or 0)
                if ip:
                    candidates.append((ip, int(ua.OnLinkPrefixLength)))
                u = ua.Next
            # Prefer a real address over a 169.254.x.x link-local one.
            candidates.sort(key=lambda c: ipaddress.IPv4Address(c[0]).is_link_local)
            if candidates:
                ipv4, prefix = candidates[0]
            gateway = None
            g = a.FirstGatewayAddress
            while g and gateway is None:
                ga = w.IP_ADAPTER_GATEWAY_ADDRESS_LH.from_address(g)
                gateway = _sockaddr_ipv4(ga.Address.lpSockaddr or 0)
                g = ga.Next
            dhcp = None
            if a.Flags & w.IP_ADAPTER_DHCP_ENABLED:
                dhcp = _sockaddr_ipv4(a.Dhcpv4Server.lpSockaddr or 0)
            friendly = _read_utf16z(a.FriendlyName) if a.FriendlyName else None
            return L3Snapshot(
                if_index=int(a.IfIndex),
                friendly_name=friendly,
                ipv4=ipv4,
                prefix_len=prefix,
                gateway=gateway,
                dhcp_server=dhcp,
            )
        node = a.Next or 0
    return None


class WindowsNetworkOps(NetworkOps):
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("WindowsNetworkOps only works on Windows")
        iphlp = ctypes.WinDLL("iphlpapi.dll", use_last_error=True)  # type: ignore[attr-defined]
        self._GetAdaptersAddresses = iphlp.GetAdaptersAddresses
        self._GetAdaptersAddresses.argtypes = [w.ULONG, w.ULONG, w.PVOID, w.PVOID, POINTER(w.ULONG)]
        self._GetAdaptersAddresses.restype = w.ULONG
        self._IcmpCreateFile = iphlp.IcmpCreateFile
        self._IcmpCreateFile.argtypes = []
        self._IcmpCreateFile.restype = w.HANDLE
        self._IcmpCloseHandle = iphlp.IcmpCloseHandle
        self._IcmpCloseHandle.argtypes = [w.HANDLE]
        self._IcmpCloseHandle.restype = w.BOOL
        self._IcmpSendEcho = iphlp.IcmpSendEcho
        self._IcmpSendEcho.argtypes = [w.HANDLE, w.ULONG, w.PVOID, w.WORD, w.PVOID, w.PVOID, w.DWORD, w.DWORD]
        self._IcmpSendEcho.restype = w.DWORD
        self._FlushIpNetTable2 = iphlp.FlushIpNetTable2
        self._FlushIpNetTable2.argtypes = [w.USHORT, w.ULONG]
        self._FlushIpNetTable2.restype = w.DWORD

    def is_admin(self) -> bool:
        return is_admin()

    def snapshot(self, interface_guid: str) -> L3Snapshot:
        flags = w.GAA_FLAG_INCLUDE_GATEWAYS | w.GAA_FLAG_SKIP_ANYCAST | w.GAA_FLAG_SKIP_MULTICAST | w.GAA_FLAG_SKIP_DNS_SERVER
        size = w.ULONG(16 * 1024)
        for _ in range(4):
            buf = ctypes.create_string_buffer(size.value)
            rc = self._GetAdaptersAddresses(w.AF_INET, flags, None, buf, byref(size))
            if rc == w.ERROR_BUFFER_OVERFLOW:
                continue
            if rc == w.ERROR_NO_DATA:
                break
            if rc != w.ERROR_SUCCESS:
                raise OSError(f"GetAdaptersAddresses failed with code {rc}")
            snap = parse_adapter_addresses(ctypes.addressof(buf), interface_guid)
            if snap is not None:
                return snap
            break
        return L3Snapshot(if_index=None, friendly_name=None, ipv4=None, prefix_len=None, gateway=None)

    def ping(self, host: str, timeout_ms: int) -> PingResult:
        try:
            target = str(ipaddress.IPv4Address(host))
        except ValueError:
            try:
                target = socket.gethostbyname(host)
            except OSError as exc:
                return PingResult(ok=False, rtt_ms=None, error=f"cannot resolve {host}: {exc}")
        handle = self._IcmpCreateFile()
        if not handle or handle == ctypes.c_void_p(-1).value:
            return PingResult(ok=False, rtt_ms=None, error=f"IcmpCreateFile failed ({ctypes.get_last_error()})")
        try:
            payload = b"RoamPredict-ping" * 2
            request = ctypes.create_string_buffer(payload, len(payload))
            reply = ctypes.create_string_buffer(sizeof(w.ICMP_ECHO_REPLY) + len(payload) + 64)
            started = time.perf_counter()
            count = self._IcmpSendEcho(
                handle,
                int.from_bytes(socket.inet_aton(target), "little"),  # IPAddr = network-order bytes in a ULONG
                request,
                len(payload),
                None,
                reply,
                len(reply),
                int(timeout_ms),
            )
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if count == 0:
                code = ctypes.get_last_error()
                what = "timed out" if code == w.IP_REQ_TIMED_OUT else f"no reply (code {code})"
                return PingResult(ok=False, rtt_ms=None, error=what)
            echo = w.ICMP_ECHO_REPLY.from_buffer(reply)
            if echo.Status != w.IP_SUCCESS:
                return PingResult(ok=False, rtt_ms=None, error=f"ICMP status {echo.Status}")
            return PingResult(ok=True, rtt_ms=float(max(echo.RoundTripTime, 0)) or round(elapsed_ms, 2))
        finally:
            self._IcmpCloseHandle(handle)

    def flush_arp(self, snapshot: L3Snapshot) -> CommandResult:
        started = time.perf_counter()
        if not self.is_admin():
            return CommandResult(ok=False, skipped=True, duration_ms=0.0, detail="needs admin (skipped)")
        if snapshot.if_index is not None:
            rc = self._FlushIpNetTable2(w.AF_INET, snapshot.if_index)
            if rc == w.ERROR_SUCCESS:
                return CommandResult(True, False, (time.perf_counter() - started) * 1000.0, f"ARP cache of interface {snapshot.if_index} flushed")
            if rc == w.ERROR_ACCESS_DENIED:
                return CommandResult(False, True, 0.0, "needs admin (skipped)")
        return self._run([system_tool("netsh.exe"), "interface", "ip", "delete", "arpcache"], timeout_s=15, started=started)

    def renew_dhcp(self, snapshot: L3Snapshot) -> CommandResult:
        if not self.is_admin():
            return CommandResult(ok=False, skipped=True, duration_ms=0.0, detail="needs admin (skipped)")
        if not snapshot.friendly_name:
            return CommandResult(ok=False, skipped=True, duration_ms=0.0, detail="adapter name unknown (skipped)")
        return self._run([system_tool("ipconfig.exe"), "/renew", snapshot.friendly_name], timeout_s=60, started=time.perf_counter())

    @staticmethod
    def _run(args: list[str], *, timeout_s: float, started: float) -> CommandResult:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argument list, absolute path, no shell
                args,
                capture_output=True,
                timeout=timeout_s,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CommandResult(False, False, (time.perf_counter() - started) * 1000.0, f"{os.path.basename(args[0])}: {exc}")
        text = _decode(proc.stdout + proc.stderr).strip().replace("\r", "")
        detail = f"{os.path.basename(args[0])} exit {proc.returncode}: {text[:160]}"
        return CommandResult(proc.returncode == 0, False, (time.perf_counter() - started) * 1000.0, detail)
