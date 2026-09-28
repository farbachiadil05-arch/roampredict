"""Parse 802.11 information elements (IEs) to see which fast-roaming features an
AP advertises.

Windows exposes the raw IEs of every BSS it has seen (``WLAN_BSS_ENTRY``
``ulIeOffset`` / ``ulIeSize``, taken from the last beacon or probe response).
They come from the air, so they are untrusted input: every length is
bounds-checked and malformed data gives "unknown", never an exception.

What we look for:

* 802.11r (Fast Transition): an FT AKM suite in the RSN element and/or a
  Mobility Domain element (ID 54).
* 802.11k: RM Enabled Capabilities element (ID 70), "neighbor report" bit.
* 802.11v: Extended Capabilities element (ID 127), bit 19 "BSS Transition".
* 802.11i pre-authentication: RSN Capabilities bit 0.

PMKSA caching is NOT advertised in beacons, so it cannot be detected here -
only measured (``roampredict report``).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from roampredict.platform.base import RoamCapabilities

__all__ = [
    "iter_elements",
    "RsnInfo",
    "parse_rsn",
    "parse_capabilities",
    "AKM_NAMES",
    "FT_AKMS",
    "ENTERPRISE_AKMS",
]

EID_SSID = 0
EID_BSS_LOAD = 11
EID_RSN = 48
EID_MOBILITY_DOMAIN = 54
EID_RM_ENABLED_CAPABILITIES = 70
EID_EXTENDED_CAPABILITIES = 127

RSN_OUI = b"\x00\x0f\xac"

AKM_NAMES = {
    1: "802.1X",
    2: "PSK",
    3: "FT-802.1X",
    4: "FT-PSK",
    5: "802.1X-SHA256",
    6: "PSK-SHA256",
    8: "SAE",
    9: "FT-SAE",
    11: "802.1X-SuiteB",
    12: "802.1X-SuiteB-192",
    13: "FT-802.1X-SHA384",
    14: "FILS-SHA256",
    15: "FILS-SHA384",
    16: "FT-FILS-SHA256",
    17: "FT-FILS-SHA384",
    18: "OWE",
    19: "FT-PSK-SHA384",
    20: "PSK-SHA384",
    24: "SAE-EXT-KEY",
    25: "FT-SAE-EXT-KEY",
}
FT_AKMS = frozenset({3, 4, 9, 13, 16, 17, 19, 25})
ENTERPRISE_AKMS = frozenset({1, 3, 5, 11, 12, 13, 14, 15, 16, 17})


def iter_elements(data: bytes) -> Iterator[tuple[int, bytes]]:
    """Yield ``(element_id, body)``; stops at the first truncated element."""
    pos = 0
    n = len(data)
    while pos + 2 <= n:
        eid = data[pos]
        end = pos + 2 + data[pos + 1]
        if end > n:
            return
        yield eid, data[pos + 2 : end]
        pos = end


def _suite(raw: bytes) -> int:
    """Standard suites (00-0F-AC) -> their type number; vendor suites -> a
    large number that cannot collide with a standard type."""
    if raw[:3] == RSN_OUI:
        return raw[3]
    return (int.from_bytes(raw[:3], "big") << 8) | raw[3]


@dataclass(frozen=True)
class RsnInfo:
    version: int
    group_cipher: int | None
    pairwise_ciphers: tuple[int, ...]
    akms: tuple[int, ...]
    capabilities: int | None

    @property
    def preauth(self) -> bool | None:
        return None if self.capabilities is None else bool(self.capabilities & 0x0001)

    @property
    def mfp_required(self) -> bool | None:
        return None if self.capabilities is None else bool(self.capabilities & 0x0040)

    @property
    def mfp_capable(self) -> bool | None:
        return None if self.capabilities is None else bool(self.capabilities & 0x0080)


def parse_rsn(body: bytes) -> RsnInfo | None:
    """Parse an RSN element body; ``None`` if it is malformed.

    Every field after the version is optional in the standard; missing
    trailing fields are allowed, a list count that runs past the end is not.
    """
    if len(body) < 2:
        return None
    version = int.from_bytes(body[0:2], "little")
    pos = 2
    group = None
    pairwise: tuple[int, ...] = ()
    akms: tuple[int, ...] = ()
    caps = None
    if len(body) >= pos + 4:
        group = _suite(body[pos : pos + 4])
        pos += 4
    for field in ("pairwise", "akm"):
        if len(body) < pos + 2:
            break
        count = int.from_bytes(body[pos : pos + 2], "little")
        pos += 2
        if len(body) < pos + 4 * count:
            return None
        suites = tuple(_suite(body[pos + 4 * i : pos + 4 * i + 4]) for i in range(count))
        pos += 4 * count
        if field == "pairwise":
            pairwise = suites
        else:
            akms = suites
    if len(body) >= pos + 2:
        caps = int.from_bytes(body[pos : pos + 2], "little")
    return RsnInfo(version, group, pairwise, akms, caps)


def parse_capabilities(ies: bytes) -> RoamCapabilities:
    """What an AP advertises.  No IE data at all -> everything unknown."""
    if not ies:
        return RoamCapabilities()
    rsn: RsnInfo | None = None
    rsn_seen = False
    mde: bytes | None = None
    rm: bytes | None = None
    ext: bytes | None = None
    load: bytes | None = None
    for eid, body in iter_elements(ies):
        if eid == EID_RSN and not rsn_seen:
            rsn_seen = True
            rsn = parse_rsn(body)
        elif eid == EID_MOBILITY_DOMAIN and mde is None:
            mde = body
        elif eid == EID_RM_ENABLED_CAPABILITIES and rm is None:
            rm = body
        elif eid == EID_EXTENDED_CAPABILITIES and ext is None:
            ext = body
        elif eid == EID_BSS_LOAD and load is None:
            load = body

    akms = rsn.akms if rsn is not None else ()
    malformed_rsn = rsn_seen and rsn is None
    mde_ok = mde is not None and len(mde) >= 3
    if malformed_rsn and not mde_ok:
        ft: bool | None = None
    else:
        ft = bool(set(akms) & FT_AKMS) or mde_ok
    return RoamCapabilities(
        ft=ft,
        ft_over_ds=bool(mde[2] & 0x01) if mde_ok and mde is not None else (None if ft is None else False),
        mobility_domain=mde[0:2].hex() if mde_ok and mde is not None else None,
        rrm_neighbor_report=bool(rm[0] & 0x02) if rm else False,
        bss_transition=len(ext) >= 3 and bool(ext[2] & 0x08) if ext is not None else False,
        rsn_preauth=None if malformed_rsn else (rsn.preauth if rsn is not None else False),
        akm_suites=akms,
        enterprise=None if malformed_rsn else bool(set(akms) & ENTERPRISE_AKMS),
        mfp_capable=None if rsn is None else rsn.mfp_capable,
        mfp_required=None if rsn is None else rsn.mfp_required,
        bss_load_stations=int.from_bytes(load[0:2], "little") if load is not None and len(load) >= 3 else None,
        bss_load_utilization=load[2] / 255.0 if load is not None and len(load) >= 3 else None,
    )
