"""How long switches take, and when the link counts as "down".

EVERY NUMBER HERE IS AN ASSUMPTION, not a measurement.  They are plausible for
a WPA2-Enterprise (PEAP/EAP-TTLS) campus network, but yours can differ a lot -
eduroam requests can even travel to another university's server.  Replace them
with the medians that ``roampredict report`` prints after a few days of use.

Two kinds of switch are modelled:

* driver roam (Windows' own roaming): reassociation inside the same
  connection.  Uses 802.11r FT when the network offers it; otherwise PMKSA
  caching if the AP still has our key; otherwise a full 802.1X exchange.
  No DHCP (the IP address stays).

* app switch (RoamPredict/threshold via WlanConnect): most likely Windows drops
  the old link and connects again.  We ASSUME that 802.11r is NOT used for this
  (``app_switch_uses_ft=False``) - set it to True to see the best case.  PMKSA
  caching still applies, and Windows re-confirms its DHCP lease afterwards.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

__all__ = ["Timing", "SwitchParts", "LinkModel"]


@dataclass(frozen=True)
class Timing:
    mean_ms: float
    sd_ms: float

    def sample(self, rng: random.Random) -> float:
        """Seconds, never below 30% of the mean."""
        return max(0.3 * self.mean_ms, rng.gauss(self.mean_ms, self.sd_ms)) / 1000.0


@dataclass(frozen=True)
class SwitchParts:
    disconnect_s: float
    assoc_s: float
    auth_s: float
    dhcp_s: float
    auth_kind: str  # "ft" | "pmk_cache" | "full_eap"

    @property
    def total_s(self) -> float:
        return self.disconnect_s + self.assoc_s + self.auth_s + self.dhcp_s


@dataclass(frozen=True)
class LinkModel:
    link_floor_dbm: float = -82.0  # below this the link counts as down (outage)
    assoc: Timing = Timing(40, 10)
    full_eap: Timing = Timing(1200, 350)  # full 802.1X/EAP with the campus RADIUS server
    pmk_cached: Timing = Timing(120, 30)  # cached PMKSA: only the 4-way handshake
    ft: Timing = Timing(50, 15)  # 802.11r fast transition
    wlanconnect_disconnect: Timing = Timing(80, 20)  # extra cost of disconnect -> reconnect
    dhcp_revalidate: Timing = Timing(150, 60)  # Windows re-confirms the lease after a reconnect
    ap_pmk_lifetime_s: float = 8 * 3600.0  # how long the AP side keeps our key (assumption)
    client_pmk_ttl_s: float = 12 * 3600.0  # Windows' documented default PMKCacheTTL (720 min)
    app_switch_uses_ft: bool = False

    def pmk_valid(self, last_auth_t: float | None, now: float) -> bool:
        if last_auth_t is None:
            return False
        return 0 <= now - last_auth_t <= min(self.ap_pmk_lifetime_s, self.client_pmk_ttl_s)

    def _auth(self, rng: random.Random, *, ft: bool, pmk_cached: bool) -> tuple[float, str]:
        if ft:
            return self.ft.sample(rng), "ft"
        if pmk_cached:
            return self.pmk_cached.sample(rng), "pmk_cache"
        return self.full_eap.sample(rng), "full_eap"

    def driver_roam(self, rng: random.Random, *, ft_available: bool, pmk_cached: bool) -> SwitchParts:
        auth_s, kind = self._auth(rng, ft=ft_available, pmk_cached=pmk_cached)
        return SwitchParts(0.0, self.assoc.sample(rng), auth_s, 0.0, kind)

    def app_switch(self, rng: random.Random, *, ft_available: bool, pmk_cached: bool) -> SwitchParts:
        auth_s, kind = self._auth(rng, ft=ft_available and self.app_switch_uses_ft, pmk_cached=pmk_cached)
        return SwitchParts(
            self.wlanconnect_disconnect.sample(rng),
            self.assoc.sample(rng),
            auth_s,
            self.dhcp_revalidate.sample(rng),
            kind,
        )

    def reconnect(self, rng: random.Random, *, pmk_cached: bool) -> SwitchParts:
        """Windows auto-connect after the link was lost (fresh association + DHCP)."""
        auth_s, kind = self._auth(rng, ft=False, pmk_cached=pmk_cached)
        return SwitchParts(0.0, self.assoc.sample(rng), auth_s, self.dhcp_revalidate.sample(rng), kind)

    def describe(self) -> list[str]:
        return [
            f"link counts as down below {self.link_floor_dbm:.0f} dBm",
            f"full 802.1X/EAP {self.full_eap.mean_ms:.0f} ms, cached key {self.pmk_cached.mean_ms:.0f} ms, "
            f"802.11r {self.ft.mean_ms:.0f} ms, association {self.assoc.mean_ms:.0f} ms",
            f"WlanConnect switch adds {self.wlanconnect_disconnect.mean_ms:.0f} ms disconnect + "
            f"{self.dhcp_revalidate.mean_ms:.0f} ms DHCP re-check; 802.11r used by it: {self.app_switch_uses_ft}",
            f"AP keeps cached keys {self.ap_pmk_lifetime_s / 3600:.0f} h (assumed), Windows {self.client_pmk_ttl_s / 3600:.0f} h",
        ]
