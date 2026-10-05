"""WindowsWlanAdapter end to end against the wlanapi stand-in (see wlan_fakes.py)."""

import time

import pytest
from wlan_fakes import BSS_B, FakeWlanApi

from roampredict.platform.base import WlanEventKind, WlanPermissionError, WlanUnavailableError
from roampredict.platform.windows_wlan import WindowsWlanAdapter, _WlanApi, list_interfaces
from roampredict.platform import win32_structs as w
from roampredict.validate import ValidationError


def make(**kw):
    fake = FakeWlanApi(**kw)
    adapter = WindowsWlanAdapter(api=_WlanApi(fake.dll()))
    return fake, adapter


def test_open_link_status_and_close():
    fake, adapter = make()
    assert adapter.interface().description.startswith("Intel(R) Wi-Fi 6E")
    link = adapter.link_status()
    assert link.connected and link.ssid == "eduroam" and link.bssid == "02:5e:00:00:00:a1"
    assert link.profile_name == "eduroam" and link.auth == "WPA2-Enterprise" and link.onex is True
    assert link.cipher == "CCMP (AES)" and link.rx_rate_mbps == pytest.approx(866.7)
    assert link.rssi_dbm == -63 and link.rssi_source == "rssi" and link.channel == 36
    adapter.close()
    adapter.close()  # idempotent
    assert fake.unregistered and fake.closed


def test_rssi_falls_back_to_signal_quality_once():
    fake, adapter = make(rssi_supported=False)
    link = adapter.link_status()
    assert link.rssi_source == "quality" and link.rssi_dbm == pytest.approx(74 / 2 - 100)
    adapter.link_status()
    assert fake.queries.count(w.wlan_intf_opcode_rssi) == 1  # not asked again
    adapter.close()


def test_implausible_driver_rssi_falls_back_to_quality():
    # A real Intel AX201 reported +27 "dBm" here; RSSI is always negative.
    fake, adapter = make(rssi_value=27)
    link = adapter.link_status()
    assert link.rssi_source == "quality" and link.rssi_dbm == pytest.approx(74 / 2 - 100)
    adapter.link_status()
    assert fake.queries.count(w.wlan_intf_opcode_rssi) == 1  # not trusted again
    adapter.close()


def test_bss_list_scan_and_events():
    fake, adapter = make()
    entries = adapter.bss_list()
    assert [e.bssid for e in entries] == ["02:5e:00:00:00:a1", "02:5e:00:00:00:b1"]
    assert entries[1].channel == 149 and entries[1].capabilities.ft is True
    adapter.request_scan("eduroam")
    assert adapter.wait_for_scan(2.0)
    assert fake.scan_calls == [b"eduroam"]
    assert any(e.kind is WlanEventKind.SCAN_COMPLETE for e in adapter.poll_events())
    assert adapter.poll_events() == []  # drained
    assert fake.freed >= 1  # every Windows allocation is released
    adapter.close()


def test_scan_while_windows_is_already_scanning():
    fake, adapter = make()
    fake.scan_busy = True  # real campus: WlanScan -> 170 "resource in use"
    adapter.request_scan("eduroam")  # no error
    assert adapter.wait_for_scan(2.0)  # the running scan completes
    adapter.close()


def test_missing_location_permission_is_explained():
    fake, adapter = make(bss_denied=True)
    with pytest.raises(WlanPermissionError, match="Location"):
        adapter.bss_list()
    adapter.close()


def test_connect_bssid_success_with_phase_timings():
    fake, adapter = make()
    result = adapter.connect_bssid("eduroam", "eduroam", "02:5E:00:00:00:B1", timeout_s=3.0, auth_stall_s=2.0)
    assert fake.connect_calls == [("eduroam", BSS_B)]  # the profile NAME and exactly one BSSID
    assert result.connected and result.honored and result.final_bssid == "02:5e:00:00:00:b1"
    assert result.disconnect_seen
    assert result.assoc_ms is not None and result.assoc_ms >= 5
    assert result.auth_ms is not None and result.auth_ms >= 20
    names = [name for _, name in result.events]
    assert names.index("associating") < names.index("authenticating") < names.index("connection_complete")
    adapter.close()


def test_connect_stall_is_reported_as_possible_login_prompt():
    fake, adapter = make(connect_mode="stall")
    started = time.monotonic()
    result = adapter.connect_bssid("eduroam", "eduroam", "02:5e:00:00:00:b1", timeout_s=5.0, auth_stall_s=0.3)
    assert time.monotonic() - started < 2.0
    assert result.auth_stalled and not result.connected
    assert "login prompt" in result.failure_reason
    adapter.close()


def test_connect_failure_keeps_the_reason_code():
    fake, adapter = make(connect_mode="fail")
    result = adapter.connect_bssid("eduroam", "eduroam", "02:5e:00:00:00:b1", timeout_s=3.0, auth_stall_s=2.0)
    assert not result.connected and result.reason_code == 0x50005
    assert "0x50005" in result.failure_reason
    adapter.close()


def test_plain_profile_connect_has_no_bssid():
    fake, adapter = make()
    adapter.connect_profile("eduroam")
    assert fake.connect_calls == [("eduroam", None)]
    adapter.close()


def test_inputs_are_validated_before_windows_is_called():
    fake, adapter = make()
    with pytest.raises(ValidationError):
        adapter.connect_bssid("eduroam", "eduroam", "ff:ff:ff:ff:ff:ff", timeout_s=1, auth_stall_s=0.5)
    with pytest.raises(ValidationError):
        adapter.connect_bssid("bad\nname", "eduroam", "02:5e:00:00:00:b1", timeout_s=1, auth_stall_s=0.5)
    assert fake.connect_calls == []
    adapter.close()


def test_profiles_interfaces_and_selection():
    fake, adapter = make()
    assert adapter.profile_names() == ["eduroam", "Home WiFi"]
    assert adapter.reason_text(0x50005) == "reason 0x50005"
    adapter.close()
    assert [i.state for i in list_interfaces(_WlanApi(FakeWlanApi().dll()))] == ["connected"]
    picked = WindowsWlanAdapter("ax211", api=_WlanApi(FakeWlanApi().dll()))
    assert "AX211" in picked.interface().description
    picked.close()
    other = FakeWlanApi()
    with pytest.raises(WlanUnavailableError):
        WindowsWlanAdapter("no-such-adapter", api=_WlanApi(other.dll()))
    assert other.closed  # cleaned up after the failed start
