import pytest

from roampredict.validate import (
    ValidationError,
    bssid_from_bytes,
    bssid_to_bytes,
    is_valid_bssid,
    normalize_bssid,
    ssid_from_bytes,
    validate_profile_name,
    validate_ssid,
)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("AA:BB:CC:DD:EE:01", "aa:bb:cc:dd:ee:01"),
        ("aa-bb-cc-dd-ee-01", "aa:bb:cc:dd:ee:01"),
        ("aabbccddee01", "aa:bb:cc:dd:ee:01"),
        ("  02:5e:00:00:00:a1 ", "02:5e:00:00:00:a1"),  # locally administered is fine
    ],
)
def test_normalize_accepts_common_formats(raw, expected):
    assert normalize_bssid(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "aa:bb:cc:dd:ee",  # too short
        "aa:bb:cc:dd:ee:ff:00",  # too long
        "aa:bb-cc:dd:ee:01",  # mixed separators
        "gg:bb:cc:dd:ee:01",  # not hex
        "00:00:00:00:00:00",  # all zero
        "ff:ff:ff:ff:ff:ff",  # broadcast
        "01:00:5e:00:00:01",  # multicast
        "",
        "aa:bb:cc:dd:ee:01; rm -rf /",
    ],
)
def test_normalize_rejects_bad_input(raw):
    with pytest.raises(ValidationError):
        normalize_bssid(raw)
    assert not is_valid_bssid(raw)


def test_normalize_rejects_non_strings():
    for value in (None, 42, b"aa:bb:cc:dd:ee:01", ["aa"]):
        with pytest.raises(ValidationError):
            normalize_bssid(value)


def test_bytes_round_trip():
    raw = bytes.fromhex("f4dbe6112201")
    assert bssid_from_bytes(raw) == "f4:db:e6:11:22:01"
    assert bssid_to_bytes("F4-DB-E6-11-22-01") == raw
    with pytest.raises(ValidationError):
        bssid_from_bytes(b"\x00" * 6)
    with pytest.raises(ValidationError):
        bssid_from_bytes(b"\x01\x02\x03")


def test_ssid_validation():
    assert validate_ssid("eduroam") == "eduroam"
    assert validate_ssid("x" * 32) == "x" * 32
    for bad in ("", "x" * 33, "é" * 17, "a\x00b", None):
        with pytest.raises(ValidationError):
            validate_ssid(bad)


def test_profile_name_validation():
    assert validate_profile_name("eduroam") == "eduroam"
    assert validate_profile_name("Campus WiFi (802.1X)") == "Campus WiFi (802.1X)"
    for bad in ("", "a" * 256, "bad\nname", "tab\tname", 7):
        with pytest.raises(ValidationError):
            validate_profile_name(bad)


def test_ssid_from_bytes_never_fails():
    assert ssid_from_bytes(b"eduroam") == "eduroam"
    assert ssid_from_bytes(b"\xff\xfe") == "��"
