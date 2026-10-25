import pytest

from nettoolkit.subnet import calculate, split_subnet


def test_basic_ipv4():
    info = calculate("192.168.1.10/24")
    assert info.network == "192.168.1.0"
    assert info.netmask == "255.255.255.0"
    assert info.wildcard == "0.0.0.255"
    assert info.broadcast == "192.168.1.255"
    assert info.first_host == "192.168.1.1"
    assert info.last_host == "192.168.1.254"
    assert info.total_addresses == 256
    assert info.usable_hosts == 254
    assert info.is_private is True


def test_slash_30():
    info = calculate("10.0.0.0/30")
    assert info.usable_hosts == 2
    assert info.first_host == "10.0.0.1"
    assert info.last_host == "10.0.0.2"


def test_slash_31_and_32():
    assert calculate("10.0.0.0/31").usable_hosts == 2
    assert calculate("10.0.0.5/32").usable_hosts == 1


def test_public_address():
    assert calculate("8.8.8.0/24").is_private is False


def test_ipv6():
    info = calculate("2001:db8::/32")
    assert info.version == 6
    assert info.broadcast is None


def test_invalid_input():
    with pytest.raises(ValueError):
        calculate("999.1.1.1/24")


def test_split():
    assert split_subnet("192.168.1.0/24", 26) == [
        "192.168.1.0/26",
        "192.168.1.64/26",
        "192.168.1.128/26",
        "192.168.1.192/26",
    ]


def test_split_invalid_prefix():
    with pytest.raises(ValueError):
        split_subnet("192.168.1.0/24", 24)
