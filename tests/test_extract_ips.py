#!/usr/bin/env python3

import ipaddress
import pytest

from wg_to_hostname_if import extract_ips

potential_ips = [
    # Bogus IP addresses
    "bogus",
    "256.256.256.256",
    "1.1.-1.1",
    # ip4 addresses
    "192.168.0.1",
    "192.168.0.1/32",
    # ip4 networks
    "10.0.0.0/24",
    # ip6 addresses
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334/128",
    # ip6 networks
    "2001:0db8:85a3::/64",
]


def test_base():
    assert extract_ips(potential_ips) == [
        ipaddress.ip_interface("192.168.0.1"),
        ipaddress.ip_interface("192.168.0.1/32"),
        ipaddress.ip_interface("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        ipaddress.ip_interface("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"),
    ]


def test_type_of_ip():
    assert extract_ips(potential_ips) == extract_ips(
        potential_ips, type_of_ip="address"
    )

    assert extract_ips(potential_ips, type_of_ip="network") == [
        ipaddress.ip_interface("10.0.0.0/24"),
        ipaddress.ip_interface("2001:0db8:85a3::/64"),
    ]

    assert extract_ips(potential_ips, type_of_ip="any") == [
        ipaddress.ip_interface("192.168.0.1"),
        ipaddress.ip_interface("192.168.0.1/32"),
        ipaddress.ip_interface("10.0.0.0/24"),
        ipaddress.ip_interface("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        ipaddress.ip_interface("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"),
        ipaddress.ip_interface("2001:0db8:85a3::/64"),
    ]


def test_version():
    assert extract_ips(potential_ips) == extract_ips(
        potential_ips, version="any"
    )

    assert extract_ips(potential_ips, version=4) == [
        ipaddress.ip_interface("192.168.0.1"),
        ipaddress.ip_interface("192.168.0.1/32"),
    ]

    assert extract_ips(potential_ips, version=6) == [
        ipaddress.ip_interface("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
        ipaddress.ip_interface("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"),
    ]


def test_exceptions():
    with pytest.raises(ValueError):
        extract_ips(potential_ips, type_of_ip="invalid_type")

    with pytest.raises(ValueError):
        extract_ips(potential_ips, version="invalid_version")


def test_skips_invalid():
    assert extract_ips(["192.168.0.1", "invalid_ip"]) == [
        ipaddress.ip_interface("192.168.0.1")
    ]
