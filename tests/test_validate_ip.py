#!/usr/bin/env python3

import ipaddress
import pytest

from wg_to_hostname_if import validate_ip


def test_address():
    ip = "192.168.1.1"
    result = validate_ip(ip)
    assert isinstance(result, ipaddress.IPv4Interface)
    assert str(result.ip) == ip


def test_address_with_prefixlen():
    ip = "192.168.1.1/32"
    result = validate_ip(ip)
    assert isinstance(result, ipaddress.IPv4Interface)
    assert str(result) == ip


def test_address_v4():
    ip = "10.0.0.1"
    result = validate_ip(ip, version=4)
    assert isinstance(result, ipaddress.IPv4Interface)
    assert str(result.ip) == ip


def test_address_v6():
    ip = "2001:db8:85a3::8a2e:370:7334"
    result = validate_ip(ip, version=6)
    assert isinstance(result, ipaddress.IPv6Interface)
    assert str(result.ip) == ip


def test_network():
    ip = "192.168.0.0/16"
    result = validate_ip(ip, type_of_ip="network")
    assert isinstance(result, ipaddress.IPv4Interface)
    assert str(result.network) == ip


def test_network_v4():
    ip = "10.0.0.0/8"
    result = validate_ip(ip, version=4, type_of_ip="network")
    assert isinstance(result, ipaddress.IPv4Interface)
    assert str(result.network) == ip


def test_network_v6():
    ip = "2001:db8:85a3::/64"
    result = validate_ip(ip, version=6, type_of_ip="network")
    assert isinstance(result, ipaddress.IPv6Interface)
    assert str(result.network) == ip


def test_any_version():
    ip = "2001:db8:85a3::8a2e:370:7334"
    result = validate_ip(ip, version="any")
    assert isinstance(result, ipaddress.IPv6Interface)
    assert str(result.ip) == ip


def test_any_type():
    ip = "192.168.1.0/24"
    result = validate_ip(ip, type_of_ip="any")
    assert isinstance(result, ipaddress.IPv4Interface)
    assert str(result.network) == ip


def test_default_version():
    ip = "2001:db8:85a3::8a2e:370:7334"
    result = validate_ip(ip, version="any")
    explicit_result = validate_ip(ip)
    assert result == explicit_result


def test_default_type():
    ip = "192.168.1.1"
    result = validate_ip(ip)
    explicit_result = validate_ip(ip, type_of_ip="address")
    assert result == explicit_result


def test_mismatched_version():
    ip = "192.168.0.1"
    with pytest.raises(ipaddress.AddressValueError):
        validate_ip(ip, version=6)


def test_invalid_type():
    ip = "192.168.0.1"
    with pytest.raises(ValueError):
        validate_ip(ip, type_of_ip="invalid")


def test_invalid_version():
    ip = "192.168.0.1"
    with pytest.raises(ValueError):
        validate_ip(ip, version=5)


def test_invalid_address():
    ip = "192.168.0.0/16"
    with pytest.raises(ipaddress.AddressValueError):
        validate_ip(ip, type_of_ip="address")


def test_invalid_network():
    ip = "192.168.0.1"
    with pytest.raises(ipaddress.AddressValueError):
        validate_ip(ip, type_of_ip="network")
