#!/usr/bin/env python3

from wg_to_hostname_if import transform_wg_data
import pytest
import ipaddress


def create_basic_data():
    return {
        "address": "192.168.1.23/32,fd12:3456:789a:1::1/128",
        "allowed_ips": "0.0.0.0/0,::0/0",
        "endpoint": "73.60.105.217:11507",
        "private_key": "yPlLc8Frd05JcfMBzs/p+53b5tfX29WhQbwuyJkdnEs=",
        "public_key": "YV1sIDB+wgwYqlgxAGnvo2h80v+r7Y5BgHKLoYwt2Xg=",
    }, {
        "endpoint": ["73.60.105.217", "11507"],
        "allowed_ips": [
            ipaddress.ip_interface("0.0.0.0/0"),
            ipaddress.ip_interface("::0/0"),
        ],
        "address": [
            ipaddress.ip_interface("192.168.1.23"),
            ipaddress.ip_interface("fd12:3456:789a:1::1"),
        ],
        "private_key": "yPlLc8Frd05JcfMBzs/p+53b5tfX29WhQbwuyJkdnEs=",
        "public_key": "YV1sIDB+wgwYqlgxAGnvo2h80v+r7Y5BgHKLoYwt2Xg=",
    }


def test_basic_config():
    wg_config_data, expected_result = create_basic_data()
    assert transform_wg_data(wg_config_data) == expected_result


def test_config_with_spaces():
    wg_config_data, expected_result = create_basic_data()
    wg_config_data["address"] = "192.168.1.23/32, fd12:3456:789a:1::1/128"
    wg_config_data["allowed_ips"] = "0.0.0.0/0, ::0/0"
    assert transform_wg_data(wg_config_data) == expected_result


def test_config_with_invalid_ips():
    wg_config_data, expected_result = create_basic_data()
    wg_config_data["address"] = "bogus,192.168.1.23/32,fd12:3456:789a:1::1/128"
    wg_config_data["allowed_ips"] = "0.0.0.0/0,::0/0,invalid"
    assert transform_wg_data(wg_config_data) == expected_result


def test_empty_config():
    wg_config_data = {}
    with pytest.raises(KeyError):
        transform_wg_data(wg_config_data)
