#!/usr/bin/env python3

from wg_to_hostname_if import transform_wg_data
import pytest
import ipaddress


def test_basic_config():
    wg_config_data = {
        "endpoint": "192.168.1.1:51820",
        "allowed_ips": "10.0.0.0/24,192.168.0.0/16",
        "address": "10.0.0.1/32,192.168.1.1/32",
    }
    expected_result = {
        "endpoint": ["192.168.1.1", "51820"],
        "allowed_ips": [
            ipaddress.ip_interface("10.0.0.0/24"),
            ipaddress.ip_interface("192.168.0.0/16"),
        ],
        "address": [
            ipaddress.ip_interface("10.0.0.1"),
            ipaddress.ip_interface("192.168.1.1"),
        ],
    }
    assert transform_wg_data(wg_config_data) == expected_result


def test_config_with_spaces():
    wg_config_data = {
        "endpoint": "192.168.1.1:51820",
        "allowed_ips": "10.0.0.0/24, 192.168.0.0/16",
        "address": "10.0.0.1/32, 192.168.1.1/32",
    }
    expected_result = {
        "endpoint": ["192.168.1.1", "51820"],
        "allowed_ips": [
            ipaddress.ip_interface("10.0.0.0/24"),
            ipaddress.ip_interface("192.168.0.0/16"),
        ],
        "address": [
            ipaddress.ip_interface("10.0.0.1"),
            ipaddress.ip_interface("192.168.1.1"),
        ],
    }
    assert transform_wg_data(wg_config_data) == expected_result


def test_config_with_invalid_ips():
    wg_config_data = {
        "endpoint": "192.168.1.1:51820",
        "allowed_ips": "10.0.0.0/24,invalid_ip",
        "address": "bogus,192.168.1.1/32",
    }
    expected_result = {
        "endpoint": ["192.168.1.1", "51820"],
        "allowed_ips": [ipaddress.ip_interface("10.0.0.0/24")],
        "address": [ipaddress.ip_interface("192.168.1.1/32")],
    }
    assert transform_wg_data(wg_config_data) == expected_result


def test_empty_config():
    wg_config_data = {}
    with pytest.raises(KeyError):
        transform_wg_data(wg_config_data)
