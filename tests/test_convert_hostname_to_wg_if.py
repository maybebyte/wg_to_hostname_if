#!/usr/bin/env python3

import ipaddress
import pytest
from wg_to_hostname_if import convert_wg_to_hostname_if


def create_basic_data():
    return {
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


def test_base():
    transformed_wg_data = create_basic_data()

    expected_hostname_if = [
        "wgkey yPlLc8Frd05JcfMBzs/p+53b5tfX29WhQbwuyJkdnEs=",
        "wgpeer YV1sIDB+wgwYqlgxAGnvo2h80v+r7Y5BgHKLoYwt2Xg= \\",
        "\t" + "wgendpoint 73.60.105.217 11507 \\",
        "\t" + "wgaip 0.0.0.0/0 \\",
        "\t" + "wgaip ::/0",
        "inet 192.168.1.23/32",
        "inet6 fd12:3456:789a:1::1/128",
    ]

    assert (
        convert_wg_to_hostname_if(transformed_wg_data) == expected_hostname_if
    )


def test_only_one_wgaip():
    transformed_wg_data = create_basic_data()
    transformed_wg_data["allowed_ips"] = [ipaddress.ip_interface("0.0.0.0/0")]

    expected_hostname_if = [
        "wgkey yPlLc8Frd05JcfMBzs/p+53b5tfX29WhQbwuyJkdnEs=",
        "wgpeer YV1sIDB+wgwYqlgxAGnvo2h80v+r7Y5BgHKLoYwt2Xg= \\",
        "\t" + "wgendpoint 73.60.105.217 11507 \\",
        "\t" + "wgaip 0.0.0.0/0",
        "inet 192.168.1.23/32",
        "inet6 fd12:3456:789a:1::1/128",
    ]

    assert (
        convert_wg_to_hostname_if(transformed_wg_data) == expected_hostname_if
    )


def test_missing_data():
    transformed_wg_data = {}
    with pytest.raises(KeyError):
        convert_wg_to_hostname_if(transformed_wg_data)
