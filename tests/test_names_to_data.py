#!/usr/bin/env python3

import configparser
import pytest

from wg_to_hostname_if import names_to_data

NAME_TO_SECTION_AND_OPTION = {
    "address": ("Interface", "Address"),
    "private_key": ("Interface", "PrivateKey"),
    "allowed_ips": ("Peer", "AllowedIPs"),
    "endpoint": ("Peer", "Endpoint"),
    "public_key": ("Peer", "PublicKey"),
}

EXPECTED_RESULT = {
    "private_key": "yPlLc8Frd05JcfMBzs/p+53b5tfX29WhQbwuyJkdnEs=",
    "address": "192.168.1.23/32,fd12:3456:789a:1::1/128",
    "allowed_ips": "0.0.0.0/0,::0/0",
    "endpoint": "73.60.105.217:11507",
    "public_key": "YV1sIDB+wgwYqlgxAGnvo2h80v+r7Y5BgHKLoYwt2Xg=",
}


@pytest.fixture
def ini_parser():
    parser = configparser.ConfigParser()
    parser.read("tests/test.ini")
    return parser


def test_names_to_data(ini_parser):
    assert (
        names_to_data(ini_parser, NAME_TO_SECTION_AND_OPTION)
        == EXPECTED_RESULT
    )


def test_names_to_data_invalid_parser():
    with pytest.raises(TypeError):
        names_to_data({}, NAME_TO_SECTION_AND_OPTION)
