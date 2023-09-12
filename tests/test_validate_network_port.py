#!/usr/bin/env python3

from wg_to_hostname_if import validate_network_port
import pytest


def test_valid_ports():
    assert validate_network_port(80) == 80
    assert validate_network_port(0) == 0
    assert validate_network_port(65535) == 65535


def test_invalid_ports():
    with pytest.raises(ValueError):
        validate_network_port(-1)

    with pytest.raises(ValueError):
        validate_network_port(65536)

    with pytest.raises(ValueError):
        validate_network_port("abc")
