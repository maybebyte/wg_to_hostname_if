#!/usr/bin/env python3

import pytest
from wg_to_hostname_if import validate_ips


def test_valid_ips():
    potential_ips = ["192.168.0.1", "10.0.0.1", "172.16.0.1"]
    assert validate_ips(potential_ips) is True


def test_invalid_ips():
    potential_ips = ["192.168.0.1", "10.0.0.1", "172.16.0.1", "invalid"]
    with pytest.raises(ValueError):
        validate_ips(potential_ips)


def test_invalid_argument_type():
    potential_ips = "192.168.0.1"
    with pytest.raises(TypeError):
        validate_ips(potential_ips)


def test_empty_list():
    potential_ips = []
    with pytest.raises(ValueError):
        validate_ips(potential_ips)
