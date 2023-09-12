#!/usr/bin/env python3

from wg_to_hostname_if import to_str


def test_bytes_to_str():
    assert to_str(b"hello") == "hello"
    assert to_str(b"") == ""


def test_str_to_str():
    assert to_str("world") == "world"
    assert to_str("") == ""
