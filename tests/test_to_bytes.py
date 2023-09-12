#!/usr/bin/env python3


from wg_to_hostname_if import to_bytes


def test_bytes_to_bytes():
    assert to_bytes(b"hello") == b"hello"


def test_str_to_bytes():
    assert to_bytes("world") == b"world"


def test_empty_bytes_to_bytes():
    assert to_bytes(b"") == b""


def test_empty_str_to_bytes():
    assert to_bytes("") == b""
