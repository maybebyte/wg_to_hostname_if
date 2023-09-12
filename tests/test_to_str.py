#!/usr/bin/env python3

from wg_to_hostname_if import to_str


def test_bytes_to_str():
    assert to_str(b"hello") == "hello"


def test_str_to_str():
    assert to_str("world") == "world"


def test_empty_bytes_to_str():
    assert to_str(b"") == ""


def test_empty_str_to_str():
    assert to_str("") == ""
