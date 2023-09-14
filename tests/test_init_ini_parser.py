#!/usr/bin/env python3

import configparser
import io
import sys

import pytest

from wg_to_hostname_if import init_ini_parser


def test_with_file_path():
    ini_file = "tests/test.ini"
    ini_parser = init_ini_parser(ini_file)

    assert isinstance(ini_parser, configparser.ConfigParser)
    assert ini_parser.has_section("Peer")
    assert ini_parser.get("Peer", "Endpoint") == "73.60.105.217:11507"


def test_with_stdin(monkeypatch):
    ini_file = "-"
    monkeypatch.setattr(
        "sys.stdin", io.StringIO("[section1]\nkey1 = value1")
    )
    ini_parser = init_ini_parser(ini_file)

    assert isinstance(ini_parser, configparser.ConfigParser)
    assert ini_parser.has_section("section1")
    assert ini_parser.get("section1", "key1") == "value1"


def test_with_text_io():
    ini_file = io.StringIO("[section1]\nkey1 = value1")
    ini_parser = init_ini_parser(ini_file)

    assert isinstance(ini_parser, configparser.ConfigParser)
    assert ini_parser.has_section("section1")
    assert ini_parser.get("section1", "key1") == "value1"
