#!/usr/bin/env python3

import sys

import pytest

from wg_to_hostname_if import parse_cli_arguments


def test_parse_cli_arguments(monkeypatch):
    monkeypatch.setattr(
        "sys.argv", ["script.py", "-m", "1500", "-t", "10", "tests/test.ini"]
    )
    arguments = parse_cli_arguments()
    assert arguments.filename == "tests/test.ini"
    assert arguments.MTU == 1500
    assert arguments.ADD_ROUTES is False
    assert arguments.WGRTABLE == 10


def test_parse_cli_arguments_no_args(monkeypatch):
    monkeypatch.setattr("sys.argv", ["script.py"])
    arguments = parse_cli_arguments()
    assert arguments.filename == sys.stdin
    assert arguments.MTU is None
    assert arguments.ADD_ROUTES is False
    assert arguments.WGRTABLE is None


def test_parse_cli_arguments_wgrtable_0(monkeypatch):
    monkeypatch.setattr("sys.argv", ["script.py", "-t", "0"])
    arguments = parse_cli_arguments()
    assert arguments.filename == sys.stdin
    assert arguments.MTU is None
    assert arguments.ADD_ROUTES is False
    assert arguments.WGRTABLE == 0


def test_parse_cli_arguments_invalid_wgrtable(monkeypatch):
    monkeypatch.setattr("sys.argv", ["script.py", "-t", "256"])
    with pytest.raises(SystemExit) as system_exit:
        parse_cli_arguments()
        assert system_exit.value.code == 1


def test_parse_cli_arguments_invalid_mtu(monkeypatch):
    monkeypatch.setattr("sys.argv", ["script.py", "-m", "10000"])
    with pytest.raises(SystemExit) as system_exit:
        parse_cli_arguments()
        assert system_exit.value.code == 1
