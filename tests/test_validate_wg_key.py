#!/usr/bin/env python3

from wg_to_hostname_if import validate_wg_key, to_bytes
import pytest
import base64


def test_valid_keys():
    # Should be obvious, but don't use these anywhere else. They were
    # generated purely for testing.
    wg_keys = {
        "private_key_str": "sMKUucORyDA4wypb1bSf6Vngn3FBSsF3BFhwv5nhq2g=",
        "public_key_str": "cfKd+hFh4w6CXTqROX9/mQoXuQ/EjcmHO3Z1lTGBuBo=",
    }

    wg_keys["private_key_bytes"] = to_bytes(wg_keys["private_key_str"])
    wg_keys["public_key_bytes"] = to_bytes(wg_keys["public_key_str"])

    for v in wg_keys.values():
        assert validate_wg_key(v) is True


def test_invalid_keys():
    b32_key = base64.b32encode(to_bytes("abcdefghijklmnopqrstuvwxyz123456"))

    with pytest.raises(ValueError):
        validate_wg_key("invalid_key")

    with pytest.raises(ValueError):
        validate_wg_key(b32_key)
