#!/usr/bin/env python3
# Copyright (c) 2023 Ashlen <dev@anthes.is>
#
# Permission to use, copy, modify, and distribute this software for
# any purpose with or without fee is hereby granted, provided that
# the above copyright notice and this permission notice appear in all
# copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Takes a WireGuard configuration file in INI format.
Translates it to hostname.if(5) format.
"""

from base64 import b64decode
import configparser
import ipaddress
import sys


def to_str(bytes_or_str):
    """
    Given a str or bytes instance, return a string instance.
    """
    if isinstance(bytes_or_str, bytes):
        value = bytes_or_str.decode("utf-8")
    else:
        value = bytes_or_str
    return value


def to_bytes(bytes_or_str):
    """
    Given a str or bytes instance, return a bytes instance.
    """
    if isinstance(bytes_or_str, str):
        value = bytes_or_str.encode("utf-8")
    else:
        value = bytes_or_str
    return value


def validate_and_extract_wg_endpoint(endpoint_entry):
    """
    Given the contents of a WireGuard Endpoint entry, return the IP and
    port.

    Validation consists of these steps:
    - Validate the IP address using the ipaddress library.
    - Check that the port number is between 0 and 65535.

    IP is returned as a string. Port is returned as an int.
    """
    endpoint_entry_as_str = to_str(endpoint_entry)
    endpoint_ip, endpoint_port = endpoint_entry_as_str.split(":")

    validated_ip = ipaddress.ip_address(endpoint_ip)
    endpoint_port = int(endpoint_port)

    if not 0 <= endpoint_port <= 65535:
        raise ValueError(f"{endpoint_port} is not a valid port number.")

    validated_port = endpoint_port

    return validated_ip, validated_port


def check_wg_key_validity(key, key_name="Key"):
    """
    Validate the provided WireGuard key.

    Validation consists of these steps:
    - base64 decode the key.
    - check if its decoded length is 32 bytes.

    Raises a ValueError if the length check fails.
    """
    key_as_bytes = to_bytes(key)
    b64decoded_key = b64decode(key_as_bytes, validate=True)
    if len(b64decoded_key) != 32:
        raise ValueError(f"{key_name} didn't base64 decode to 32 bytes.")
    return True


def find_ips(potential_ips, look_for="addresses"):
    """
    Searches a list for IPs.

    Returns a dictionary with these entries:
    "ip": list of IPs.
    "ip4": list of IPs (IPv4 only).
    "ip6": list of IPs (IPv6 only).

    If look_for is provided, find_ips will look for a particular kind of
    IP. Valid types include:

    "addresses": Look for IP addresses. The default.
    "network": Look for network ranges.
    """
    ips = {
        "ip": [],
        "ip4": [],
        "ip6": [],
    }

    for ip in potential_ips:
        try:
            ip = ipaddress.ip_interface(ip)
            if look_for == "addresses":
                ip = ip.ip
            elif look_for == "networks":
                ip = ip.network
            else:
                raise ValueError('look_for must be "addresses" or "networks".')
        except ipaddress.AddressValueError:
            continue

        if ip.version == 4:
            ips["ip4"].append(ip)
        elif ip.version == 6:
            ips["ip6"].append(ip)

        ips["ip"].append(ip)

    return ips


if __name__ == "__main__":
    try:
        INI_FILE = sys.argv[1]
    except IndexError:
        print(
            f"{sys.argv[0]} needs a WireGuard configuration file.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(file=INI_FILE, mode="r", encoding="utf-8") as f:
        ini_parser = configparser.ConfigParser()
        ini_parser.read_file(f)

    wg_config_data = {
        "address": ini_parser.get(section="Interface", option="Address"),
        "private_key": ini_parser.get(
            section="Interface", option="PrivateKey"
        ),
        "allowed_ips": ini_parser.get(section="Peer", option="AllowedIPs"),
        "endpoint": ini_parser.get(section="Peer", option="Endpoint"),
        "public_key": ini_parser.get(section="Peer", option="PublicKey"),
    }

    check_wg_key_validity(wg_config_data["private_key"], key_name="PrivateKey")
    check_wg_key_validity(wg_config_data["public_key"], key_name="PublicKey")

    wg_endpoint_ip, wg_endpoint_port = validate_and_extract_wg_endpoint(
        wg_config_data["endpoint"]
    )

    wg_allowed_ips = find_ips(
        wg_config_data["allowed_ips"].split(","), look_for="networks"
    )
    wg_if_addresses = find_ips(
        wg_config_data["address"].split(","), look_for="addresses"
    )

    print("wgkey " + wg_config_data["private_key"])
    print("wgpeer " + wg_config_data["public_key"] + " \\")
    print("\t" + f"wgendpoint {wg_endpoint_ip} {wg_endpoint_port} \\")

    for i, allowed_ip in enumerate(wg_allowed_ips["ip"]):
        if i == len(wg_allowed_ips["ip"]) - 1:
            print("\t" + f"wgaip {allowed_ip}")
        else:
            print("\t" + f"wgaip {allowed_ip} \\")

    for ip4_addr in wg_if_addresses["ip4"]:
        print(f"inet {ip4_addr}")

    for ip6_addr in wg_if_addresses["ip6"]:
        print(f"inet6 {ip6_addr}")
