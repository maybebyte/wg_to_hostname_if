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

NAME_TO_SECTION_AND_OPTION = {
    "address": ("Interface", "Address"),
    "private_key": ("Interface", "PrivateKey"),
    "allowed_ips": ("Peer", "AllowedIPs"),
    "endpoint": ("Peer", "Endpoint"),
    "public_key": ("Peer", "PublicKey"),
}


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


def init_ini_parser(ini_file_path):
    """
    Receives an INI configuration file as an argument.

    Opens the file, reads it, and returns the appropriate
    configparser.ConfigParser instance.
    """
    with open(file=ini_file_path, mode="r", encoding="utf-8") as f:
        ini_parser = configparser.ConfigParser()
        ini_parser.read_file(f)
    return ini_parser


def names_to_data(ini_parser, name_to_section_and_option):
    """
    ini_parser: a configparser.ConfigParser() instance.

    name_to_section_and_option: a dictionary where the keys are
    names, and the values are each tuples that contain the corresponding
    section and option.

    Extracts configuration data from ini_parser by iterating through
    the name_to_section_and_option dictionary.

    Returns a dictionary where the keys are the names and the values
    are the corresponding data.
    """
    if not isinstance(ini_parser, configparser.ConfigParser):
        raise SystemExit("Expected configparser.ConfigParser instance.")

    name_to_data = {}

    for name, (section, option) in name_to_section_and_option.items():
        name_to_data[name] = wg_ini_parser.get(section, option)

    return name_to_data


def transform_wg_data(wg_config_data):
    """
    Receives a dictionary containing lowercase names of WireGuard
    INI options as the keys and their associated data as the values.

    Performs processing on them such that the values for these names
    are different:

    "endpoint": list containing an IP address and a network port
    "allowed_ips": list containing IP networks/addresses allowed by the
    server
    "address": list containing interface addresses

    Note that this does NOT validate the data.

    Returns a dictionary using the same key names, but with updated
    data.
    """

    new_config_data = wg_config_data

    new_config_data["endpoint"] = wg_config_data["endpoint"].split(":")
    new_config_data["allowed_ips"] = wg_config_data["allowed_ips"].split(",")
    new_config_data["address"] = wg_config_data["address"].split(",")

    return new_config_data


def validate_network_port(port):
    """
    Validate a network port with these checks:

    - Does int succeed?
    - Is it contained within the range 0-65535?

    Returns the port on success. Otherwise, it raises a ValueError.
    """
    port = int(port)
    if not 0 <= port <= 65535:
        raise ValueError(f"{port} is not within the range 0-65535.")
    return port


def validate_wg_key(key, key_name="Key"):
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


def validate_ip(potential_ip, type_of_ip="address", version="any"):
    """
    Given a potential IP, validate it and make sure it matches any
    other specified criteria.

    If type_of_ip is provided, validate_ip will only consider a
    particular kind of IP valid. Types include:

    "address": An IP address. The default.
    "network": A network range.
    "any": Either.

    If version is provided, validate_ip will only consider a
    particular IP version valid. Versions include:

    4: IPv4.
    6: IPv6.
    "any": Either. The default.

    Returns the appropriate ipaddress object based on the value of
    type_of_ip.
    """
    if type_of_ip not in ("address", "network", "any"):
        raise SystemExit(
            'type_of_ip must be "address", "network", or "any"'
        )
    if version not in (4, 6, "any"):
        raise SystemExit('version must be 4, 6, or "any"')

    validated_ip = ipaddress.ip_interface(potential_ip)

    if version != "any" and version != validated_ip.version:
        raise ipaddress.AddressValueError(
            f"{validated_ip} doesn't look like IPv{validated_ip.version}"
        )

    if type_of_ip == "address":
        validated_ip = validated_ip.ip
    elif type_of_ip == "network":
        validated_ip = validated_ip.network

    return validated_ip


def extract_ips(potential_ips, type_of_ip="address", version="any"):
    """
    Searches a list for IPs.

    Returns a dictionary with these entries:
    "ip": list of IPs.
    "ip4": list of IPs (IPv4 only).
    "ip6": list of IPs (IPv6 only).

    If type_of_ip is provided, extract_ips will look for a particular kind of
    IP. Valid types include:

    "address": Look for IP addresses. The default.
    "network": Look for network ranges.
    "any": Look for either.
    """
    ips = {
        "ip": [],
        "ip4": [],
        "ip6": [],
    }

    for ip in potential_ips:
        try:
            ip = validate_ip(ip, type_of_ip, version)
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

    wg_ini_parser = init_ini_parser(INI_FILE)
    wg_data = names_to_data(wg_ini_parser, NAME_TO_SECTION_AND_OPTION)
    new_wg_data = transform_wg_data(wg_data)

    validate_wg_key(new_wg_data["private_key"], key_name="PrivateKey")
    validate_wg_key(new_wg_data["public_key"], key_name="PublicKey")

    wg_allowed_ips = extract_ips(
        new_wg_data["allowed_ips"], type_of_ip="network"
    )
    wg_if_addresses = extract_ips(new_wg_data["address"])

    wg_endpoint_ip, wg_endpoint_port = new_wg_data["endpoint"]
    print("wgkey " + new_wg_data["private_key"])
    print("wgpeer " + new_wg_data["public_key"] + " \\")
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
