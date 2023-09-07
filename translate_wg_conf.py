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


def init_ini_parser(ini_file_path: str) -> configparser.ConfigParser:
    """
    Receives an INI configuration file as an argument.

    Opens the file, reads it, and returns the appropriate
    configparser.ConfigParser instance.
    """
    with open(file=ini_file_path, mode="r", encoding="utf-8") as f:
        ini_parser = configparser.ConfigParser()
        ini_parser.read_file(f)
    return ini_parser


def names_to_data(
    ini_parser: configparser.ConfigParser, name_to_section_and_option: dict
) -> dict:
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


def transform_wg_data(wg_config_data: dict) -> dict:
    """
    Receives a dictionary containing lowercase names of WireGuard
    INI options as the keys and their associated data as the values.

    Performs processing on them such that the values for these names
    are different:

    "endpoint": list containing an IP address and a network port
    "allowed_ips": list containing IP networks/addresses allowed by the
    server
    "address": list containing interface addresses

    Returns a dictionary using the same key names, but with updated
    data.
    """
    new_config_data = wg_config_data

    new_config_data["endpoint"] = new_config_data["endpoint"].split(":")

    new_config_data["allowed_ips"] = extract_ips(
        new_config_data["allowed_ips"].split(","), type_of_ip="network"
    )

    new_config_data["address"] = extract_ips(
        new_config_data["address"].split(",")
    )

    return new_config_data


def validate_network_port(port: int) -> int:
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


def validate_wg_key(key: str, key_name="Key") -> bool:
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


def validate_ip(potential_ip: str, type_of_ip="address", version="any"):
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
        raise SystemExit('type_of_ip must be "address", "network", or "any"')
    if version not in (4, 6, "any"):
        raise SystemExit('version must be 4, 6, or "any"')

    validated_ip = ipaddress.ip_interface(potential_ip)

    if version not in ("any", validated_ip.version):
        raise ipaddress.AddressValueError(
            f"{validated_ip} doesn't look like IPv{validated_ip.version}"
        )

    if type_of_ip == "address":
        try:
            validated_ip.ip
        except Exception as e:
            raise e
    elif type_of_ip == "network":
        try:
            validated_ip.network
        except Exception as e:
            raise e

    return validated_ip


def validate_ips(
    potential_ips: list, type_of_ip="address", version="any"
) -> bool:
    """
    Iterates through a list of IPs and validates them the way
    validate_ip does.

    On success, simply returns True.
    """
    if not isinstance(potential_ips, list):
        raise TypeError(
            "validate_ips: 'potential_ips' argument accepts a list."
        )

    if not potential_ips:
        raise ValueError(
            "validate_ips: 'potential_ips' argument needs a non-empty list."
        )

    for ip in potential_ips:
        validate_ip(ip, type_of_ip, version)
    return True


def extract_ips(
    potential_ips: list, type_of_ip="address", version="any"
) -> list:
    """
    Searches a list for IPs.

    Returns a new list containing the IPs it found.

    If type_of_ip is provided, extract_ips will look for a particular
    kind of IP. Valid types include:

    "address": Look for IP addresses. The default.
    "network": Look for network ranges.
    "any": Look for either.

    If version is provided, extract_ips will only accept IPs with
    a particular IP version. Versions include:

    4: IPv4.
    6: IPv6.
    "any": Either. The default.
    """
    ips = []

    for ip in potential_ips:
        try:
            ip = validate_ip(ip, type_of_ip, version)
        except ipaddress.AddressValueError:
            continue
        except ValueError:
            continue

        if version in ("any", ip.version):
            ips.append(ip)

    return ips


def validate_wg_data(transformed_wg_data: dict) -> dict:
    """
    Validates transformed WireGuard data and returns it on success.
    """
    validate_wg_key(transformed_wg_data["private_key"], key_name="PrivateKey")
    validate_wg_key(transformed_wg_data["public_key"], key_name="PublicKey")

    validate_ips(transformed_wg_data["allowed_ips"], type_of_ip="network")
    validate_ips(transformed_wg_data["address"])

    endpoint_ip, endpoint_port = transformed_wg_data["endpoint"]
    validate_ip(endpoint_ip)
    validate_network_port(endpoint_port)

    return transformed_wg_data


def convert_wg_to_hostname_if(transformed_wg_data: dict) -> list:
    """
    Given transformed WireGuard data, create a list of
    strings in hostname.if(5) format and return the list.
    """
    hostname_if_lines = []

    hostname_if_lines.append("wgkey " + transformed_wg_data["private_key"])
    hostname_if_lines.append(
        "wgpeer " + transformed_wg_data["public_key"] + " \\"
    )
    hostname_if_lines.append(
        "\t"
        + "wgendpoint "
        + " ".join(transformed_wg_data["endpoint"])
        + " \\"
    )

    for i, allowed_ip in enumerate(
        allowed_ips := transformed_wg_data["allowed_ips"]
    ):
        if i == len(allowed_ips) - 1:
            line_end = ""
        else:
            line_end = " \\"
        hostname_if_lines.append("\t" + f"wgaip {allowed_ip}" + line_end)

    for ip_addr in transformed_wg_data["address"]:
        if ip_addr.version == 4:
            ifconfig_arg = "inet"
        elif ip_addr.version == 6:
            ifconfig_arg = "inet6"
        hostname_if_lines.append(f"{ifconfig_arg} {ip_addr}")

    return hostname_if_lines


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

    validate_wg_data(new_wg_data)

    for wg_line in convert_wg_to_hostname_if(new_wg_data):
        print(wg_line)
