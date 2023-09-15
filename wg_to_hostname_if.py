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

import argparse
from base64 import b64decode
import configparser
import ipaddress
import sys
from typing import TextIO

NAME_TO_SECTION_AND_OPTION = {
    "address": ("Interface", "Address"),
    "private_key": ("Interface", "PrivateKey"),
    "allowed_ips": ("Peer", "AllowedIPs"),
    "endpoint": ("Peer", "Endpoint"),
    "public_key": ("Peer", "PublicKey"),
}


def to_str(bytes_or_str: str | bytes) -> str:
    """
    Given a str or bytes instance, return a string instance.
    """
    if isinstance(bytes_or_str, bytes):
        value = bytes_or_str.decode("utf-8")
    else:
        value = bytes_or_str
    return value


def to_bytes(bytes_or_str: str | bytes) -> bytes:
    """
    Given a str or bytes instance, return a bytes instance.
    """
    if isinstance(bytes_or_str, str):
        value = bytes_or_str.encode("utf-8")
    else:
        value = bytes_or_str
    return value


def split_and_strip(string: str, separator: str) -> list[str]:
    """
    Splits a given string into substrings using the specified
    separator and returns a list of substrings that are stripped
    of whitespace.

    Args:
        string:
        The string to be split.

        separator:
        The separator used to split the string into substrings.

    Returns:
        A list of substrings stripped of whitespace.
    """
    return [
        substring.strip() for substring in string.split(separator)
    ]


def init_ini_parser(
    ini_file: str | TextIO,
) -> configparser.ConfigParser:
    """
    Initialize and configure an INI parser.

    Args:
        ini_file:
        The path to the INI file or a file-like object containing
        the INI data.

    Returns:
        A configured instance of the configparser.ConfigParser
        class.
    """
    ini_parser = configparser.ConfigParser()
    if ini_file == "-":
        ini_file = sys.stdin

    if isinstance(ini_file, str):
        ini_parser.read(ini_file)
    else:
        ini_parser.read_file(ini_file)

    return ini_parser


def names_to_data(
    ini_parser: configparser.ConfigParser,
    name_to_section_and_option: dict[str, tuple[str, str]],
) -> dict[str, str]:
    """
    Retrieves data from a configparser.ConfigParser instance based
    on the provided section and option names.

    Args:
        ini_parser:
        An instance of configparser.ConfigParser that contains the
        configuration data.

        name_to_section_and_option:
        A dictionary mapping names to tuples of section and option
        names.

    Returns:
        A dictionary mapping names to the corresponding data retrieved
        from the configparser.ConfigParser instance.
    """
    if not isinstance(ini_parser, configparser.ConfigParser):
        raise TypeError("Expected configparser.ConfigParser instance.")

    name_to_data = {}

    for name, (section, option) in name_to_section_and_option.items():
        name_to_data[name] = ini_parser.get(section, option)

    return name_to_data


def transform_wg_data(
    wg_config_data: dict[str, str],
) -> dict:
    """
    Receives a dictionary containing lowercase names of WireGuard
    INI options as the keys and their associated data as the values.

    Performs processing on them such that the values for these names
    become updated with the following:

    "endpoint": list containing an IP address and a network port
    "allowed_ips": list containing IP networks/addresses allowed by the
    server
    "address": list containing interface addresses

    Returns a dictionary using the same key names, but with updated
    data.
    """
    endpoint = split_and_strip(wg_config_data["endpoint"], ":")
    allowed_ips = split_and_strip(wg_config_data["allowed_ips"], ",")
    address = split_and_strip(wg_config_data["address"], ",")

    # Type checkers will complain without a type annotation here.
    new_config_data: dict = {}

    new_config_data["private_key"] = wg_config_data["private_key"]
    new_config_data["public_key"] = wg_config_data["public_key"]
    new_config_data["endpoint"] = endpoint
    new_config_data["allowed_ips"] = extract_ips(
        allowed_ips,
        type_of_ip="network",
    )
    new_config_data["address"] = extract_ips(address)

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


def validate_wg_key(key: str | bytes, key_name: str = "Key") -> bool:
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


def validate_ip(
    potential_ip: str, type_of_ip: str = "address", version: str | int = "any"
) -> ipaddress.IPv4Interface | ipaddress.IPv6Interface:
    """
    Given a potential IP, validate it.

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
    """
    if type_of_ip not in ("address", "network", "any"):
        raise ValueError('type_of_ip must be "address", "network", or "any"')
    if version not in (4, 6, "any"):
        raise ValueError('version must be 4, 6, or "any"')

    validated_ip = ipaddress.ip_interface(potential_ip)

    if version not in ("any", validated_ip.version):
        raise ipaddress.AddressValueError(
            f"{validated_ip} doesn't look like IPv{validated_ip.version}"
        )

    if type_of_ip == "address":
        if validated_ip.network.num_addresses != 1:
            raise ipaddress.AddressValueError(
                f"{validated_ip} is a network and type_of_ip was address."
            )
    elif type_of_ip == "network":
        if validated_ip.network.num_addresses == 1:
            raise ipaddress.AddressValueError(
                f"{validated_ip} is an IP and type_of_ip was network."
            )

    return validated_ip


def validate_ips(
    potential_ips: list,
    type_of_ip: str = "address",
    version: str | int = "any",
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
    potential_ips: list[str],
    type_of_ip: str = "address",
    version: str | int = "any",
) -> list[ipaddress.IPv4Interface | ipaddress.IPv6Interface]:
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
    if type_of_ip not in ("address", "network", "any"):
        raise ValueError('type_of_ip must be "address", "network", or "any"')
    if version not in (4, 6, "any"):
        raise ValueError('version must be 4, 6, or "any"')

    ips = []

    for potential_ip in potential_ips:
        try:
            valid_ip = validate_ip(potential_ip, type_of_ip, version)
        except ipaddress.AddressValueError:
            continue
        except ValueError:
            continue

        if version in ("any", valid_ip.version):
            ips.append(valid_ip)

    return ips


def validate_wg_data(transformed_wg_data: dict) -> bool:
    """
    Validates transformed WireGuard data and returns True on success.
    """
    validate_wg_key(transformed_wg_data["private_key"], key_name="PrivateKey")
    validate_wg_key(transformed_wg_data["public_key"], key_name="PublicKey")

    validate_ips(transformed_wg_data["allowed_ips"], type_of_ip="network")
    validate_ips(transformed_wg_data["address"])

    endpoint_ip, endpoint_port = transformed_wg_data["endpoint"]
    validate_ip(endpoint_ip)
    validate_network_port(endpoint_port)

    return True


def convert_wg_to_hostname_if(transformed_wg_data: dict) -> list[str]:
    """
    Given transformed WireGuard data, create a list of
    strings in hostname.if(5) format and return the list.
    """
    hostname_if_lines = []

    hostname_if_lines.append(f'wgkey {transformed_wg_data["private_key"]}')
    hostname_if_lines.append(f'wgpeer {transformed_wg_data["public_key"]} \\')
    hostname_if_lines.append(
        "\t" + f'wgendpoint {" ".join(transformed_wg_data["endpoint"])} \\'
    )

    for i, allowed_ip in enumerate(
        allowed_ips := transformed_wg_data["allowed_ips"]
    ):
        line_end = "" if i == len(allowed_ips) - 1 else " \\"
        hostname_if_lines.append("\t" + f"wgaip {allowed_ip}{line_end}")

    for ip_addr in transformed_wg_data["address"]:
        if ip_addr.version == 4:
            ifconfig_arg = "inet"
        elif ip_addr.version == 6:
            ifconfig_arg = "inet6"
        else:
            raise ipaddress.AddressValueError
        hostname_if_lines.append(f"{ifconfig_arg} {ip_addr}")

    return hostname_if_lines


def parse_cli_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.
    """
    argparser = argparse.ArgumentParser(
        description="""
Translates a WireGuard configuration file to OpenBSD's hostname.if(5) format.
""",
    )
    argparser.add_argument(
        "filename",
        help="Path to WireGuard configuration file (STDIN if absent or '-').",
        nargs="?",
        default=sys.stdin,
    )
    argparser.add_argument(
        "-m",
        help="Also print an `mtu` line.",
        dest="MTU",
        metavar="mtu",
        type=int,
    )
    argparser.add_argument(
        "-r",
        help="Also print route(8) commands to install default routes.",
        action="store_true",
        dest="ADD_ROUTES",
    )
    argparser.add_argument(
        "-t",
        help="Also print a wgrtable entry. See ifconfig(8) and rtable(4).",
        dest="WGRTABLE",
        metavar="rtable",
        type=int,
    )
    arguments = argparser.parse_args()

    # Accept 0 here. `wgrtable 0` may sometimes be needed when the
    # default rtable isn't 0, see login.conf(5).
    if (
        arguments.WGRTABLE is not None
        and not 0 <= arguments.WGRTABLE <= 255
    ):
        print("wgrtable must be from 0-255.", file=sys.stderr)
        sys.exit(1)

    # Numbers are taken from sys/net/if_wg.c:
    # if (ifr->ifr_mtu <= 0 || ifr->ifr_mtu > 9000)
    #     ret = EINVAL;
    if arguments.MTU is not None and not 1 <= arguments.MTU <= 9000:
        print("mtu must be from 1-9000.", file=sys.stderr)
        sys.exit(1)

    return arguments


if __name__ == "__main__":
    args = parse_cli_arguments()
    wg_ini_parser = init_ini_parser(args.filename)
    wg_data = names_to_data(wg_ini_parser, NAME_TO_SECTION_AND_OPTION)
    new_wg_data = transform_wg_data(wg_data)

    validate_wg_data(new_wg_data)

    for wg_line in convert_wg_to_hostname_if(new_wg_data):
        print(wg_line)

    if args.MTU:
        print(f"mtu {args.MTU}")

    if args.WGRTABLE is not None:
        print(f"wgrtable {args.WGRTABLE}")

    # On OpenBSD 7.3, route(8) fails to install a default route if
    # the IP is in CIDR format due to EFAULT. So, make sure we use a
    # bare IP instead.
    #
    # Also, there can only be one default route for IPv4 and IPv6.
    if args.ADD_ROUTES:
        IP4_ROUTE_PRINTED, IP6_ROUTE_PRINTED = False, False
        for route_ip in new_wg_data["address"]:
            if route_ip.version == 4 and IP4_ROUTE_PRINTED is False:
                print(f"!/sbin/route -qn add -inet default {route_ip.ip}")
                IP4_ROUTE_PRINTED = True
            elif route_ip.version == 6 and IP6_ROUTE_PRINTED is False:
                print(f"!/sbin/route -qn add -inet6 default {route_ip.ip}")
                IP6_ROUTE_PRINTED = True
