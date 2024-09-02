#!/usr/bin/env python3
# Copyright (c) 2023-2024 Ashlen <dev@anthes.is>
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
    Convert a string or bytes object to a string.

    Args:
        bytes_or_str:
        The input to be converted.

    Returns:
        The converted string.
    """
    if isinstance(bytes_or_str, bytes):
        value = bytes_or_str.decode("utf-8")
    else:
        value = bytes_or_str
    return value


def to_bytes(bytes_or_str: str | bytes) -> bytes:
    """
    Converts a string or bytes object to bytes.

    Args:
        bytes_or_str:
        The input to be converted.

    Returns:
        The converted bytes object.
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
    return [substring.strip() for substring in string.split(separator)]


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
    Transforms WireGuard configuration data into a new format.

    Args:
        wg_config_data:
        A dictionary containing WireGuard configuration data.

        The dictionary must have the following keys:

        - "private_key":
        The private key for the WireGuard connection.

        - "public_key":
        The public key for the WireGuard connection.

        - "endpoint":
        The endpoint for the WireGuard connection, in the format
        "host:port".

        - "allowed_ips":
        A comma-separated string of allowed IP addresses or networks.

        - "address":
        A comma-separated string of IP addresses assigned to the
        WireGuard interface.

    Returns:
        A dictionary containing the transformed WireGuard configuration
        data.

        The dictionary will have the same keys as before, but these
        keys will have updated values:

        - "endpoint":
        A list containing the host and port of the WireGuard endpoint.

        - "allowed_ips":
        A list of IP addresses or networks allowed by the WireGuard
        connection.

        - "address":
        A list of IP addresses assigned to the WireGuard interface.

    Raises:
        KeyError:
        If any of the required keys weren't in the provided dictionary.
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
        type_of_ip="any",
    )
    new_config_data["address"] = extract_ips(address)

    return new_config_data


def validate_network_port(port: int) -> int:
    """
    Validates a network port number.

    Args:
        port:
        The port number to be validated.

    Returns:
        The validated port number.

    Raises:
        ValueError:
        If the port number is not within the range 0-65535.
    """
    port = int(port)
    if not 0 <= port <= 65535:
        raise ValueError(f"{port} is not within the range 0-65535.")
    return port


def validate_wg_key(key: str | bytes, key_name: str = "Key") -> bool:
    """
    Validates a WireGuard key by performing the following checks:
    1. Converts the key to bytes if it is a string.
    2. Decodes the key from base64 and performs validation.
    3. Checks if the decoded key is exactly 32 bytes long.

    Args:
        key:
        The WireGuard key to validate. It can be either a string
        or bytes.

        key_name:
        The name of the key being validated. Defaults to "Key".

    Returns:
        bool: True if the key is valid, False otherwise.

    Raises:
        ValueError:
        If the key doesn't base64 decode to exactly 32 bytes.
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
    Validates an IP address or network based on the specified
    parameters.

    Args:
        potential_ip:
        The IP address or network to be validated.

        type_of_ip:
        The type of IP to validate. Can be one of these:
        - "address" (default)
        - "network"
        - "any"

        version:
        The IP version to validate. Can be one of these:
        - 4
        - 6
        - "any" (default)

    Returns:
        ipaddress.IPv4Interface | ipaddress.IPv6Interface:
        The validated IP address or network.

    Raises:
        ValueError:
        - If type_of_ip is not an allowed type.
        - If version is not an allowed version.

        ipaddress.AddressValueError:
        - If the IP address or network doesn't match the specified
        version.

        - If the IP address is a network and type_of_ip was set to
        "address".

        - If the IP address is an IP and type_of_ip was set to
        "network".
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


def extract_ips(
    potential_ips: list[str],
    type_of_ip: str = "address",
    version: str | int = "any",
) -> list[ipaddress.IPv4Interface | ipaddress.IPv6Interface]:
    """
    Extracts valid IP addresses from a list of potential IP addresses.

    Args:
        potential_ips:
        A list of potential IP addresses.

        type_of_ip:
        The type of IP to extract. Can be one of these:
        - "address" (default)
        - "network"
        - "any"

        version:
        The IP version to extract. Can be one of these:
        - 4
        - 6
        - "any" (default)

    Returns:
        list[ipaddress.IPv4Interface | ipaddress.IPv6Interface]:
        A list of valid IP addresses.

    Raises:
        ValueError:
        - If type_of_ip is not an allowed type.
        - If version is not an allowed version.
    """
    if type_of_ip not in ("address", "network", "any"):
        raise ValueError('type_of_ip must be "address", "network", or "any"')
    if version not in (4, 6, "any"):
        raise ValueError('version must be 4, 6, or "any"')

    ips = []

    for potential_ip in potential_ips:
        try:
            valid_ip = validate_ip(potential_ip, type_of_ip, version)
        # Ignoring these exceptions is alright because we never append to
        # the list of IPs that extract_ips() returns. In this situation,
        # we don't want to terminate the whole program if the IP we're on
        # failed the validation checks. Instead, we want to ignore that IP
        # and keep checking for more valid IPs in the list we were provided.
        except ipaddress.AddressValueError:
            continue
        except ValueError:
            continue

        if version in ("any", valid_ip.version):
            ips.append(valid_ip)

    return ips


def validate_wg_data(transformed_wg_data: dict) -> bool:
    """
    Validates the WireGuard data provided in the transformed_wg_data
    dictionary.

    Args:
        transformed_wg_data:
        A dictionary containing the transformed WireGuard data.

    Returns:
        bool:
        True if the WireGuard data is valid.

    Raises:
        KeyError:
        If any of the required keys are missing in the transformed_wg_data
        dictionary.

        Otherwise, the exception is determined by the specific
        validation function that failed.
    """
    validate_wg_key(transformed_wg_data["private_key"], key_name="PrivateKey")
    validate_wg_key(transformed_wg_data["public_key"], key_name="PublicKey")

    for potential_ip in transformed_wg_data["allowed_ips"]:
        validate_ip(potential_ip, type_of_ip="any")

    for potential_ip in transformed_wg_data["address"]:
        validate_ip(potential_ip)

    endpoint_ip, endpoint_port = transformed_wg_data["endpoint"]
    validate_ip(endpoint_ip)
    validate_network_port(endpoint_port)

    return True


def convert_wg_to_hostname_if(transformed_wg_data: dict) -> list[str]:
    """
    Converts transformed WireGuard data to a list of hostname.if(5)
    lines.

    Args:
        transformed_wg_data:
        A dictionary containing the transformed WireGuard data.

    Returns:
        list[str]:
        A list of hostname.if lines.

    Raises:
        ipaddress.AddressValueError:
        If an ipaddress.ip_interface object with a version other
        than 4 or 6 is encountered.
    """
    hostname_if_lines = []

    hostname_if_lines.append(f'wgkey {transformed_wg_data["private_key"]}')
    hostname_if_lines.append(f'wgpeer {transformed_wg_data["public_key"]} \\')
    hostname_if_lines.append(
        "\t" + f'wgendpoint {" ".join(transformed_wg_data["endpoint"])} \\'
    )

    index_of_last_allowed_ip = len(transformed_wg_data["allowed_ips"]) - 1
    for i, allowed_ip in enumerate(transformed_wg_data["allowed_ips"]):
        line_ending = " \\"
        if i == index_of_last_allowed_ip:
            line_ending = ""

        hostname_if_lines.append("\t" + f"wgaip {allowed_ip}{line_ending}")

    inet_version_map = {4: "inet", 6: "inet6"}
    for ip_addr in transformed_wg_data["address"]:
        inet_version = inet_version_map[ip_addr.version]
        if inet_version is None:
            raise ipaddress.AddressValueError
        hostname_if_lines.append(f"{inet_version} {ip_addr}")

    return hostname_if_lines


def parse_cli_arguments() -> argparse.Namespace:
    """
    Parses command line arguments for wg_hostname_to_if.py.

    Returns:
        argparse.Namespace:
        An object containing the parsed command line arguments.

    Exits:
        With exit code 1 and an error message if:
        - The provided wgrtable value is not within the range of 0-255.
        - The provided mtu value is not within the range of 1-9000.
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
    if arguments.WGRTABLE is not None and not 0 <= arguments.WGRTABLE <= 255:
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
