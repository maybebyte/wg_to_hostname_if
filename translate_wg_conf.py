#!/usr/bin/env python3

# Takes a WireGuard configuration file in INI format.
# Translates it to hostname.if(5) format.

from base64 import b64decode
import configparser
import ipaddress
import sys


class WGConfAccessor:
    """
    Retrieves options from sections in the provided WireGuard INI file.
    """

    def __init__(self, file):
        with open(file=file, mode="r", encoding="utf-8") as f:
            ini_parser = configparser.ConfigParser()
            ini_parser.read_file(f)

        self.ini_parser = ini_parser

    def get_interface_private_key(self):
        """
        Retrieves PrivateKey option from Interface section in the INI file.
        """
        return self.ini_parser.get(section="Interface", option="PrivateKey")

    def get_interface_address(self):
        """
        Retrieves Address option from Interface section in the INI file.
        """
        return self.ini_parser.get(section="Interface", option="Address")

    def get_peer_public_key(self):
        """
        Retrieves PublicKey option from Peer section in the INI file.
        """
        return self.ini_parser.get(section="Peer", option="PublicKey")

    def get_peer_allowed_ips(self):
        """
        Retrieves AllowedIPs option from Peer section in the INI file.
        """
        return self.ini_parser.get(section="Peer", option="AllowedIPs")

    def get_peer_endpoint(self):
        """
        Retrieves Endpoint option from Peer section in the INI file.
        """
        return self.ini_parser.get(section="Peer", option="Endpoint")


class WGKeyValidator:
    """
    Validate public and private WireGuard keys.
    """

    def validate_key(self, key, key_name="Key"):
        """
        Validate the provided key.

        Validation consists of these steps:
        - base64 decode the key.
        - check if its decoded length is 32 bytes.

        If validation fails, raise an exception:
        - If it failed during base64 decoding, see b64decode in base64.
        - If it failed the length check, the exception is a ValueError.
        """
        b64decoded_key = b64decode(bytes(key, "utf-8"), validate=True)
        if len(b64decoded_key) != 32:
            raise ValueError(f"{key_name} didn't base64 decode to 32 bytes.")

    def validate_keys(self, keys):
        """
        Validate all provided keys.
        See validate_key in the same class for more details.
        """
        for k in keys:
            self.validate_key(k)


class IPAddressFinder:
    """
    Given a list, find IPv4/IPv6 addresses within that list.
    """

    def __init__(self, potential_addresses):
        self.potential_addresses = potential_addresses

    def find_ipv4_addresses(self):
        """
        Searches a list for IPv4 addresses.
        Returns a new list containing the IPv4 addresses it found.
        """
        ipv4_addresses = []
        for address in self.potential_addresses:
            try:
                ip4 = ipaddress.IPv4Network(address)
                ipv4_addresses.append(ip4.compressed)
            except ipaddress.AddressValueError:
                continue
        return ipv4_addresses

    def find_ipv6_addresses(self):
        """
        Searches a list for IPv6 addresses.
        Returns a new list containing the IPv6 addresses it found.
        """
        ipv6_addresses = []
        for address in self.potential_addresses:
            try:
                ip6 = ipaddress.IPv6Network(address)
                ipv6_addresses.append(ip6.compressed)
            except ipaddress.AddressValueError:
                continue
        return ipv6_addresses


try:
    INI_FILE = sys.argv[1]
except IndexError:
    print(
        f"{sys.argv[0]} needs a WireGuard configuration file.", file=sys.stderr
    )
    sys.exit(1)

wg_accessor = WGConfAccessor(INI_FILE)
key_validator = WGKeyValidator()

wg_private_key = wg_accessor.get_interface_private_key()
key_validator.validate_key(wg_private_key, key_name="PrivateKey")

wg_public_key = wg_accessor.get_peer_public_key()
key_validator.validate_key(wg_public_key, key_name="PublicKey")

wg_endpoint_ip, wg_endpoint_port = wg_accessor.get_peer_endpoint().split(":")

wg_allowed_ips = wg_accessor.get_peer_allowed_ips().split(",")

print(f"wgkey {wg_private_key}")
print(f"wgpeer {wg_public_key} \\")
print(f"\twgendpoint {wg_endpoint_ip} {wg_endpoint_port} \\")

for allowed_ip in wg_allowed_ips:
    if allowed_ip == wg_allowed_ips[-1]:
        print(f"\twgaip {allowed_ip}")
    else:
        print(f"\twgaip {allowed_ip} \\")
