#!/usr/bin/env python3

# Takes a WireGuard configuration file in INI format.
# Translates it to hostname.if(5) format.

from base64 import b64decode
import configparser
import ipaddress
import sys


def check_wg_key_validity(key, key_name="Key"):
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


class IPAddressFinder:
    """
    Given a list, find IPv4/IPv6 addresses within that list.
    """

    def __init__(self, potential_addresses):
        self.potential_addresses = potential_addresses
        self.ip_addresses = []
        self.ipv4_addresses = []
        self.ipv6_addresses = []

    def find_ip_addresses(self):
        """
        Searches a list for IP addresses.
        Returns a new list containing the addresses it found.
        """
        for address in self.potential_addresses:
            try:
                _ip = ipaddress.ip_interface(address)
            except ipaddress.AddressValueError:
                continue

            if _ip.version == 4:
                self.ipv4_addresses.append(_ip.with_prefixlen)
            elif _ip.version == 6:
                self.ipv6_addresses.append(_ip.with_prefixlen)

            self.ip_addresses.append(_ip.with_prefixlen)

        return self.ip_addresses


try:
    INI_FILE = sys.argv[1]
except IndexError:
    print(
        f"{sys.argv[0]} needs a WireGuard configuration file.", file=sys.stderr
    )
    sys.exit(1)

with open(file=INI_FILE, mode="r", encoding="utf-8") as f:
    ini_parser = configparser.ConfigParser()
    ini_parser.read_file(f)

wg_config_data = {
    "private_key": ini_parser.get(section="Interface", option="PrivateKey"),
    "public_key": ini_parser.get(section="Peer", option="PublicKey"),
    "endpoint": ini_parser.get(section="Peer", option="Endpoint"),
    "allowed_ips": ini_parser.get(section="Peer", option="AllowedIPs"),
    "address": ini_parser.get(section="Interface", option="Address"),
}

check_wg_key_validity(wg_config_data["private_key"], key_name="PrivateKey")
check_wg_key_validity(wg_config_data["public_key"], key_name="PublicKey")

wg_endpoint_ip, wg_endpoint_port = wg_config_data["endpoint"].split(":")

wg_allowed_ips_ip_finder = IPAddressFinder(
    wg_config_data["allowed_ips"].split(",")
)
wg_allowed_ips_ip_finder.find_ip_addresses()

wg_interface_ip_finder = IPAddressFinder(wg_config_data["address"].split(","))
wg_interface_ip_finder.find_ip_addresses()


print("wgkey " + wg_config_data["private_key"])
print("wgpeer " + wg_config_data["public_key"] + " \\")
print(
    "\t"
    + "wgendpoint "
    + wg_endpoint_ip
    + " "
    + wg_endpoint_port
    + " \\"
)

for allowed_ip in wg_allowed_ips_ip_finder.ip_addresses:
    if allowed_ip == wg_config_data["allowed_ips"][-1]:
        print(f"\twgaip {allowed_ip}")
    else:
        print(f"\twgaip {allowed_ip} \\")

for ip4_addr in wg_interface_ip_finder.ipv4_addresses:
    print(f"inet {ip4_addr}")

for ip6_addr in wg_interface_ip_finder.ipv6_addresses:
    print(f"inet6 {ip6_addr}")
