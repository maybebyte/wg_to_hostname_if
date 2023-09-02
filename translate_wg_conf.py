#!/usr/bin/env python3

# Takes a WireGuard configuration file in INI format.
# Translates it to hostname.if(5) format.

import configparser
import ipaddress
import sys


class WGConfAccessor:
    """
    Handles retrieving information from the provided WireGuard INI file.
    """

    def __init__(self, file):
        with open(file=file, mode="r", encoding="utf-8") as f:
            ini_parser = configparser.ConfigParser()
            ini_parser.read_file(f)

        self.file_handle = f
        self.ini_parser = ini_parser

    def get_interface_private_key(self):
        """
        Retrieves the private key for the interface from the INI file.

        Returns:
            str: The private key for the interface.
        """
        return self.ini_parser.get(section="Interface", option="PrivateKey")

    def get_interface_address(self):
        """
        Retrieves the interface address entry from the INI file.

        Returns:
            str: The interface address entry.
        """
        return self.ini_parser.get(section="Interface", option="Address")

    def get_peer_public_key(self):
        """
        Retrieves the public key of the peer from the INI file.

        Returns:
            str: The public key of the peer.
        """
        return self.ini_parser.get(section="Peer", option="PublicKey")

    def get_peer_allowed_ips(self):
        """
        Retrieves the allowed IP addresses for the peer from the INI file.

        Returns:
            str: A string representing the allowed IP addresses for the peer.
        """
        return self.ini_parser.get(section="Peer", option="AllowedIPs")

    def get_peer_endpoint(self):
        """
        Retrieves the endpoint of the peer from the INI file.

        Returns:
            str: The endpoint of the peer.
        """
        return self.ini_parser.get(section="Peer", option="Endpoint")

    def get_peer_endpoint_ip(self):
        """
        Retrieves the IP address of the peer endpoint from the INI file.

        Returns:
            str: The IP address of the peer endpoint.
        """
        return self.get_peer_endpoint().split(":")[0]

    def get_peer_endpoint_port(self):
        """
        Retrieves the port number of the peer endpoint from the INI file.

        Returns:
            str: The port number of the peer endpoint.
        """
        return self.get_peer_endpoint().split(":")[1]


class IPAddressRetriever:
    """
    Given a list, find IPv4/IPv6 addresses within that list.
    """

    def __init__(self, potential_addresses):
        self.potential_addresses = potential_addresses

    def get_ipv4_addresses(self):
        """
        Returns a list of IPv4 addresses.

        Returns:
            list: A list of IPv4 addresses (in compressed format).
        """
        ipv4_addresses = []
        for address in self.potential_addresses:
            try:
                ip4 = ipaddress.IPv4Network(address)
                ipv4_addresses.append(ip4.compressed)
            except ipaddress.AddressValueError:
                continue
        return ipv4_addresses

    def get_ipv6_addresses(self):
        """
        Returns a list of IPv6 addresses.

        Returns:
            list: A list of IPv6 addresses (in compressed format).
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
