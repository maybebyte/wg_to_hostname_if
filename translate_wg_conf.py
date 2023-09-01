#!/usr/bin/env python3

# Takes a WireGuard configuration file in INI format.
# Translates it to hostname.if(5) format.

import configparser
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
        Retrieves the address of the interface from the INI file.

        Returns:
            str: The address of the interface.
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


try:
    INI_FILE = sys.argv[1]
except IndexError:
    print(
        f"{sys.argv[0]} needs a WireGuard configuration file.", file=sys.stderr
    )
    sys.exit(1)
