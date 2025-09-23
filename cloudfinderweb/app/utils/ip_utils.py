"""
Utilities for working with IP addresses.
"""

import re
import ipaddress
from typing import Tuple, Optional


def is_valid_ip(ip_str: str) -> bool:
    """
    Check if a string is a valid IP address (IPv4 or IPv6).

    Args:
        ip_str: String to check

    Returns:
        bool: True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str.strip())
        return True
    except ValueError:
        return False


def is_ipv4(ip_str: str) -> bool:
    """
    Check if a string is a valid IPv4 address.

    Args:
        ip_str: String to check

    Returns:
        bool: True if valid IPv4, False otherwise
    """
    pattern = r"^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$"
    return bool(re.match(pattern, ip_str.strip()))


def is_ipv6(ip_str: str) -> bool:
    """
    Check if a string is a valid IPv6 address.

    Args:
        ip_str: String to check

    Returns:
        bool: True if valid IPv6, False otherwise
    """
    pattern = (
        r"^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,7}:|"
        r"([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|"
        r"([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|"
        r"([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|"
        r"([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|"
        r"[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|"
        r":((:[0-9a-fA-F]{1,4}){1,7}|:)|"
        r"fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|"
        r"::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
        r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|"
        r"([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}"
        r"(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
    )
    return bool(re.match(pattern, ip_str.strip()))


def get_ip_type(ip_str: str) -> Optional[int]:
    """
    Get the IP version (4 or 6) of an IP address.

    Args:
        ip_str: IP address string

    Returns:
        4 for IPv4, 6 for IPv6, None if invalid
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.version
    except ValueError:
        return None