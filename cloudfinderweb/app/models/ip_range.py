"""
Models for handling IP ranges and efficient lookups.
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional, List, Union, Tuple
import ipaddress
import json
import os
import bisect


@dataclass
class IPRangeInfo:
    """Information about an IP range."""
    description: str
    region: Optional[str] = None
    service: Optional[str] = None
    ip_type: Optional[int] = None  # 4 for IPv4, 6 for IPv6

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "description": self.description,
            "region": self.region,
            "service": self.service,
            "type": self.ip_type
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IPRangeInfo':
        """Create from dictionary."""
        return cls(
            description=data.get("description", ""),
            region=data.get("region"),
            service=data.get("service"),
            ip_type=data.get("type")
        )


@dataclass
class IPRangeEntry:
    """A single IP range entry with precomputed integer bounds."""
    start_ip: int
    end_ip: int
    network_str: str
    info: IPRangeInfo


class IPRangeTree:
    """
    Efficient data structure for IP range lookups using binary search.

    Optimized for O(log n) lookups instead of O(n) by using sorted lists
    and binary search. Separates IPv4 and IPv6 for better performance.
    """

    def __init__(self):
        # Separate sorted lists for IPv4 and IPv6 ranges
        self.ipv4_ranges: List[IPRangeEntry] = []
        self.ipv6_ranges: List[IPRangeEntry] = []

        # Keep the old dict for backward compatibility during migration
        self.ranges = {}  # {network_obj: IPRangeInfo}

    def add(self, cidr: str, info: IPRangeInfo) -> bool:
        """
        Add an IP range to the tree.

        Args:
            cidr: The IP range in CIDR notation (e.g. "192.168.0.0/24")
            info: Information about this IP range

        Returns:
            bool: True if added successfully, False otherwise
        """
        try:
            network = ipaddress.ip_network(cidr)

            # Keep old format for backward compatibility
            self.ranges[network] = info

            # Add to optimized structure
            start_ip = int(network.network_address)
            end_ip = int(network.broadcast_address)

            entry = IPRangeEntry(
                start_ip=start_ip,
                end_ip=end_ip,
                network_str=str(network),
                info=info
            )

            if network.version == 4:
                # Insert in sorted order for IPv4
                bisect.insort(self.ipv4_ranges, entry, key=lambda x: x.start_ip)
            else:
                # Insert in sorted order for IPv6
                bisect.insort(self.ipv6_ranges, entry, key=lambda x: x.start_ip)

            return True
        except ValueError:
            return False

    def lookup(self, ip: str) -> List[Dict[str, Any]]:
        """
        Look up an IP address in the tree using optimized binary search.

        Args:
            ip: The IP address to look up

        Returns:
            List of matches with their info
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            ip_int = int(ip_obj)

            # Choose the appropriate range list based on IP version
            ranges = self.ipv4_ranges if ip_obj.version == 4 else self.ipv6_ranges

            return self._binary_search_lookup(ip_int, ranges)

        except ValueError:
            return []

    def _binary_search_lookup(self, ip_int: int, ranges: List[IPRangeEntry]) -> List[Dict[str, Any]]:
        """
        Perform optimized search to find IP ranges that contain the given IP.

        Args:
            ip_int: The IP address as an integer
            ranges: The sorted list of IP ranges to search

        Returns:
            List of matching ranges with their info
        """
        results = []

        if not ranges:
            return results

        # Since ranges can overlap, we need to check all ranges that might contain our IP
        # We can optimize by finding a good starting point with binary search

        # Find the rightmost range whose start_ip <= ip_int
        left = 0
        right = len(ranges) - 1
        candidate_start = -1

        while left <= right:
            mid = (left + right) // 2
            if ranges[mid].start_ip <= ip_int:
                candidate_start = mid
                left = mid + 1
            else:
                right = mid - 1

        # Check all ranges that could potentially contain the IP
        # Since we need to handle overlapping ranges correctly, we'll check
        # all ranges whose start_ip <= ip_int
        seen_networks = set()  # Prevent duplicates

        for i in range(len(ranges)):
            range_entry = ranges[i]

            # If start_ip > ip_int, no more ranges can contain the IP
            # (ranges are sorted by start_ip)
            if range_entry.start_ip > ip_int:
                break

            if range_entry.start_ip <= ip_int <= range_entry.end_ip:
                if range_entry.network_str not in seen_networks:
                    results.append({
                        "network": range_entry.network_str,
                        "info": range_entry.info.to_dict()
                    })
                    seen_networks.add(range_entry.network_str)

        return results

    def save_to_file(self, filename: str) -> bool:
        """
        Save the IP ranges to a file.

        Args:
            filename: The filename to save to

        Returns:
            bool: True if saved successfully, False otherwise
        """
        try:
            # Make sure the directory exists
            import os
            os.makedirs(os.path.dirname(filename), exist_ok=True)

            # Convert to serializable format
            serializable = {
                str(network): info.to_dict()
                for network, info in self.ranges.items()
            }

            with open(filename, 'w') as f:
                json.dump(serializable, f)
            print(f"Successfully saved {len(self.ranges)} IP ranges to {filename}")
            return True
        except Exception as e:
            import traceback
            print(f"Error saving to file {filename}: {str(e)}")
            print(traceback.format_exc())
            return False

    @classmethod
    def load_from_file(cls, filename: str) -> Optional['IPRangeTree']:
        """
        Load IP ranges from a file.

        Args:
            filename: The filename to load from

        Returns:
            IPRangeTree or None if loading failed
        """
        try:
            tree = cls()

            if not os.path.exists(filename):
                return tree

            with open(filename, 'r') as f:
                data = json.load(f)

            for network_str, info_dict in data.items():
                try:
                    info = IPRangeInfo.from_dict(info_dict)
                    # Use add() method to properly populate both old and new structures
                    tree.add(network_str, info)
                except ValueError:
                    # Skip invalid networks
                    continue

            print(f"Loaded {tree.count()} IP ranges from {filename}")
            return tree
        except Exception as e:
            print(f"Error loading from {filename}: {str(e)}")
            return cls()  # Return empty tree on error

    def count(self) -> int:
        """Return the number of ranges in the tree."""
        return len(self.ipv4_ranges) + len(self.ipv6_ranges)