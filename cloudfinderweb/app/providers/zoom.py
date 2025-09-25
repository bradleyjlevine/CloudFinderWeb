"""
Zoom cloud provider implementation.
"""

import os.path
import re
from typing import Dict, List, Tuple

from .base import CloudProvider


class ZoomProvider(CloudProvider):
    """
    Zoom provider that aggregates IP ranges across multiple Zoom services.

    Fetches IP ranges from various Zoom service TXT files and organizes them
    by service type and IP version.
    """

    # Base URL for all Zoom IP range files
    BASE_URL = "https://assets.zoom.us/docs/ipranges/"

    # Mapping of service files to their readable names and URLs
    SERVICE_FILES = [
        # General Zoom IPs
        {"filename": "Zoom.txt", "service": "General", "ipv6": False},

        # Zoom Meetings
        {"filename": "ZoomMeetings.txt", "service": "Meetings", "ipv6": False},
        {"filename": "ZoomMeetings-IPv6.txt", "service": "Meetings", "ipv6": True},

        # Zoom Cloud Room Connector
        {"filename": "ZoomCRC.txt", "service": "Cloud Room Connector", "ipv6": False},

        # Zoom Phone
        {"filename": "ZoomPhone.txt", "service": "Phone", "ipv6": False},
        {"filename": "ZoomPhone-IPv6.txt", "service": "Phone", "ipv6": True},

        # Zoom Contact Center
        {"filename": "ZoomCC.txt", "service": "Contact Center", "ipv6": False},
        {"filename": "ZoomCC-IPv6.txt", "service": "Contact Center", "ipv6": True},

        # Zoom Virtual Assistant
        {"filename": "ZoomZVA.txt", "service": "Virtual Assistant", "ipv6": False},

        # Zoom CDN
        {"filename": "ZoomCDN.txt", "service": "CDN", "ipv6": False},
        {"filename": "ZoomCDN-IPv6.txt", "service": "CDN", "ipv6": True},

        # Zoom Apps
        {"filename": "ZoomApps.txt", "service": "Apps", "ipv6": False},
        {"filename": "ZoomApps-IPv6.txt", "service": "Apps", "ipv6": True},
    ]

    def __init__(self):
        """Initialize the Zoom provider."""
        super().__init__("zoom", "Zoom")

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Zoom IP ranges from multiple service files.

        Returns:
            bool: True if at least one service was successfully fetched, False otherwise
        """
        try:
            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            success_count = 0
            failure_count = 0

            # Process each service file
            for service_info in self.SERVICE_FILES:
                filename = service_info["filename"]
                service_name = service_info["service"]
                is_ipv6 = service_info["ipv6"]
                ip_type = 6 if is_ipv6 else 4

                url = f"{self.BASE_URL}{filename}"
                success = await self._process_service_file(url, service_name, ip_type)

                if success:
                    success_count += 1
                else:
                    failure_count += 1
                    print(f"Failed to fetch Zoom IP ranges for {service_name} from {url}")

            # Save to cache file
            self._save_cache()

            # Return True if at least one service was successfully fetched
            return success_count > 0

        except Exception as e:
            print(f"Error fetching Zoom IP ranges: {str(e)}")
            return False

    async def _process_service_file(self, url: str, service_name: str, ip_type: int) -> bool:
        """
        Process a single Zoom service IP range file.

        Args:
            url: URL to fetch the IP ranges from
            service_name: Name of the Zoom service
            ip_type: IP version (4 or 6)

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(url)
            if not response:
                return False

            text = await response.text()
            lines = text.splitlines()

            # Process each line in the file
            for line in lines:
                # Skip empty lines and comments
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                # Some Zoom files use semicolons as separators, others use spaces
                # Try to parse both formats
                ip_cidr = line
                description = None

                # Check if there's a semicolon separator (IP;Description)
                if ';' in line:
                    parts = line.split(';', 1)
                    if len(parts) == 2:
                        ip_cidr, description = parts[0].strip(), parts[1].strip()

                # Check if IP is valid
                if not self.is_valid_ip(ip_cidr):
                    continue

                # Add the IP range
                self.add_ip_range(
                    cidr=ip_cidr,
                    description="IP Address Used by Zoom" if not description else description,
                    region=None,  # Zoom doesn't provide region information
                    service=f"Zoom {service_name}",
                    ip_type=ip_type
                )

            return True

        except Exception as e:
            print(f"Error processing Zoom service file {url}: {str(e)}")
            return False