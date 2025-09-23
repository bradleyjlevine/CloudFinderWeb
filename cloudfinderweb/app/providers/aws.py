"""
AWS (Amazon Web Services) cloud provider implementation.
"""

import json
from typing import Dict, Any

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class AWSProvider(CloudProvider):
    """AWS cloud provider."""

    def __init__(self):
        super().__init__("aws", "Amazon Web Services")
        self.api_url = CLOUD_PROVIDER_URLS["aws"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch AWS IP ranges from the official API.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()

            if "prefixes" not in data:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process IPv4 prefixes
            for prefix in data["prefixes"]:
                if "ip_prefix" in prefix:
                    ip_prefix = prefix["ip_prefix"].strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by AWS",
                        region=prefix.get("region"),
                        service=prefix.get("service"),
                        ip_type=4
                    )

            # Process IPv6 prefixes if available
            if "ipv6_prefixes" in data:
                for prefix in data["ipv6_prefixes"]:
                    if "ipv6_prefix" in prefix:
                        ip_prefix = prefix["ipv6_prefix"].strip()
                        if not self.is_valid_ip(ip_prefix):
                            continue

                        self.add_ip_range(
                            cidr=ip_prefix,
                            description="IPv6 Address Used by AWS",
                            region=prefix.get("region"),
                            service=prefix.get("service"),
                            ip_type=6
                        )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False