"""
Google Cloud Platform provider implementation.
"""

import json
from typing import Dict, Any

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class GoogleProvider(CloudProvider):
    """Google Cloud Platform provider."""

    def __init__(self):
        super().__init__("google", "Google")
        self.api_url = CLOUD_PROVIDER_URLS["google"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Google IP ranges.

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

            for prefix in data["prefixes"]:
                # Process IPv4 prefixes
                if "ipv4Prefix" in prefix:
                    ip_prefix = prefix["ipv4Prefix"].strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Owned by Google",
                        region=None,
                        service=None,
                        ip_type=4
                    )

                # Process IPv6 prefixes
                if "ipv6Prefix" in prefix:
                    ip_prefix = prefix["ipv6Prefix"].strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Owned by Google",
                        region=None,
                        service=None,
                        ip_type=6
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False


class GCPProvider(CloudProvider):
    """Google Cloud Platform specific services."""

    def __init__(self):
        super().__init__("gcp", "Google Cloud Platform")
        self.api_url = CLOUD_PROVIDER_URLS["gcp"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch GCP IP ranges.

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

            for prefix in data["prefixes"]:
                # Process IPv4 prefixes
                if "ipv4Prefix" in prefix:
                    ip_prefix = prefix["ipv4Prefix"].strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by GCP",
                        region=prefix.get("scope"),
                        service=prefix.get("service"),
                        ip_type=4
                    )

                # Process IPv6 prefixes
                if "ipv6Prefix" in prefix:
                    ip_prefix = prefix["ipv6Prefix"].strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by GCP",
                        region=prefix.get("scope"),
                        service=prefix.get("service"),
                        ip_type=6
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False