"""
Fastly provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class FastlyProvider(CloudProvider):
    """Fastly provider."""

    def __init__(self):
        super().__init__("fastly", "Fastly")
        self.api_url = CLOUD_PROVIDER_URLS["fastly"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Fastly IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            if not data:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process IPv4 addresses
            if "addresses" in data and isinstance(data["addresses"], list):
                for ip_prefix in data["addresses"]:
                    ip_prefix = ip_prefix.strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by Fastly",
                        region=None,
                        service=None,
                        ip_type=4
                    )

            # Process IPv6 addresses
            if "ipv6_addresses" in data and isinstance(data["ipv6_addresses"], list):
                for ip_prefix in data["ipv6_addresses"]:
                    ip_prefix = ip_prefix.strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by Fastly",
                        region=None,
                        service=None,
                        ip_type=6
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False