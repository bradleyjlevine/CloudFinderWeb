"""
Cloudflare cloud provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class CloudflareIPv4Provider(CloudProvider):
    """Cloudflare IPv4 provider."""

    def __init__(self):
        super().__init__("cloudflare-v4", "Cloudflare IPv4")
        self.api_url = CLOUD_PROVIDER_URLS["cloudflare-v4"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Cloudflare IPv4 ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            text = await response.text()

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            for line in text.split("\n"):
                ip_prefix = line.strip()
                if not ip_prefix or not self.is_valid_ip(ip_prefix):
                    continue

                self.add_ip_range(
                    cidr=ip_prefix,
                    description="IP Address Used by Cloudflare",
                    region=None,
                    service=None,
                    ip_type=4
                )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False


class CloudflareIPv6Provider(CloudProvider):
    """Cloudflare IPv6 provider."""

    def __init__(self):
        super().__init__("cloudflare-v6", "Cloudflare IPv6")
        self.api_url = CLOUD_PROVIDER_URLS["cloudflare-v6"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Cloudflare IPv6 ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            text = await response.text()

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            for line in text.split("\n"):
                ip_prefix = line.strip()
                if not ip_prefix or not self.is_valid_ip(ip_prefix):
                    continue

                self.add_ip_range(
                    cidr=ip_prefix,
                    description="IP Address Used by Cloudflare",
                    region=None,
                    service=None,
                    ip_type=6
                )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False