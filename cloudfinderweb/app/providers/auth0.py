"""
Auth0 cloud provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class Auth0Provider(CloudProvider):
    """Auth0 provider."""

    def __init__(self):
        super().__init__("auth0", "Auth0")
        self.api_url = CLOUD_PROVIDER_URLS["auth0"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Auth0 IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process each region's IPv4 CIDRs
            for region_code, region_data in data.get("regions", {}).items():
                for ip_prefix in region_data.get("ipv4_cidrs", []):
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by Auth0",
                        region=region_code,
                        service="Auth0",
                        ip_type=4
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception as e:
            print(f"Error fetching Auth0 IP ranges: {str(e)}")
            return False