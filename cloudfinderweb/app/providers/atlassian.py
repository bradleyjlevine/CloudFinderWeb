"""
Atlassian cloud provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class AtlassianProvider(CloudProvider):
    """Atlassian provider."""

    def __init__(self):
        super().__init__("atlassian", "Atlassian")
        self.api_url = CLOUD_PROVIDER_URLS["atlassian"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Atlassian IP ranges.

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

            # Process each item in the items array
            for item in data.get("items", []):
                cidr = item.get("cidr")
                if not cidr or not self.is_valid_ip(cidr):
                    continue

                # Join region list into a string if it exists
                regions = item.get("region", [])
                region_str = ", ".join(regions) if regions else None

                # Join product list into a string if it exists
                products = item.get("product", [])
                service_str = ", ".join(products) if products else None

                # Determine IP type from the CIDR notation
                ip_type = 6 if ":" in cidr else 4

                self.add_ip_range(
                    cidr=cidr,
                    description="IP Address Used by Atlassian",
                    region=region_str,
                    service=service_str,
                    ip_type=ip_type
                )

            # Save to cache file
            self._save_cache()
            return True

        except Exception as e:
            print(f"Error fetching Atlassian IP ranges: {str(e)}")
            return False