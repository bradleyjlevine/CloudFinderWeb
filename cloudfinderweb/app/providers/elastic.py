"""
Elastic Cloud provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class ElasticCloudProvider(CloudProvider):
    """Elastic Cloud provider."""

    def __init__(self):
        super().__init__("elastic", "Elastic Cloud")
        self.api_url = CLOUD_PROVIDER_URLS["elastic"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Elastic Cloud IP ranges.

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

            # Process each region in the regions object
            for region_name, region_data in data.get("regions", {}).items():
                # Process egress IPs (from Elastic to customer)
                for ip_prefix in region_data.get("egress_from_elastic", []):
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by Elastic Cloud",
                        region=region_name,
                        service="egress",
                        ip_type=6 if ":" in ip_prefix else 4
                    )

                # Process ingress IPs (from customer to Elastic)
                for ip_prefix in region_data.get("ingress_to_elastic", []):
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by Elastic Cloud",
                        region=region_name,
                        service="ingress",
                        ip_type=6 if ":" in ip_prefix else 4
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception as e:
            print(f"Error fetching Elastic Cloud IP ranges: {str(e)}")
            return False