"""
Vultr cloud provider implementation.
"""

from ...config.config import CLOUD_PROVIDER_URLS
from .base import CloudProvider

class VultrProvider(CloudProvider):
    """
    Provider for Vultr cloud IP ranges.
    Data source: https://geofeed.constant.com/?json
    Documentation: https://docs.vultr.com/vultr-ip-space
    """
    def __init__(self):
        super().__init__("vultr", "Vultr")
        self.api_url = CLOUD_PROVIDER_URLS["vultr"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch IP ranges from Vultr API.

        The API returns a GeoFeed format JSON with subnets containing:
        - ip_prefix: CIDR notation
        - alpha2code: Two-letter country code
        - region: Regional subdivision code
        - city: City name
        - postal_code: Postal code
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            if not data or "subnets" not in data:
                return False

            # Clear existing ranges
            self.ip_ranges = self.ip_ranges.__class__()

            # Process each subnet entry
            for subnet in data.get("subnets", []):
                ip_prefix = subnet.get("ip_prefix")
                if not ip_prefix or not self.is_valid_ip(ip_prefix):
                    continue

                # Extract location information
                region_parts = []
                if "city" in subnet and subnet["city"]:
                    region_parts.append(subnet["city"])
                if "region" in subnet and subnet["region"]:
                    region_parts.append(subnet["region"])
                if "alpha2code" in subnet and subnet["alpha2code"]:
                    region_parts.append(subnet["alpha2code"])

                region = ", ".join(filter(None, region_parts)) if region_parts else None

                # Automatically detect IP type (IPv4 vs IPv6)
                ip_type = 6 if ":" in ip_prefix else 4

                # Add the IP range
                self.add_ip_range(
                    cidr=ip_prefix,
                    description="IP Address Used by Vultr",
                    region=region,
                    service=None,  # Vultr API doesn't provide service information
                    ip_type=ip_type
                )

            # Save to cache
            self._save_cache()
            return True

        except Exception as e:
            # Log the error if needed
            # print(f"Error fetching Vultr IP ranges: {e}")
            return False