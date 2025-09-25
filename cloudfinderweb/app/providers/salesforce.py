"""
Salesforce cloud provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class SalesforceProvider(CloudProvider):
    """Salesforce provider."""

    def __init__(self):
        super().__init__("salesforce", "Salesforce")
        self.api_url = CLOUD_PROVIDER_URLS["salesforce"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Salesforce IP ranges.

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

            # Process each prefix entry
            for prefix in data.get("prefixes", []):
                region = prefix.get("region")
                provider = prefix.get("provider")

                for ip_prefix in prefix.get("ip_prefix", []):
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by Salesforce",
                        region=region,
                        service=provider,
                        ip_type=4 if ":" not in ip_prefix else 6
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception as e:
            print(f"Error fetching Salesforce IP ranges: {str(e)}")
            return False