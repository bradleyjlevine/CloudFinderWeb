"""
DigitalOcean provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class DigitalOceanProvider(CloudProvider):
    """DigitalOcean provider."""

    def __init__(self):
        super().__init__("digital_ocean", "DigitalOcean")
        self.api_url = CLOUD_PROVIDER_URLS["digital_ocean"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch DigitalOcean IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url, allow_redirects=True)
            if not response:
                return False

            text = await response.text()
            if not text:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process the CSV format
            lines = text.split("\n")
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                cols = line.split(",")
                if len(cols) < 4:
                    continue

                ip_prefix = cols[0].strip()
                if not self.is_valid_ip(ip_prefix):
                    continue

                # Extract region information (cols 2 and 3 contain region data)
                region = ",".join(cols[2:4])

                # Determine IP type
                ip_type = 6 if ":" in ip_prefix else 4

                self.add_ip_range(
                    cidr=ip_prefix,
                    description="IP Address Used by DigitalOcean",
                    region=region,
                    service=None,
                    ip_type=ip_type
                )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False