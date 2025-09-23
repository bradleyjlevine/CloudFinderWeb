"""
Linode provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class LinodeProvider(CloudProvider):
    """Linode provider."""

    def __init__(self):
        super().__init__("linode", "Linode")
        self.api_url = CLOUD_PROVIDER_URLS["linode"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Linode IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            text = await response.text()
            if not text:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process the CSV-like format
            lines = text.split("\n")
            if len(lines) < 3:
                return False

            # Skip the first three lines (headers)
            for line in lines[3:]:
                line = line.strip()
                if not line:
                    continue

                # Split the CSV columns
                cols = line.split(",")
                if len(cols) < 4:
                    continue

                ip_prefix = cols[0].strip()
                if not self.is_valid_ip(ip_prefix):
                    continue

                # Extract region information (cols 2 and 3 contain country and city)
                region = ",".join(cols[2:4])

                # Determine IP type
                ip_type = 6 if ":" in ip_prefix else 4

                self.add_ip_range(
                    cidr=ip_prefix,
                    description="IP Address Used by Linode",
                    region=region,
                    service=None,
                    ip_type=ip_type
                )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False