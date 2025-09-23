"""
Akamai provider implementation.
"""

import zipfile
from io import BytesIO

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS, DEFAULT_HEADERS


class AkamaiProvider(CloudProvider):
    """Akamai provider."""

    def __init__(self):
        super().__init__("akamai", "Akamai")
        self.api_url = CLOUD_PROVIDER_URLS["akamai"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Akamai IP ranges from their ZIP file.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Add custom User-Agent header for Akamai
            headers = dict(DEFAULT_HEADERS)
            headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"

            # Download the ZIP file
            response = await self.http_get(self.api_url, headers=headers, timeout=60)
            if not response:
                return False

            # Get the ZIP content
            zip_content = await response.read()
            if not zip_content:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process the ZIP file
            with zipfile.ZipFile(BytesIO(zip_content)) as zip_file:
                # Process IPv4 and IPv6 files
                for filename in zip_file.namelist():
                    if filename not in ["akamai_ipv4_CIDRs.txt", "akamai_ipv6_CIDRs.txt"]:
                        continue

                    # Determine IP type from filename
                    ip_type = 6 if "ipv6" in filename.lower() else 4

                    # Read the file contents
                    with zip_file.open(filename) as file:
                        for line in file:
                            ip_prefix = line.decode("utf-8").strip()
                            if not ip_prefix or not self.is_valid_ip(ip_prefix):
                                continue

                            self.add_ip_range(
                                cidr=ip_prefix,
                                description="IP Address Used by Akamai",
                                region=None,
                                service=None,
                                ip_type=ip_type
                            )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False