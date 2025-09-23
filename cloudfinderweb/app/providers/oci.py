"""
Oracle Cloud Infrastructure (OCI) provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class OCIProvider(CloudProvider):
    """Oracle Cloud Infrastructure provider."""

    def __init__(self):
        super().__init__("oci", "Oracle Cloud Infrastructure")
        self.api_url = CLOUD_PROVIDER_URLS["oci"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch OCI IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            if "regions" not in data or not isinstance(data["regions"], list):
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process all regions
            for region_entry in data["regions"]:
                if "region" not in region_entry or "cidrs" not in region_entry:
                    continue

                region_name = region_entry["region"]

                for cidr_entry in region_entry["cidrs"]:
                    if "cidr" not in cidr_entry:
                        continue

                    ip_prefix = cidr_entry["cidr"].strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    # Get tags if available
                    tags = cidr_entry.get("tags", [])
                    service = ", ".join(tags) if tags else None

                    # Determine IP type
                    ip_type = 6 if ":" in ip_prefix else 4

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by Oracle for OCI or other services",
                        region=region_name,
                        service=service,
                        ip_type=ip_type
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False