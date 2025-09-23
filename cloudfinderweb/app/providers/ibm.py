"""
IBM Cloud provider implementation.
"""

import ipaddress

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class IBMCloudProvider(CloudProvider):
    """IBM Cloud provider."""

    def __init__(self):
        super().__init__("ibm", "IBM Cloud")
        self.api_url = CLOUD_PROVIDER_URLS["ibm"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch IBM Cloud IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            if "data_centers" not in data:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process data centers
            for datacenter in data["data_centers"]:
                # Extract datacenter name
                dc_name = datacenter.get("name", "")

                # Process each service
                for service_name, service_data in datacenter.items():
                    # Skip non-service keys
                    if service_name in ["key", "name", "city", "state", "country", "geo_region"]:
                        continue

                    if not isinstance(service_data, list):
                        continue

                    # Process service entries
                    for service_entry in service_data:
                        if not isinstance(service_entry, dict) or "cidr_blocks" not in service_entry:
                            continue

                        for ip_prefix in service_entry["cidr_blocks"]:
                            ip_prefix = ip_prefix.strip()
                            if not self.is_valid_ip(ip_prefix):
                                continue

                            try:
                                # Only include globally routable IPs
                                if not ipaddress.ip_interface(ip_prefix).is_global:
                                    continue
                            except ValueError:
                                continue

                            # Determine IP type
                            ip_type = 6 if ":" in ip_prefix else 4

                            self.add_ip_range(
                                cidr=ip_prefix,
                                description="IP Address Used by IBM Cloud",
                                region=dc_name,
                                service=service_name,
                                ip_type=ip_type
                            )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False