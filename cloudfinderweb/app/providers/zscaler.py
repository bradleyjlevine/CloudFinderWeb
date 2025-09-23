"""
Zscaler provider implementations.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class ZscalerProvider(CloudProvider):
    """Zscaler provider for standard endpoints."""

    def __init__(self):
        super().__init__("zscaler", "Zscaler")
        self.api_url = CLOUD_PROVIDER_URLS["zscaler"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Zscaler IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            if "zscaler.net" not in data:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process the hierarchical structure
            for continent, cities in data["zscaler.net"].items():
                for city, entries in cities.items():
                    for entry in entries:
                        if "range" not in entry:
                            continue

                        ip_prefix = entry["range"].strip()
                        if not self.is_valid_ip(ip_prefix):
                            continue

                        # Build service information
                        services = []
                        if entry.get("vpn"):
                            services.append("vpn")
                        if entry.get("gre"):
                            services.append("gre")

                        service_info = ",".join(services) if services else None

                        # Determine IP type
                        ip_type = 6 if ":" in ip_prefix else 4

                        self.add_ip_range(
                            cidr=ip_prefix,
                            description="IP Address Used by Zscaler",
                            region=f"{continent},{city}",
                            service=service_info,
                            ip_type=ip_type
                        )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False


class ZscalerHubsProvider(CloudProvider):
    """Zscaler provider for hub endpoints."""

    def __init__(self):
        super().__init__("zscaler-hubs", "Zscaler Hubs")
        self.api_url = CLOUD_PROVIDER_URLS["zscaler-hubs"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Zscaler Hubs IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            if "hubPrefixes" not in data:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            for ip_prefix in data["hubPrefixes"]:
                ip_prefix = ip_prefix.strip()
                if not self.is_valid_ip(ip_prefix):
                    continue

                # Determine IP type
                ip_type = 6 if ":" in ip_prefix else 4

                self.add_ip_range(
                    cidr=ip_prefix,
                    description="IP Address Used by Zscaler",
                    region=None,
                    service="Used by various Zscaler services (i.e. ZIA Virtual Service Edge, ZIA Private Service Edge, Zscaler Client Connector, DLP)",
                    ip_type=ip_type
                )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False