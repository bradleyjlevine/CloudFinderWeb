"""
Microsoft O365 provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class O365Provider(CloudProvider):
    """Microsoft Office 365 provider."""

    def __init__(self):
        super().__init__("o365", "Microsoft Office 365")
        self.api_url = CLOUD_PROVIDER_URLS["o365"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Microsoft O365 IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            if not data or not isinstance(data, list):
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            for endpoint in data:
                if "ips" not in endpoint:
                    continue

                service_info = []
                if "serviceArea" in endpoint:
                    service_info.append(endpoint["serviceArea"])
                if "serviceAreaDisplayName" in endpoint:
                    service_info.append(endpoint["serviceAreaDisplayName"])

                service = ", ".join(service_info) if service_info else None

                for ip_prefix in endpoint["ips"]:
                    ip_prefix = ip_prefix.strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    # Determine IP type
                    ip_type = 6 if ":" in ip_prefix else 4

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by Microsoft O365",
                        region=None,
                        service=service,
                        ip_type=ip_type
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False