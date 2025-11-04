"""
Okta cloud IP provider
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class OktaProvider(CloudProvider):
    """Provider for Okta IP ranges"""

    def __init__(self):
        super().__init__("okta", "Okta")
        self.api_url = "https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json"

    async def fetch_ip_ranges(self) -> bool:
        """Fetch IP ranges from Okta API"""
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            self.ip_ranges = self.ip_ranges.__class__()  # Clear existing IP ranges

            # Okta JSON format is:
            # {
            #   "cell_name": {
            #     "ip_ranges": ["CIDR1", "CIDR2", ...]
            #   },
            #   ...
            # }
            for cell_name, cell_data in data.items():
                # Extract region from cell name
                region = None
                if cell_name.startswith("us_"):
                    region = "US"
                elif cell_name.startswith("emea_"):
                    region = "EMEA"
                elif cell_name.startswith("apac_"):
                    region = "APAC"

                # Extract service from cell name
                service = "Okta"
                if "pam" in cell_name:
                    service = "Okta PAM"
                elif "preview" in cell_name:
                    service = "Okta Preview"

                # Process IP ranges
                for ip_prefix in cell_data.get("ip_ranges", []):
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    # Determine IP type (IPv4 or IPv6)
                    ip_type = 6 if ":" in ip_prefix else 4

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description=f"IP Address Used by {service}",
                        region=region,
                        service=f"{service} ({cell_name})",
                        ip_type=ip_type
                    )

            self._save_cache()
            return True

        except Exception as e:
            print(f"Error fetching Okta IP ranges: {str(e)}")
            return False