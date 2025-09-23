"""
Azure cloud provider implementations.
"""

from typing import Dict, List, Any
import json
from bs4 import BeautifulSoup

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS, DEFAULT_HEADERS


class AzureBaseProvider(CloudProvider):
    """Base class for Azure providers."""

    def __init__(self, provider_id: str, display_name: str, deployment: str):
        super().__init__(provider_id, display_name)
        self.azure_base_url = CLOUD_PROVIDER_URLS["azure_base"]
        self.deployment = deployment
        self.download_url = None

    async def _get_download_url(self) -> bool:
        """
        Get the download URL for the specific Azure deployment.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.azure_base_url)
            if not response:
                return False

            html = await response.text()
            soup = BeautifulSoup(html, features="html.parser")

            if not soup.body or not soup.body.table or not soup.body.table.tbody:
                return False

            # Find all table rows
            rows = soup.body.table.tbody.find_all("tr")
            for row in rows:
                # Find all cells in the row
                cells = row.find_all("td")
                if len(cells) >= 3 and cells[2].a and self.deployment in cells[2].a["href"]:
                    self.download_url = cells[2].a["href"]
                    return True

            return False
        except Exception:
            return False

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch Azure IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # First get the download URL
            if not self.download_url and not await self._get_download_url():
                return False

            # Download the JSON data
            response = await self.http_get(self.download_url)
            if not response:
                return False

            data = await response.json()

            if "cloud" not in data or "values" not in data:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process all values
            for service_entry in data["values"]:
                if "properties" not in service_entry:
                    continue

                properties = service_entry["properties"]
                if "addressPrefixes" not in properties:
                    continue

                region = properties.get("region", "")
                service = properties.get("systemService", "")

                for ip_prefix in properties["addressPrefixes"]:
                    ip_prefix = ip_prefix.strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    # Determine IP type
                    ip_type = 6 if ":" in ip_prefix else 4

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description=f"IP Address Used by Azure {self.deployment}",
                        region=region,
                        service=service,
                        ip_type=ip_type
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False


class AzurePublicProvider(AzureBaseProvider):
    """Azure Public Cloud provider."""

    def __init__(self):
        super().__init__("azure-public", "Microsoft Azure (Public)", "Public")


class AzureChinaProvider(AzureBaseProvider):
    """Azure China Cloud provider."""

    def __init__(self):
        super().__init__("azure-china", "Microsoft Azure (China)", "China")


class AzureGovernmentProvider(AzureBaseProvider):
    """Azure Government Cloud provider."""

    def __init__(self):
        super().__init__("azure-gov", "Microsoft Azure (Government)", "Government")


class AzureGermanyProvider(AzureBaseProvider):
    """Azure Germany Cloud provider."""

    def __init__(self):
        super().__init__("azure-germany", "Microsoft Azure (Germany)", "Germany")