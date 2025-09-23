"""
GitHub provider implementation.
"""

from .base import CloudProvider
from ...config.config import CLOUD_PROVIDER_URLS


class GitHubProvider(CloudProvider):
    """GitHub provider."""

    def __init__(self):
        super().__init__("github", "GitHub")
        self.api_url = CLOUD_PROVIDER_URLS["github"]

    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch GitHub IP ranges.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            response = await self.http_get(self.api_url)
            if not response:
                return False

            data = await response.json()
            if not data:
                return False

            # Clear existing ranges before adding new ones
            self.ip_ranges = self.ip_ranges.__class__()

            # Process all IP ranges for different services
            for service_name, ip_list in data.items():
                # Skip non-IP fields
                if service_name in [
                    "ssh_keys",
                    "ssh_key_fingerprints",
                    "verifiable_password_authentication",
                    "domains"
                ]:
                    continue

                if not isinstance(ip_list, list):
                    continue

                for ip_prefix in ip_list:
                    ip_prefix = ip_prefix.strip()
                    if not self.is_valid_ip(ip_prefix):
                        continue

                    # Determine IP type
                    try:
                        ip_type = 6 if ":" in ip_prefix else 4
                    except ValueError:
                        continue

                    self.add_ip_range(
                        cidr=ip_prefix,
                        description="IP Address Used by GitHub",
                        region=None,
                        service=service_name,
                        ip_type=ip_type
                    )

            # Save to cache file
            self._save_cache()
            return True

        except Exception:
            return False