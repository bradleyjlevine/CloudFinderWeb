"""
Cloud provider registry.
"""

import asyncio
from typing import Dict, List, Any, Tuple

from .base import CloudProvider
from .aws import AWSProvider
from .gcp import GoogleProvider, GCPProvider
from .cloudflare import CloudflareIPv4Provider, CloudflareIPv6Provider
from .github import GitHubProvider
from .o365 import O365Provider
from .azure import AzurePublicProvider, AzureChinaProvider, AzureGovernmentProvider, AzureGermanyProvider
from .akamai import AkamaiProvider
from .zscaler import ZscalerProvider, ZscalerHubsProvider
from .fastly import FastlyProvider
from .oci import OCIProvider
from .linode import LinodeProvider
from .digitalocean import DigitalOceanProvider
from .ibm import IBMCloudProvider


class ProviderRegistry:
    """Registry of cloud providers."""

    def __init__(self):
        self.providers = {}

    def register(self, provider: CloudProvider) -> None:
        """
        Register a provider.

        Args:
            provider: The provider to register
        """
        self.providers[provider.provider_id] = provider

    def get_provider(self, provider_id: str) -> CloudProvider:
        """
        Get a provider by ID.

        Args:
            provider_id: The provider ID

        Returns:
            The provider or None if not found
        """
        return self.providers.get(provider_id)

    def get_all_providers(self) -> List[CloudProvider]:
        """
        Get all registered providers.

        Returns:
            List of all providers
        """
        return list(self.providers.values())

    async def update_all(self) -> Dict[str, bool]:
        """
        Update IP ranges for all providers.

        Returns:
            Dict mapping provider IDs to update success status
        """
        results = {}
        tasks = []

        # Create tasks for all providers
        for provider_id, provider in self.providers.items():
            print(f"Creating task for provider: {provider_id}")
            task = asyncio.create_task(provider.fetch_ip_ranges())
            tasks.append((provider_id, task))

        # Wait for all tasks to complete
        for provider_id, task in tasks:
            try:
                print(f"Awaiting task for provider: {provider_id}")
                result = await task
                print(f"Provider {provider_id} update completed with result: {result}")
                results[provider_id] = result
            except Exception as e:
                import traceback
                print(f"Error updating provider {provider_id}: {str(e)}")
                print(traceback.format_exc())
                results[provider_id] = False

        return results

    def lookup_ip(self, ip: str) -> Dict[str, Dict[str, Any]]:
        """
        Look up an IP address across all providers.

        Args:
            ip: The IP address to look up

        Returns:
            Dict mapping provider IDs to match details
        """
        results = {}

        for provider_id, provider in self.providers.items():
            matches = provider.lookup_ip(ip)
            if matches:
                results[provider_id] = {
                    "provider": provider.display_name,
                    "matches": matches
                }

        return results


# Create and initialize the global provider registry
provider_registry = ProviderRegistry()

# Register all available providers
provider_registry.register(AWSProvider())
provider_registry.register(GoogleProvider())
provider_registry.register(GCPProvider())
provider_registry.register(CloudflareIPv4Provider())
provider_registry.register(CloudflareIPv6Provider())
provider_registry.register(GitHubProvider())
provider_registry.register(O365Provider())
provider_registry.register(AzurePublicProvider())
provider_registry.register(AzureChinaProvider())
provider_registry.register(AzureGovernmentProvider())
provider_registry.register(AzureGermanyProvider())
provider_registry.register(AkamaiProvider())
provider_registry.register(ZscalerProvider())
provider_registry.register(ZscalerHubsProvider())
provider_registry.register(FastlyProvider())
provider_registry.register(OCIProvider())
provider_registry.register(LinodeProvider())
provider_registry.register(DigitalOceanProvider())
provider_registry.register(IBMCloudProvider())