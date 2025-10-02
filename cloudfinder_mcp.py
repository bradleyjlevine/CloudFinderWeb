#!/usr/bin/env python3
import asyncio
import logging
from typing import Optional, Dict, Any, List

from fastmcp import FastMCP
from pydantic import BaseModel, Field

# Import CloudFinderWeb components
from cloudfinderweb.app.providers import provider_registry
from cloudfinderweb.app.utils.ip_utils import is_valid_ip

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create FastMCP instance
mcp = FastMCP("CloudFinder MCP Server")

# Define request and response models
class IPRequest(BaseModel):
    ip: str = Field(..., description="The IP address to check (IPv4 or IPv6)")

class ProviderRequest(BaseModel):
    provider: Optional[str] = Field(None, description="Optional: Provider ID to filter results")

class CloudIPResult(BaseModel):
    is_cloud_ip: bool = Field(..., description="Whether the IP belongs to a cloud provider")

class CloudIPDetails(BaseModel):
    ip: str = Field(..., description="The IP address that was looked up")
    found: bool = Field(..., description="Whether the IP was found in any cloud provider")
    providers: Dict[str, Any] = Field(..., description="Details about which providers the IP belongs to")

class RandomIPResult(BaseModel):
    ip: str = Field(..., description="A randomly selected cloud IP address")
    providers: Dict[str, Any] = Field(..., description="All cloud providers this IP belongs to (same format as get_cloud_ip_details)")

class UpdateResult(BaseModel):
    success: bool = Field(..., description="Whether the update was successful")
    results: Dict[str, Any] = Field(..., description="Results for each provider")

# Define tools
@mcp.tool(
    name="is_cloud_ip",
    description="Check if an IPv4 or IPv6 address belongs to any cloud provider's IP range. Returns a simple yes/no result.",
    output_schema={
        "type": "object",
        "properties": {
            "is_cloud_ip": {
                "type": "boolean",
                "description": "True if the IP address belongs to a cloud provider, False otherwise"
            }
        },
        "required": ["is_cloud_ip"]
    }
)
def is_cloud_ip(ip: str) -> CloudIPResult:
    """
    Check if an IPv4 or IPv6 address belongs to any cloud provider.
    """
    if not is_valid_ip(ip):
        raise ValueError(f"Invalid IP address format: {ip}")

    # Use the provider registry to look up the IP
    results = provider_registry.lookup_ip(ip)

    return CloudIPResult(is_cloud_ip=len(results) > 0)

@mcp.tool(
    name="get_cloud_ip_details",
    description="Get detailed information about an IPv4 or IPv6 address, including which cloud providers it belongs to and specific details about each provider's usage of this IP range.",
    output_schema={
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "The IP address that was looked up"
            },
            "found": {
                "type": "boolean",
                "description": "Whether the IP was found in any cloud provider"
            },
            "providers": {
                "type": "object",
                "description": "Details about which providers the IP belongs to, with provider IDs as keys and provider details as values"
            }
        },
        "required": ["ip", "found", "providers"]
    }
)
def get_cloud_ip_details(ip: str) -> CloudIPDetails:
    """
    Get detailed information about an IPv4 or IPv6 cloud address.
    """
    if not is_valid_ip(ip):
        raise ValueError(f"Invalid IP address format: {ip}")

    # Use the provider registry to look up the IP
    results = provider_registry.lookup_ip(ip)

    return CloudIPDetails(
        ip=ip,
        found=len(results) > 0,
        providers=results
    )

@mcp.tool(
    name="get_random_cloud_ip",
    description="Get a random IP address from the cached cloud provider data. Optionally filter by a specific provider ID. Useful for testing or sampling cloud provider IP ranges.",
    output_schema={
        "type": "object",
        "properties": {
            "ip": {
                "type": "string",
                "description": "A randomly selected cloud IP address"
            },
            "providers": {
                "type": "object",
                "description": "All cloud providers this IP belongs to, with provider IDs as keys and provider details as values (same format as get_cloud_ip_details)"
            }
        },
        "required": ["ip", "providers"]
    }
)
def get_random_cloud_ip(provider: Optional[str] = None) -> RandomIPResult:
    """
    Get a random IP from the cached cloud provider data.
    """
    import random

    try:
        # Get all providers or a specific one
        if provider:
            provider_obj = provider_registry.get_provider(provider)
            if not provider_obj or provider_obj.range_count() == 0:
                raise ValueError(f"Provider '{provider}' not found or has no IP ranges")
            valid_providers = [provider_obj]
        else:
            # Get all providers
            all_providers = provider_registry.get_all_providers()
            valid_providers = [p for p in all_providers if p.range_count() > 0]

        if not valid_providers:
            raise ValueError("No IP ranges available")

        selected_provider = random.choice(valid_providers)

        # Get a random IP range from the selected provider
        ip_ranges = list(selected_provider.ip_ranges.ranges.keys())
        if not ip_ranges:
            raise ValueError(f"No IP ranges in {selected_provider.display_name}")

        selected_range = random.choice(ip_ranges)

        # Get the network address (first IP in range)
        ip = str(selected_range.network_address)

        # Perform a full lookup to get all providers that contain this IP
        # This ensures we return ALL providers that match this IP, not just the one we randomly selected from
        all_matches = provider_registry.lookup_ip(ip)

        return RandomIPResult(
            ip=ip,
            providers=all_matches
        )
    except Exception as e:
        logger.error(f"Error getting random IP: {str(e)}")
        raise

@mcp.tool(
    name="update_cloud_ips",
    description="Update the cached cloud provider IP ranges by fetching the latest data from provider APIs. Optionally update a specific provider by ID. This is an asynchronous operation that may take some time for all providers.",
    output_schema={
        "type": "object",
        "properties": {
            "success": {
                "type": "boolean",
                "description": "Whether the update operation was successful overall"
            },
            "results": {
                "type": "object",
                "description": "Results for each provider's update operation, with provider IDs as keys and success status as values"
            }
        },
        "required": ["success", "results"]
    }
)
async def update_cloud_ips(provider: Optional[str] = None) -> UpdateResult:
    """
    Update the cached cloud provider IP ranges.
    """
    try:
        if provider:
            provider_obj = provider_registry.get_provider(provider)
            if not provider_obj:
                raise ValueError(f"Provider '{provider}' not found")

            # Update only the specified provider
            result = await provider_obj.fetch_ip_ranges()
            return UpdateResult(
                success=result,
                results={provider: result}
            )
        else:
            # Update all providers
            update_results = await provider_registry.update_all()

            return UpdateResult(
                success=True,
                results=update_results
            )
    except Exception as e:
        logger.error(f"Error updating providers: {str(e)}")
        raise

# Run the server if this script is executed directly
if __name__ == "__main__":
    # Ensure the CloudFinderWeb data is loaded
    print("Starting CloudFinder MCP server...")
    # Use the run_async method with the appropriate transport
    mcp.run(transport="streamable-http", host="0.0.0.0", port=5051)