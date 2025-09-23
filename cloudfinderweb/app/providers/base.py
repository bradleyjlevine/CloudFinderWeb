"""
Base class for cloud provider IP range data fetching.
"""

import re
import os
import ipaddress
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Union
import aiohttp
import asyncio
import json

from ..models.ip_range import IPRangeTree, IPRangeInfo
from ...config.config import CLOUDS_DIR, API_TIMEOUT, DEFAULT_HEADERS


class CloudProvider(ABC):
    """Base class for cloud providers."""

    def __init__(self, provider_id: str, display_name: str):
        """
        Initialize a cloud provider.

        Args:
            provider_id: Unique identifier for the provider (e.g., 'aws', 'gcp')
            display_name: Human-readable name (e.g., 'Amazon Web Services', 'Google Cloud Platform')
        """
        self.provider_id = provider_id
        self.display_name = display_name
        self.ip_ranges = IPRangeTree()
        self.data_file = os.path.join(CLOUDS_DIR, f"{provider_id}.json")

        # Load cached data if available
        self._load_cache()

    def _load_cache(self) -> None:
        """Load cached IP ranges from file."""
        if os.path.exists(self.data_file):
            loaded_tree = IPRangeTree.load_from_file(self.data_file)
            if loaded_tree:
                self.ip_ranges = loaded_tree

    def _save_cache(self) -> None:
        """Save IP ranges to cache file."""
        # Make sure the directory exists
        os.makedirs(os.path.dirname(self.data_file), exist_ok=True)
        self.ip_ranges.save_to_file(self.data_file)

    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """
        Check if a string is a valid IP address or IP network (IPv4 or IPv6).

        Args:
            ip_str: String to check (can be individual IP or CIDR notation)

        Returns:
            bool: True if valid IP or IP network, False otherwise
        """
        try:
            # First try as an IP network (CIDR notation)
            ipaddress.ip_network(ip_str, strict=False)
            return True
        except ValueError:
            try:
                # Then try as an individual IP address
                ipaddress.ip_address(ip_str)
                return True
            except ValueError:
                return False

    @abstractmethod
    async def fetch_ip_ranges(self) -> bool:
        """
        Fetch IP ranges from provider API.

        This method must be implemented by each provider.

        Returns:
            bool: True if successful, False otherwise
        """
        pass

    async def http_get(self, url: str, *,
                  headers: Optional[Dict[str, str]] = None,
                  timeout: Optional[int] = None,
                  allow_redirects: bool = True) -> Optional[aiohttp.ClientResponse]:
        """
        Make an HTTP GET request with error handling.

        Args:
            url: The URL to request
            headers: Optional HTTP headers
            timeout: Optional timeout in seconds
            allow_redirects: Whether to follow redirects

        Returns:
            Response object or None if request failed
        """
        headers = headers or DEFAULT_HEADERS
        timeout = timeout or API_TIMEOUT

        try:
            session = aiohttp.ClientSession(trust_env=True)
            try:
                response = await session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    allow_redirects=allow_redirects,
                    ssl=False  # Disable SSL verification for testing
                )

                # Instead of returning the response directly, read its content
                if 200 <= response.status < 300:
                    # Create a simple response-like object with the data
                    class ResponseWrapper:
                        def __init__(self, original_response, data):
                            self.status = original_response.status
                            self._data = data
                            self._text = None

                        async def json(self):
                            import json
                            if isinstance(self._data, bytes):
                                return json.loads(self._data.decode('utf-8'))
                            return json.loads(self._data)

                        async def text(self):
                            if self._text is None:
                                if isinstance(self._data, bytes):
                                    self._text = self._data.decode('utf-8')
                                else:
                                    self._text = self._data
                            return self._text

                        async def read(self):
                            if isinstance(self._data, bytes):
                                return self._data
                            return self._data.encode('utf-8')

                    # Read the data
                    try:
                        data = await response.read()
                        await response.release()
                        await session.close()
                        return ResponseWrapper(response, data)
                    except Exception as e:
                        print(f"Error reading response data: {str(e)}")
                        await session.close()
                        return None
                else:
                    print(f"HTTP error: {response.status} for URL {url}")
                    await response.release()
                    await session.close()
                    return None
            except Exception as e:
                print(f"Error in HTTP request to {url}: {str(e)}")
                await session.close()
                return None
        except Exception as e:
            print(f"Failed to create session for {url}: {str(e)}")
            return None

    def add_ip_range(self, cidr: str, description: str,
                    region: Optional[str] = None,
                    service: Optional[str] = None,
                    ip_type: Optional[int] = None) -> bool:
        """
        Add an IP range to this provider.

        Args:
            cidr: CIDR notation string (e.g., "192.168.0.0/24")
            description: Description of the IP range
            region: Optional region information
            service: Optional service information
            ip_type: IP version (4 for IPv4, 6 for IPv6)

        Returns:
            bool: True if added successfully, False otherwise
        """
        # Auto-detect IP type if not provided
        if ip_type is None:
            try:
                network = ipaddress.ip_network(cidr)
                ip_type = 6 if network.version == 6 else 4
            except ValueError:
                return False

        info = IPRangeInfo(
            description=description,
            region=region,
            service=service,
            ip_type=ip_type
        )

        return self.ip_ranges.add(cidr, info)

    def lookup_ip(self, ip: str) -> List[Dict[str, Any]]:
        """
        Check if an IP belongs to this provider.

        Args:
            ip: IP address to check

        Returns:
            List of matching IP ranges with their metadata
        """
        return self.ip_ranges.lookup(ip)

    def range_count(self) -> int:
        """
        Get the number of IP ranges for this provider.

        Returns:
            int: Number of IP ranges
        """
        return self.ip_ranges.count()

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert provider to dictionary for API responses.

        Returns:
            Dict containing provider info
        """
        return {
            "id": self.provider_id,
            "name": self.display_name,
            "range_count": self.range_count()
        }