# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Environment Setup

```bash
# Create a virtual environment with Python 3.12
uv venv -p 3.12

# Activate the virtual environment
source .venv/bin/activate

# Install dependencies (project is pip-installable)
uv pip install -e .
```

## Running the Application

```bash
# Development mode (with debug output)
python test_run.py

# Production mode (clean interface)
python run.py

# Production with Gunicorn (Unix/WSL2 only)
gunicorn -b 127.0.0.1:5050 -w 4 "cloudfinderweb:create_app()"
```

Application available at http://localhost:5050

## Testing

```bash
# Run all tests
python tests/run_tests.py

# Individual test files can be run with Python unittest
python -m unittest tests.test_providers
python -m unittest tests.test_api
```

## Project Architecture

### Modular Design

The codebase uses a modern Flask application factory pattern with:

- **cloudfinderweb/app/providers/**: Cloud provider implementations using class inheritance
- **cloudfinderweb/app/models/**: Data structures (IPRangeTree for efficient lookups)
- **cloudfinderweb/app/api/**: REST API endpoints via Flask blueprints
- **cloudfinderweb/app/web/**: Web UI routes via Flask blueprints
- **cloudfinderweb/clouds/**: Cached IP range data (JSON files)

### Key Components

**Provider System**: Each cloud provider inherits from `CloudProvider` base class in `providers/base.py`. The base class provides:
- Async HTTP client with proper session management
- IP validation that handles both individual IPs and CIDR notation
- Standardized caching to `cloudfinderweb/clouds/{provider_id}.json`
- IP lookup using pre-computed `ipaddress` network objects

**IP Range Tree**: `models/ip_range.py` contains `IPRangeTree` class that:
- Stores IP networks as `ipaddress.ip_network` objects for efficient matching
- Provides O(n) lookup where n = number of networks (future optimization possible)
- Handles both IPv4 and IPv6 addresses
- Serializes/deserializes to JSON for caching

**Async Updates**: All providers can update concurrently using `asyncio.create_task()` in the provider registry.

### Data Flow

1. **Startup**: Providers load cached data from `cloudfinderweb/clouds/*.json`
2. **IP Lookup**: Convert input IP to `ipaddress.ip_address`, check against all cached networks
3. **Update**: Async fetch from provider APIs → validate/parse → save to cache → reload into memory

## Adding New Cloud Providers

1. Create new class in `cloudfinderweb/app/providers/new_provider.py`:
```python
from .base import CloudProvider

class NewProvider(CloudProvider):
    def __init__(self):
        super().__init__("provider_id", "Display Name")
        self.api_url = "https://api.example.com/ip-ranges"

    async def fetch_ip_ranges(self) -> bool:
        response = await self.http_get(self.api_url)
        if not response:
            return False

        data = await response.json()
        self.ip_ranges = self.ip_ranges.__class__()  # Clear existing

        for ip_range in data['ranges']:
            self.add_ip_range(
                cidr=ip_range['cidr'],
                description="IP used by New Provider",
                region=ip_range.get('region'),
                service=ip_range.get('service')
            )

        self._save_cache()
        return True
```

2. Register in `cloudfinderweb/app/providers/__init__.py`:
```python
from .new_provider import NewProvider
provider_registry.register(NewProvider())
```

## Important Implementation Details

**IP Validation**: The `is_valid_ip()` method tries `ipaddress.ip_network()` first (for CIDR), then `ipaddress.ip_address()`. This is critical as provider APIs return CIDR notation.

**HTTP Client**: Uses aiohttp with custom session management. The `ResponseWrapper` class in base.py handles the complexity of reading response data before session closure.

**Error Handling**: Providers that fail to update return `False` but don't crash the app. Failed updates are logged but the application continues with cached data.

**Flask Async**: Uses Flask with async support via `flask[async]` package. Routes marked with `async def` can use `await`.

## Configuration

Key settings in `cloudfinderweb/config/config.py`:
- `CLOUD_PROVIDER_URLS`: API endpoints for all providers
- `CLOUDS_DIR`: Cache directory location
- `API_TIMEOUT`: HTTP request timeout (default 60s)
- Flask environment configs (dev/prod)