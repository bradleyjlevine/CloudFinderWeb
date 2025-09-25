"""
Configuration settings for CloudFinderWeb
"""

import os

# Base directory of the application
BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

# Directory where cloud provider IP range data is stored
CLOUDS_DIR = os.path.join(BASE_DIR, "clouds")

# Default API timeout in seconds
API_TIMEOUT = 60

# Default HTTP headers for requests
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0"
}

# Cloud provider API endpoints
CLOUD_PROVIDER_URLS = {
    # AWS
    "aws": "https://ip-ranges.amazonaws.com/ip-ranges.json",

    # Google Cloud Platform
    "google": "https://www.gstatic.com/ipranges/goog.json",
    "gcp": "https://www.gstatic.com/ipranges/cloud.json",

    # Cloudflare
    "cloudflare-v4": "https://www.cloudflare.com/ips-v4/#",
    "cloudflare-v6": "https://www.cloudflare.com/ips-v6/#",

    # Fastly
    "fastly": "https://api.fastly.com/public-ip-list",

    # OCI (Oracle Cloud Infrastructure)
    "oci": "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json",

    # Linode
    "linode": "https://geoip.linode.com/",

    # GitHub
    "github": "https://api.github.com/meta",

    # DigitalOcean
    "digital_ocean": "https://digitalocean.com/geo/google.csv",

    # Akamai
    "akamai": "https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_ipv6_CIDRs-txt.zip",

    # Azure
    "azure_base": "https://azservicetags.azurewebsites.net/",

    # IBM Cloud
    "ibm": "https://raw.githubusercontent.com/dprosper/cidr-calculator/main/data/datacenters.json",

    # Office 365
    "o365": "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7",

    # Zscaler
    "zscaler": "https://config.zscaler.com/api/zscaler.net/cenr/json",
    "zscaler-hubs": "https://config.zscaler.com/api/zscaler.net/hubs/cidr/json/required",

    # Auth0
    "auth0": "https://cdn.auth0.com/ip-ranges.json",

    # Salesforce
    "salesforce": "https://ip-ranges.salesforce.com/ip-ranges.json",
}

# Flask configuration
class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'development-key'
    DEBUG = False
    TESTING = False
    SERVER_NAME = None

class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True

class ProductionConfig(Config):
    """Production configuration"""
    pass

# Set active configuration
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}

active_config = config[os.environ.get('FLASK_ENV', 'default')]