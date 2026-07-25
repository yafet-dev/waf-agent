"""
Configuration constants and utilities for WAF Agent
"""

import os
import subprocess
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Configuration paths.
#
# Every location is env-overridable so the agent can run against a test tree
# instead of the real /etc/nginx. The defaults are the standard Debian/Ubuntu
# layout, so a normal deployment needs none of these set.
NGINX_SITES_AVAILABLE = Path(os.getenv("NGINX_SITES_AVAILABLE", "/etc/nginx/sites-available"))
NGINX_SITES_ENABLED = Path(os.getenv("NGINX_SITES_ENABLED", "/etc/nginx/sites-enabled"))
PRIVATE_KEY_PATH = Path(os.getenv("WAF_AGENT_PRIVATE_KEY", "/etc/waf-agent/private_key.pem"))
PUBLIC_KEY_PATH = Path(os.getenv("WAF_AGENT_PUBLIC_KEY", "/etc/waf-agent/public_key.pem"))

# WAF IP blocking paths
WAF_BLOCKS_DIR = Path(os.getenv("WAF_BLOCKS_DIR", "/etc/nginx/waf/blocks"))
WAF_MAPS_DIR = Path(os.getenv("WAF_MAPS_DIR", "/etc/nginx/waf/maps"))
WAF_SERVERS_DIR = Path(os.getenv("WAF_SERVERS_DIR", "/etc/nginx/waf/servers"))

# Geo access control paths
GEO_LISTS_DIR = Path(os.getenv("GEO_LISTS_DIR", "/etc/nginx/waf/geo-lists"))
GEO_SERVERS_DIR = Path(os.getenv("GEO_SERVERS_DIR", "/etc/nginx/waf/geo-servers"))

# Geo map files declare `map` blocks, which nginx only accepts in the http
# context. Standard Debian/Ubuntu nginx.conf already carries
# `include /etc/nginx/conf.d/*.conf;` inside http, so writing there wires the
# maps in without ever editing nginx.conf.
NGINX_CONF_D = Path(os.getenv("NGINX_CONF_D", "/etc/nginx/conf.d"))

# The nginx variable holding the visitor's ISO-3166-1 alpha-2 country code.
# Depends on how the GeoIP2 module is configured; override if your setup
# exposes a different name (e.g. $geoip2_data_country_code).
GEO_COUNTRY_VARIABLE = os.getenv("GEO_COUNTRY_VARIABLE", "$geoip2_country_code")

# Find nginx and systemctl binaries
def find_binary(name: str, common_paths: list[str] = None) -> str:
    """Find a binary in common system paths"""
    if common_paths is None:
        common_paths = [
            f"/usr/sbin/{name}",
            f"/usr/bin/{name}",
            f"/sbin/{name}",
            f"/bin/{name}",
            name  # Try in PATH as fallback
        ]
    
    for path in common_paths:
        if os.path.exists(path) and os.access(path, os.X_OK):
            return path
    
    # Last resort: try which/whereis
    try:
        result = subprocess.run(['which', name], capture_output=True, text=True, timeout=2)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except:
        pass
    
    # Return the name itself if not found (will fail with better error message)
    return name

NGINX_BINARY = find_binary('nginx', ['/usr/sbin/nginx', '/usr/bin/nginx', '/sbin/nginx'])
SYSTEMCTL_BINARY = find_binary('systemctl', ['/usr/bin/systemctl', '/bin/systemctl'])

# Log found binaries at startup
logger.info(f"Using nginx binary: {NGINX_BINARY}")
logger.info(f"Using systemctl binary: {SYSTEMCTL_BINARY}")
