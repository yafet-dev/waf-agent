#!/usr/bin/env python3
"""
WAF Agent - Main FastAPI application
Manages ModSecurity on/off for nginx domains
Handles encrypted communication and nginx config updates
"""

import os
import sys
import logging
import traceback
from pathlib import Path

# Add parent directory to path to allow imports when running directly
# This needs to happen before any relative imports
_file_path = Path(__file__).resolve()
_parent_dir = _file_path.parent.parent

# If we're in a src directory and parent is not in path, add it
if _file_path.parent.name == "src" and str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

# Try relative imports first (when run as module), fallback to absolute (when run directly)
try:
    from .waf_toggle import toggle_waf_for_domain, get_waf_status_for_domain
    from .ip_block import ban_unban_ip, get_ip_block_status
    from .auth import require_auth
    from .geo_routes import router as geo_router
except ImportError:
    # Fallback to absolute imports when running directly
    from src.waf_toggle import toggle_waf_for_domain, get_waf_status_for_domain
    from src.ip_block import ban_unban_ip, get_ip_block_status
    from src.auth import require_auth
    from src.geo_routes import router as geo_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="WAF Agent", version="1.0.0", description="WAF Agent with Geo Access Control")

# Authentication lives in auth.py so this app and the standalone geo service
# enforce the identical policy.

# Request/Response models
class WAFToggleRequest(BaseModel):
    domain: str
    enabled: bool
    # Optional so a loopback caller can omit it; still mandatory for everyone
    # else, which toggle_waf_for_domain() enforces via require_signature.
    signature: Optional[str] = None


class WAFToggleResponse(BaseModel):
    status: str
    message: str
    domain: str
    modsecurity_status: str


class HealthResponse(BaseModel):
    status: str
    agent_version: str


class IPBanRequest(BaseModel):
    ip: str
    domains: List[str]  # Can be ["*"] for all domains
    action: str  # "ban" or "unban"


class IPBanResponse(BaseModel):
    ok: bool
    results: List[dict]
    error: Optional[str] = None


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "agent_version": "1.0.0"
    }


@app.post("/waf/toggle", response_model=WAFToggleResponse)
async def toggle_waf(
    request: WAFToggleRequest,
    is_local: bool = Depends(require_auth)
):
    """
    Toggle ModSecurity on/off for a domain

    This endpoint:
    1. Verifies the request signature (skipped for loopback callers)
    2. Updates the nginx config file
    3. Tests the configuration
    4. Reloads nginx
    5. Returns status
    """
    try:
        result = toggle_waf_for_domain(
            domain=request.domain,
            enabled=request.enabled,
            signature=request.signature,
            require_signature=not is_local
        )
        return WAFToggleResponse(**result)
    except HTTPException:
        # Re-raise HTTP exceptions as-is (401, 400, 404, 403, 500 from nginx)
        raise
    except FileNotFoundError as e:
        logger.error(f"Config file not found: {e}", exc_info=True)
        raise HTTPException(status_code=404, detail=f"Config file not found: {str(e)}")
    except PermissionError as e:
        logger.error(f"Permission denied: {e}", exc_info=True)
        raise HTTPException(status_code=403, detail=f"Permission denied: {str(e)}. Agent needs root/sudo access.")
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error toggling WAF: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@app.get("/waf/status/{domain}")
async def get_waf_status(domain: str):
    """Get current ModSecurity status for a domain"""
    try:
        return get_waf_status_for_domain(domain)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting WAF status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/ban", response_model=IPBanResponse)
async def ban_ip(
    request: IPBanRequest,
    _auth: bool = Depends(require_auth)
):
    """
    Ban or unban an IP address for one or more domains
    
    This endpoint:
    1. Updates block map files for each domain
    2. Ensures map config files exist
    3. Ensures server rule files exist
    4. Updates vhost files to include server rules
    5. Validates and reloads nginx
    """
    try:
        result = ban_unban_ip(
            ip=request.ip,
            domains=request.domains,
            action=request.action
        )
        return IPBanResponse(**result)
    except ValueError as e:
        logger.error(f"Invalid request: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error banning IP: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@app.get("/status")
async def get_status():
    """
    Get status of all domains and their blocked IPs
    
    Returns:
        - List of known domains
        - Blocked IPs per domain
        - Total count of blocked IPs
    """
    try:
        return get_ip_block_status()
    except Exception as e:
        logger.error(f"Error getting IP block status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── Geo Access Control Endpoints ────────────────────────────────────────────
# Defined in geo_routes.py and shared with the standalone geo service, so the
# two apps can never drift apart.
app.include_router(geo_router)


if __name__ == "__main__":
    import uvicorn
    
    # Check if running as root (required for nginx operations)
    if os.geteuid() != 0:
        logger.warning("WARNING: Not running as root. Nginx operations may fail.")
    
    # When running directly, we can't use module path, so run the app directly
    # Otherwise, use module path for uvicorn
    if Path(__file__).parent.name == "src" and str(Path(__file__).parent.parent) in sys.path:
        # Running from src directory with parent in path - use module path
        uvicorn.run(
            "src.main:app",
            host="0.0.0.0",
            port=8080,
            log_level="info"
        )
    else:
        # Running directly - use app object directly
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8080,
            log_level="info"
        )

