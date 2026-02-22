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

from fastapi import FastAPI, HTTPException, Security, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import List, Optional

# Try relative imports first (when run as module), fallback to absolute (when run directly)
try:
    from .waf_toggle import toggle_waf_for_domain, get_waf_status_for_domain
    from .ip_block import ban_unban_ip, get_ip_block_status
    from .geo_control import (
        read_list,
        write_list_atomic,
        set_mode_atomic,
        get_current_mode,
        validate_country_code,
        ALLOW_LIST_PATH,
        DENY_LIST_PATH,
    )
except ImportError:
    # Fallback to absolute imports when running directly
    from src.waf_toggle import toggle_waf_for_domain, get_waf_status_for_domain
    from src.ip_block import ban_unban_ip, get_ip_block_status
    from src.geo_control import (
        read_list,
        write_list_atomic,
        set_mode_atomic,
        get_current_mode,
        validate_country_code,
        ALLOW_LIST_PATH,
        DENY_LIST_PATH,
    )

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="WAF Agent", version="1.0.0", description="WAF Agent with Geo Access Control")

# Security
security = HTTPBearer()

# Request/Response models
class WAFToggleRequest(BaseModel):
    domain: str
    enabled: bool
    signature: str  # Base64 encoded signature of the request


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


# Geo Access Control models
class GeoModeRequest(BaseModel):
    mode: str  # "allow_only" or "deny_only"
    force: Optional[bool] = False


class GeoCountryRequest(BaseModel):
    country: str


class GeoHealthResponse(BaseModel):
    status: str
    service: str
    timestamp: str


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "agent_version": "1.0.0"
    }


@app.get("/v1/geo/health")
async def geo_health_check():
    """Geo service health check endpoint"""
    from datetime import datetime
    return {
        "status": "healthy",
        "service": "geo-agent",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/waf/toggle", response_model=WAFToggleResponse)
async def toggle_waf(
    request: WAFToggleRequest,
    authorization: HTTPAuthorizationCredentials = Security(security)
):
    """
    Toggle ModSecurity on/off for a domain
    
    This endpoint:
    1. Verifies the request signature
    2. Updates the nginx config file
    3. Tests the configuration
    4. Reloads nginx
    5. Returns status
    """
    try:
        result = toggle_waf_for_domain(
            domain=request.domain,
            enabled=request.enabled,
            signature=request.signature
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
    authorization: HTTPAuthorizationCredentials = Security(security)
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

@app.post("/v1/geo/mode")
async def set_geo_mode(
    request: GeoModeRequest,
    authorization: HTTPAuthorizationCredentials = Security(security)
):
    """
    Switch between allow_only and deny_only modes
    
    Body:
    {
        "mode": "allow_only" | "deny_only",
        "force": false  # optional, set to true to override safety checks
    }
    """
    try:
        if request.mode not in ["allow_only", "deny_only"]:
            raise HTTPException(
                status_code=400,
                detail='mode must be "allow_only" or "deny_only"'
            )
        
        # Safety: switching to allow_only with empty allow list blocks everyone
        if request.mode == "allow_only":
            allow = read_list(ALLOW_LIST_PATH)
            if len(allow) == 0 and not request.force:
                raise HTTPException(
                    status_code=400,
                    detail="Allow list is empty. This would block all traffic. Send force=true to override."
                )
        
        set_mode_atomic(request.mode)
        return {"ok": True, "mode": request.mode}
        
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error setting geo mode: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@app.post("/v1/geo/allow")
async def add_allow_country(
    request: GeoCountryRequest,
    authorization: HTTPAuthorizationCredentials = Security(security)
):
    """
    Add country to allow list
    
    Body:
    {
        "country": "ET"  # ISO-3166-1 alpha-2 uppercase
    }
    """
    try:
        if not validate_country_code(request.country):
            raise HTTPException(
                status_code=400,
                detail='Invalid country code. Must be uppercase ISO-3166-1 alpha-2 (e.g. "ET").'
            )
        
        codes = read_list(ALLOW_LIST_PATH)
        if request.country in codes:
            return {"ok": True, "message": "Already in allow list"}
        
        codes.add(request.country)
        write_list_atomic(ALLOW_LIST_PATH, codes)
        return {"ok": True, "added": request.country}
        
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error adding allow country: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@app.delete("/v1/geo/allow/{country}")
async def remove_allow_country(
    country: str,
    force: bool = False,
    authorization: HTTPAuthorizationCredentials = Security(security)
):
    """
    Remove country from allow list
    
    Query params:
    - force: bool (default: false) - set to true to override safety checks
    """
    try:
        if not validate_country_code(country):
            raise HTTPException(status_code=400, detail="Invalid country code.")
        
        codes = read_list(ALLOW_LIST_PATH)
        if country not in codes:
            return {"ok": True, "message": "Not in allow list"}
        
        # Safety: removing last entry while in allow_only mode blocks everyone
        if len(codes) == 1:
            mode = get_current_mode()
            if mode == "allow_only" and not force:
                raise HTTPException(
                    status_code=400,
                    detail="Removing the last country from the allow list in allow_only mode would block all traffic. Add ?force=true to override."
                )
        
        codes.remove(country)
        write_list_atomic(ALLOW_LIST_PATH, codes)
        return {"ok": True, "removed": country}
        
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error removing allow country: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@app.post("/v1/geo/deny")
async def add_deny_country(
    request: GeoCountryRequest,
    authorization: HTTPAuthorizationCredentials = Security(security)
):
    """
    Add country to deny list
    
    Body:
    {
        "country": "CN"  # ISO-3166-1 alpha-2 uppercase
    }
    """
    try:
        if not validate_country_code(request.country):
            raise HTTPException(
                status_code=400,
                detail='Invalid country code. Must be uppercase ISO-3166-1 alpha-2 (e.g. "CN").'
            )
        
        codes = read_list(DENY_LIST_PATH)
        if request.country in codes:
            return {"ok": True, "message": "Already in deny list"}
        
        codes.add(request.country)
        write_list_atomic(DENY_LIST_PATH, codes)
        return {"ok": True, "added": request.country}
        
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error adding deny country: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@app.delete("/v1/geo/deny/{country}")
async def remove_deny_country(
    country: str,
    authorization: HTTPAuthorizationCredentials = Security(security)
):
    """
    Remove country from deny list
    """
    try:
        if not validate_country_code(country):
            raise HTTPException(status_code=400, detail="Invalid country code.")
        
        codes = read_list(DENY_LIST_PATH)
        if country not in codes:
            return {"ok": True, "message": "Not in deny list"}
        
        codes.remove(country)
        write_list_atomic(DENY_LIST_PATH, codes)
        return {"ok": True, "removed": country}
        
    except HTTPException:
        raise
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error removing deny country: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@app.get("/v1/geo/status")
async def get_geo_status():
    """
    Get current geo access control status
    
    Returns:
    {
        "mode": "allow_only" | "deny_only" | "unknown",
        "allow": ["ET", "KE"],
        "deny": ["CN"]
    }
    """
    try:
        mode = get_current_mode()
        allow = read_list(ALLOW_LIST_PATH)
        deny = read_list(DENY_LIST_PATH)
        
        return {
            "mode": mode,
            "allow": sorted(allow),
            "deny": sorted(deny)
        }
        
    except Exception as e:
        error_trace = traceback.format_exc()
        error_msg = str(e) if str(e) else f"{type(e).__name__}"
        logger.error(f"Unexpected error getting geo status: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


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

