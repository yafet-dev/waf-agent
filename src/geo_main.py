#!/usr/bin/env python3
"""
Geo Agent - Main FastAPI application
Manages Geo Access Control for Nginx WAF
Handles country allow/deny lists and mode switching
"""

import os
import sys
import logging
import traceback
from pathlib import Path
from typing import Optional

# Add parent directory to path to allow imports when running directly
_file_path = Path(__file__).resolve()
_parent_dir = _file_path.parent.parent

if _file_path.parent.name == "src" and str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

# Try relative imports first (when run as module), fallback to absolute (when run directly)
try:
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

app = FastAPI(title="Geo Agent", version="1.0.0")

# ─── Request/Response models ────────────────────────────────────────────────
class ModeRequest(BaseModel):
    mode: str  # "allow_only" or "deny_only"
    force: Optional[bool] = False


class CountryRequest(BaseModel):
    country: str


class HealthResponse(BaseModel):
    status: str
    service: str
    timestamp: str


# ─── Endpoints ───────────────────────────────────────────────────────────────
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    from datetime import datetime
    return {
        "status": "healthy",
        "service": "geo-agent",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/v1/geo/mode")
async def set_mode(request: ModeRequest):
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
        logger.error(f"Unexpected error setting mode: {error_msg}\n{error_trace}")
        raise HTTPException(status_code=500, detail=f"Internal error: {error_msg}")


@app.post("/v1/geo/allow")
async def add_allow_country(request: CountryRequest):
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
async def remove_allow_country(country: str, force: bool = Query(False)):
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
async def add_deny_country(request: CountryRequest):
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
async def remove_deny_country(country: str):
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
async def get_status():
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
        logger.error(f"Unexpected error getting status: {error_msg}\n{error_trace}")
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
            "src.geo_main:app",
            host="0.0.0.0",
            port=8081,
            log_level="info"
        )
    else:
        # Running directly - use app object directly
        uvicorn.run(
            app,
            host="0.0.0.0",
            port=8081,
            log_level="info"
        )
