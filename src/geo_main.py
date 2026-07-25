#!/usr/bin/env python3
"""
Geo Agent - standalone FastAPI application

Serves only the geo access control endpoints, for deployments that run geo
separately from the WAF agent. The endpoints themselves live in geo_routes.py
and are shared with main.py, so the two services cannot drift apart.

Most deployments do not need this: main.py already serves the same routes on
port 8080, and the backend defaults GEO_AGENT_URL to WAF_AGENT_URL.
"""

import os
import sys
import logging
from pathlib import Path

# Add parent directory to path to allow imports when running directly
_file_path = Path(__file__).resolve()
_parent_dir = _file_path.parent.parent

if _file_path.parent.name == "src" and str(_parent_dir) not in sys.path:
    sys.path.insert(0, str(_parent_dir))

from fastapi import FastAPI

# Try relative imports first (when run as module), fallback to absolute
try:
    from .geo_routes import router as geo_router
except ImportError:
    from src.geo_routes import router as geo_router

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Geo Agent", version="1.0.0")

app.include_router(geo_router)


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    from datetime import datetime
    return {
        "status": "healthy",
        "service": "geo-agent",
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    import uvicorn

    # Check if running as root (required for nginx operations)
    if os.geteuid() != 0:
        logger.warning("WARNING: Not running as root. Nginx operations may fail.")

    if Path(__file__).parent.name == "src" and str(Path(__file__).parent.parent) in sys.path:
        uvicorn.run("src.geo_main:app", host="0.0.0.0", port=8081, log_level="info")
    else:
        uvicorn.run(app, host="0.0.0.0", port=8081, log_level="info")
