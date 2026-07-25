# WAF Agent

Python-based agent that manages ModSecurity on/off status for nginx domains. Handles encrypted communication and nginx configuration updates.

## Features

- ✅ Encrypted communication using RSA public/private key pairs
- ✅ Updates nginx configuration files automatically
- ✅ Tests nginx config before applying changes
- ✅ Creates backups before modifications
- ✅ Reloads nginx after successful updates
- ✅ RESTful API with FastAPI
- ✅ Health check endpoint
- ✅ Status query endpoint

## Project Structure

```
waf-agent/
├── src/                    # Source code
│   ├── __init__.py
│   ├── main.py            # FastAPI application
│   ├── config.py          # Configuration constants
│   ├── security.py        # Authentication & signature verification
│   ├── nginx_utils.py     # Nginx configuration utilities
│   └── waf_toggle.py      # WAF toggle functionality
├── scripts/               # Utility scripts
│   ├── generate_keys.py   # RSA key pair generator
│   ├── install.sh         # Installation script
│   └── test_toggle.sh      # Testing script
├── systemd/               # Systemd service files
│   └── waf-agent.service  # Service configuration
├── docs/                  # Documentation
│   └── INSTALLATION.md    # Installation guide
├── requirements.txt       # Python dependencies
└── README.md             # This file
```

## Quick Start

See [docs/INSTALLATION.md](docs/INSTALLATION.md) for detailed installation instructions.

### Quick Install

```bash
sudo bash scripts/install.sh
```

## Requirements

- Python 3.8+
- nginx installed and configured
- Root/sudo access (for nginx operations)
- RSA key pair for encryption

## Authentication

Mutating endpoints require a bearer token and, for `/waf/toggle`, an RSA
signature — **unless the caller is on this same machine**.

| Caller's peer address | Bearer token | Signature |
| --- | --- | --- |
| Loopback (`127.x`, `::1`) | Optional | Optional |
| Anything else, LAN included | **Required** | **Required** |

A request arriving over loopback never touched a network interface, so a shared
token adds setup friction without adding security. Every other caller must
authenticate. The backend applies the mirror-image rule and only omits
credentials when its `WAF_AGENT_URL` is a loopback address, so the two sides
agree on exactly one credential-free case.

A supplied signature is **always** verified, loopback included — a wrong key is
never silently ignored, only an absent one is tolerated locally.

### Make the bearer token real

Set `WAF_AGENT_AUTH_TOKEN` on the agent to the same value the backend uses:

```bash
# /etc/waf-agent/agent.env  (or the systemd unit's Environment=)
WAF_AGENT_AUTH_TOKEN=the-same-long-random-string-the-backend-sends
```

**Until you set it, any non-empty token is accepted** and the agent logs a
warning on every request. That is the historical behaviour, kept so turning
this on is never a prerequisite for an already-working deployment — but it
means `/ban` and the geo endpoints are effectively unauthenticated for anyone
who can reach the port. `/waf/toggle` is still protected by its RSA signature.

Setting it is the single highest-value hardening step for a
publicly-reachable agent.

Unauthenticated by design: `/health`, `/v1/geo/health`, `/waf/status/{domain}`,
`/status`, `/v1/geo/status`. These are read-only.

### Running behind a reverse proxy

Behind a proxy every request appears to come from loopback, which would hand an
auth bypass to the whole internet. Two protections:

1. A request carrying `X-Forwarded-For`, `X-Real-IP`, `Forwarded`, or
   `X-Forwarded-Host` is never treated as local.
2. Set `WAF_AGENT_STRICT_AUTH=true` to require credentials from every caller,
   loopback included. Use this whenever the agent is proxied — it only ever
   tightens the policy.

## API Endpoints

### Health Check
```bash
GET /health
```

### Toggle WAF Status
```bash
POST /waf/toggle
Content-Type: application/json
Authorization: Bearer <token>     # omit only when calling over loopback

{
  "domain": "example.com",
  "enabled": true,
  "signature": "<base64_encoded_signature>"   # omit only when calling over loopback
}
```

### Get WAF Status
```bash
GET /waf/status/{domain}
```

### Geo Access Control

Country blocking, scoped per domain. The first request for a domain creates all
the nginx files it needs and wires them into its server block.

```bash
POST   /v1/geo/{domain}/mode              {"mode": "allow_only" | "deny_only"}
POST   /v1/geo/{domain}/allow             {"country": "ET"}
DELETE /v1/geo/{domain}/allow/{country}
POST   /v1/geo/{domain}/deny              {"country": "CN"}
DELETE /v1/geo/{domain}/deny/{country}
GET    /v1/geo/{domain}/status
GET    /v1/geo/status                     all domains
```

Requires the nginx GeoIP2 module and a country database. See
[docs/GEO_ACCESS_CONTROL.md](docs/GEO_ACCESS_CONTROL.md) for setup and the full
file layout.

## Tests

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

`tests/test_auth_policy.py` locks in the authentication boundary described
above. All nginx side effects are stubbed, so it needs no root and touches no
real config.

## Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the agent
python -m src.main
```

## License

Internal use only.
