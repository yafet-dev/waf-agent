# Geo Agent Setup Guide

## Installation

### 1. Install the Service

```bash
# Copy service file to systemd directory
sudo cp systemd/geo-agent.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable geo-agent

# Start the service
sudo systemctl start geo-agent

# Check status
sudo systemctl status geo-agent
```

### 2. Verify It's Running

```bash
# Check if service is active
sudo systemctl is-active geo-agent

# Check logs
sudo journalctl -u geo-agent -f

# Test health endpoint
curl http://localhost:8081/health
```

### 3. Configure Backend

Make sure your backend `.env` file has:

```env
GEO_AGENT_URL=http://localhost:8081
GEO_AGENT_AUTH_TOKEN=your-token-here
```

Or if running on a different server:

```env
GEO_AGENT_URL=http://your-server-ip:8081
GEO_AGENT_AUTH_TOKEN=your-token-here
```

## Manual Start (Development)

```bash
cd /opt/waf-agent
source venv/bin/activate
python -m src.geo_main
```

## Troubleshooting

### Service Won't Start

1. Check service status:
   ```bash
   sudo systemctl status geo-agent
   ```

2. Check logs for errors:
   ```bash
   sudo journalctl -u geo-agent -n 50
   ```

3. Verify Python and dependencies:
   ```bash
   /opt/waf-agent/venv/bin/python --version
   /opt/waf-agent/venv/bin/pip list | grep fastapi
   ```

### Connection Refused Error

If backend shows `ECONNREFUSED`:

1. **Check if geo-agent is running:**
   ```bash
   sudo systemctl status geo-agent
   ```

2. **Check if port 8081 is listening:**
   ```bash
   sudo netstat -tlnp | grep 8081
   # or
   sudo ss -tlnp | grep 8081
   ```

3. **Check firewall:**
   ```bash
   sudo ufw status
   # If firewall is active, allow port 8081:
   sudo ufw allow 8081/tcp
   ```

4. **Test connection from backend server:**
   ```bash
   curl http://localhost:8081/health
   # or if on different server:
   curl http://your-geo-agent-ip:8081/health
   ```

5. **Verify backend environment variable:**
   ```bash
   # In your backend .env file, check:
   GEO_AGENT_URL=http://localhost:8081
   # Make sure it matches where geo-agent is running
   ```

### Port Already in Use

If port 8081 is already in use:

1. Find what's using it:
   ```bash
   sudo lsof -i :8081
   # or
   sudo netstat -tlnp | grep 8081
   ```

2. Either stop the conflicting service or change geo-agent port:
   - Edit `src/geo_main.py` and change port from 8081 to another port
   - Update backend `.env` with new port

### Permission Errors

Geo-agent needs root access to modify nginx configs:

```bash
# Make sure service runs as root (already configured in service file)
# If running manually, use:
sudo python -m src.geo_main
```

## Service Management

```bash
# Start service
sudo systemctl start geo-agent

# Stop service
sudo systemctl stop geo-agent

# Restart service
sudo systemctl restart geo-agent

# View logs (follow mode)
sudo journalctl -u geo-agent -f

# View recent logs
sudo journalctl -u geo-agent -n 100

# Check status
sudo systemctl status geo-agent
```

## Testing

After installation, test the endpoints:

```bash
# Health check
curl http://localhost:8081/health

# Get status (requires auth token)
curl -H "Authorization: Bearer your-token" http://localhost:8081/v1/geo/status

# Set mode (requires auth token)
curl -X POST \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"mode": "allow_only", "force": false}' \
  http://localhost:8081/v1/geo/mode
```

## Integration with Backend

Once geo-agent is running, the backend will automatically sync settings when you save geo access configurations through the UI.

The sync happens in this order:
1. User saves settings in frontend
2. Backend validates and saves to database
3. Backend calls geo-agent API to sync settings
4. Geo-agent updates nginx configuration files
5. Geo-agent validates and reloads nginx

If geo-agent is not running, the backend will return a 502 error and won't save to the database (to keep data in sync).
