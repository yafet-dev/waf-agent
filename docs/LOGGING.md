# WAF Agent Logging Guide

## Viewing Logs

### Systemd Service (Production)

The waf-agent runs as a systemd service, and logs are sent to the systemd journal.

#### Basic Commands

```bash
# Follow logs in real-time (most useful)
sudo journalctl -u waf-agent -f

# View last 100 lines
sudo journalctl -u waf-agent -n 100

# View logs from today
sudo journalctl -u waf-agent --since today

# View logs from last hour
sudo journalctl -u waf-agent --since "1 hour ago"

# View logs with specific time range
sudo journalctl -u waf-agent --since "2024-01-01 00:00:00" --until "2024-01-01 23:59:59"

# View only errors
sudo journalctl -u waf-agent -p err

# View logs with priority (err, warning, info, debug)
sudo journalctl -u waf-agent -p warning
```

#### Filtering Logs

```bash
# Search for specific text
sudo journalctl -u waf-agent | grep "nginx"

# Search for errors
sudo journalctl -u waf-agent | grep -i error

# View logs for specific domain
sudo journalctl -u waf-agent | grep "example.com"
```

#### Export Logs

```bash
# Export to file
sudo journalctl -u waf-agent > waf-agent.log

# Export with timestamps
sudo journalctl -u waf-agent --no-pager > waf-agent-$(date +%Y%m%d).log
```

### Geo Agent Logs

If you have geo-agent running as a separate service:

```bash
# Follow geo-agent logs
sudo journalctl -u geo-agent -f

# View recent geo-agent logs
sudo journalctl -u geo-agent -n 50
```

### Manual Execution (Development)

When running manually (`python -m src.main`), logs appear directly in the terminal.

## Log Levels

The agent uses Python's logging module with the following levels:

- **INFO**: Normal operations (default)
- **WARNING**: Non-critical issues
- **ERROR**: Errors that need attention
- **DEBUG**: Detailed debugging information

## Changing Log Level

To change the log level, modify the logging configuration in `src/main.py`:

```python
logging.basicConfig(
    level=logging.DEBUG,  # Change from INFO to DEBUG for more details
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
```

Then restart the service:

```bash
sudo systemctl restart waf-agent
```

## File-Based Logging (Optional)

If you prefer file-based logging instead of journald, you can modify the logging configuration:

### Option 1: Update main.py

```python
import logging
from logging.handlers import RotatingFileHandler

# Create logs directory
log_dir = Path("/var/log/waf-agent")
log_dir.mkdir(parents=True, exist_ok=True)

# Configure file logging
log_file = log_dir / "waf-agent.log"
handler = RotatingFileHandler(
    log_file,
    maxBytes=10*1024*1024,  # 10MB
    backupCount=5
)
handler.setFormatter(
    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

# Also log to console
console_handler = logging.StreamHandler()
console_handler.setFormatter(
    logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
)
logger.addHandler(console_handler)
```

### Option 2: Update systemd service

Edit `/etc/systemd/system/waf-agent.service`:

```ini
[Service]
StandardOutput=append:/var/log/waf-agent/waf-agent.log
StandardError=append:/var/log/waf-agent/waf-agent-error.log
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart waf-agent
```

## Log Rotation

If using file logging, set up logrotate:

Create `/etc/logrotate.d/waf-agent`:

```
/var/log/waf-agent/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        systemctl reload waf-agent > /dev/null 2>&1 || true
    endscript
}
```

## Common Log Messages

### Successful Operations

```
INFO - Nginx configuration test passed
INFO - Nginx reloaded successfully
INFO - Updated modsecurity from 'off' to 'on'
```

### Errors

```
ERROR - Nginx configuration test failed: ...
ERROR - Failed to reload nginx: ...
ERROR - Config file not found: ...
```

### Warnings

```
WARNING - Not running as root. Nginx operations may fail.
WARNING - Vhost file not found for domain ...
```

## Troubleshooting

### No logs appearing

1. Check if service is running:
   ```bash
   sudo systemctl status waf-agent
   ```

2. Check journald is working:
   ```bash
   sudo journalctl --list-boots
   ```

3. Verify service is logging:
   ```bash
   sudo journalctl -u waf-agent --since "5 minutes ago"
   ```

### Logs too verbose

Reduce log level in `src/main.py` from `DEBUG` to `INFO` or `WARNING`.

### Need more details

Increase log level to `DEBUG` in `src/main.py` and restart the service.
