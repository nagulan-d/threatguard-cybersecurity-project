#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "This installer must be run as root."
  exit 1
fi

AGENT_DIR="/opt/threat-agent"
LOG_DIR="/var/log/threat-agent"

mkdir -p "${AGENT_DIR}"
mkdir -p "${LOG_DIR}"

cat <<'PY' > "${AGENT_DIR}/threat_agent.py"
#!/usr/bin/env python3
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone

try:
    import requests
except Exception:
    print("Missing requests module. Run: python3 -m pip install requests")
    sys.exit(1)

CONFIG_PATH = "/opt/threat-agent/agent.conf"
STATE_PATH = "/opt/threat-agent/blocked_cache.json"
LOG_PATH = "/var/log/threat-agent/agent.log"

DEFAULTS = {
    "SERVER_URL": "",
    "API_TOKEN": "",
    "AGENT_ID": "",
    "FIREWALL_BACKEND": "auto",
    "VERIFY_TLS": "true",
    "POLL_INTERVAL": "300",
}


def load_config():
    cfg = DEFAULTS.copy()
    if not os.path.exists(CONFIG_PATH):
        return cfg
    with open(CONFIG_PATH, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            cfg[key.strip()] = value.strip()
    return cfg


def ensure_logger():
    logger = logging.getLogger("threat-agent")
    logger.setLevel(logging.INFO)
    handler = logging.FileHandler(LOG_PATH)
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    handler.setFormatter(formatter)
    if not logger.handlers:
        logger.addHandler(handler)
    return logger


def read_state():
    if not os.path.exists(STATE_PATH):
        return set()
    try:
        with open(STATE_PATH, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return set(data.get("blocked_ips", []))
    except Exception:
        return set()


def write_state(blocked_ips):
    data = {
        "blocked_ips": sorted(blocked_ips),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(STATE_PATH, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def select_firewall_backend(cfg):
    backend = (cfg.get("FIREWALL_BACKEND") or "auto").lower()
    if backend in ("iptables", "ufw"):
        return backend
    if shutil.which("ufw"):
        return "ufw"
    return "iptables"


def iptables_has_rule(ip_address):
    cmd = ["iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
    result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return result.returncode == 0


def iptables_block(ip_address):
    cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    subprocess.check_call(cmd)


def ufw_has_rule(ip_address):
    cmd = ["ufw", "status"]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    output = result.stdout.lower()
    return ip_address.lower() in output


def ufw_block(ip_address):
    cmd = ["ufw", "--force", "deny", "from", ip_address]
    subprocess.check_call(cmd)


def block_ip(ip_address, backend, logger):
    if backend == "ufw":
        if ufw_has_rule(ip_address):
            return False, "already_blocked"
        ufw_block(ip_address)
        return True, "blocked"

    if iptables_has_rule(ip_address):
        return False, "already_blocked"
    iptables_block(ip_address)
    return True, "blocked"


def build_headers(cfg):
    hostname = socket.gethostname()
    timestamp = datetime.now(timezone.utc).isoformat()
    return {
        "X-Agent-Id": cfg.get("AGENT_ID", ""),
        "X-Api-Token": cfg.get("API_TOKEN", ""),
        "X-Timestamp": timestamp,
        "X-Hostname": hostname,
    }


def send_status(cfg, ip_address, status, message=""):
    url = cfg.get("SERVER_URL", "").rstrip("/") + "/api/status"
    headers = build_headers(cfg)
    payload = {
        "agent_id": cfg.get("AGENT_ID", ""),
        "ip": ip_address,
        "status": status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": headers.get("X-Hostname"),
        "message": message,
    }
    verify_tls = str(cfg.get("VERIFY_TLS", "true")).lower() == "true"
    try:
        requests.post(url, json=payload, headers=headers, timeout=15, verify=verify_tls)
    except Exception:
        return


def run_once():
    cfg = load_config()
    logger = ensure_logger()

    if not cfg.get("SERVER_URL") or not cfg.get("API_TOKEN") or not cfg.get("AGENT_ID"):
        logger.error("Missing SERVER_URL, API_TOKEN, or AGENT_ID in config")
        return

    if os.geteuid() != 0:
        logger.error("Agent must run as root to manage firewall rules")
        return

    headers = build_headers(cfg)
    verify_tls = str(cfg.get("VERIFY_TLS", "true")).lower() == "true"
    url = cfg.get("SERVER_URL", "").rstrip("/") + "/api/high-risk-threats"

    try:
        response = requests.get(url, headers=headers, timeout=20, verify=verify_tls)
    except Exception as exc:
        logger.error("Failed to contact server: %s", exc)
        return

    if response.status_code != 200:
        logger.error("Server responded with %s: %s", response.status_code, response.text)
        return

    payload = response.json()
    threats = payload.get("threats", []) if isinstance(payload, dict) else []

    backend = select_firewall_backend(cfg)
    blocked_cache = read_state()
    updated = False

    for threat in threats:
        ip_address = threat.get("ip")
        if not ip_address or ip_address in blocked_cache:
            continue
        try:
            success, status = block_ip(ip_address, backend, logger)
            if success:
                blocked_cache.add(ip_address)
                updated = True
                logger.info("Blocked %s via %s", ip_address, backend)
                send_status(cfg, ip_address, "blocked")
            else:
                logger.info("Skipped %s (%s)", ip_address, status)
                send_status(cfg, ip_address, status)
        except Exception as exc:
            logger.error("Failed to block %s: %s", ip_address, exc)
            send_status(cfg, ip_address, "error", str(exc))

    if updated:
        write_state(blocked_cache)


if __name__ == "__main__":
    run_once()
PY

chmod +x "${AGENT_DIR}/threat_agent.py"

cat <<'CONF' > "${AGENT_DIR}/agent.conf"
# Threat Agent Configuration
SERVER_URL=https://YOUR_ADMIN_SERVER:5000
API_TOKEN=REPLACE_WITH_AGENT_API_TOKEN
AGENT_ID=agent-001
FIREWALL_BACKEND=auto
VERIFY_TLS=true
POLL_INTERVAL=300
CONF

cat <<'SERVICE' > /etc/systemd/system/threat-agent.service
[Unit]
Description=Threat Intelligence Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/threat-agent/threat_agent.py

[Install]
WantedBy=multi-user.target
SERVICE

cat <<'TIMER' > /etc/systemd/system/threat-agent.timer
[Unit]
Description=Run Threat Intelligence Agent every 5 minutes

[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
Unit=threat-agent.service

[Install]
WantedBy=timers.target
TIMER

systemctl daemon-reload
systemctl enable --now threat-agent.timer

cat <<'INFO'
Installation complete.

Next steps:
1) Edit /opt/threat-agent/agent.conf
2) Restart timer: systemctl restart threat-agent.timer
3) Check logs: tail -f /var/log/threat-agent/agent.log
INFO
