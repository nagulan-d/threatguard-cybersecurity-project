# Threat Intelligence Sharing System Deployment Guide

## Overview
This guide covers the Windows Admin Server setup and Linux agent installation for the pull-based threat enforcement system.

## 1) Windows Admin Server

### Prerequisites
- Python 3.10+
- Node.js 18+
- SQLite (default) or a database supported by SQLAlchemy

### Backend Setup
1. Open PowerShell in the project root:
   - cd backend
   - python -m venv .venv
   - .\.venv\Scripts\Activate.ps1
2. Install dependencies:
   - pip install -r requirements.txt
3. Set environment variables in backend/.env:
   - SECRET_KEY
   - DATABASE_URL
   - API_KEY (AlienVault OTX)
   - AGENT_API_TOKEN (shared secret for agents)
4. Apply database migrations:
   - flask db migrate -m "add agent tables"
   - flask db upgrade
5. Start the backend:
   - python app.py

### Frontend Setup
1. Open a new terminal:
   - cd frontend
   - npm install
   - npm start
2. Open the dashboard:
   - http://localhost:3000

### HTTPS (Recommended)
For production, terminate HTTPS in a reverse proxy (IIS, Nginx, or Caddy) and forward to the Flask server.

## 2) Linux Agent Installation

### Download and Install
1. From the Admin Dashboard, click "Download Security Agent".
2. Copy the installer to the Linux VM:
   - scp threat-agent-installer.sh user@vm:/tmp/
3. Run the installer:
   - sudo bash /tmp/threat-agent-installer.sh

### Configure the Agent
Edit /opt/threat-agent/agent.conf:
- SERVER_URL=https://YOUR_ADMIN_SERVER:5000
- API_TOKEN=YOUR_AGENT_API_TOKEN
- AGENT_ID=agent-001
- FIREWALL_BACKEND=auto
- VERIFY_TLS=true

Restart the timer:
- sudo systemctl restart threat-agent.timer

### Verify
- sudo systemctl status threat-agent.timer
- tail -f /var/log/threat-agent/agent.log

## 3) API Endpoints
- GET /api/high-risk-threats
  - Headers: X-Agent-Id, X-Api-Token, X-Timestamp, X-Hostname (optional)
- POST /api/status
  - Body: {"agent_id","ip","status","timestamp","hostname"}

## 4) Notes
- Agents pull every 5 minutes via systemd timer.
- Duplicate blocks are avoided through local cache and firewall rule checks.
- Update AGENT_API_TOKEN to rotate credentials.
