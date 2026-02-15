#!/bin/bash
# ThreatGuard IP Blocking System - Linux VM Deployment Script
# Run with sudo

set -e

echo "========================================================================"
echo "    ThreatGuard Auto-Blocking System - Linux VM Setup"
echo "========================================================================"

# Check for root/sudo
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root or with sudo"
    echo "Usage: sudo bash deploy_linux_vm.sh"
    exit 1
fi

echo "[OK] Running with root privileges"

# Detect Linux distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
    echo "[INFO] Detected: $PRETTY_NAME"
else
    echo "[ERROR] Cannot detect Linux distribution"
    exit 1
fi

# Install dependencies based on distribution
echo ""
echo "[STEP 1/7] Installing dependencies..."

if [[ "$OS" == "kali" ]] || [[ "$OS" == "debian" ]] || [[ "$OS" == "ubuntu" ]]; then
    echo "[INFO] Using APT package manager"
    apt-get update -qq
    apt-get install -y python3 python3-pip python3-venv iptables
    # UFW is optional - only install if available
    apt-get install -y ufw 2>/dev/null || echo "[INFO] UFW not available on this system, using iptables"
elif [[ "$OS" == "centos" ]] || [[ "$OS" == "rhel" ]] || [[ "$OS" == "fedora" ]]; then
    echo "[INFO] Using YUM/DNF package manager"
    yum install -y python3 python3-pip iptables firewalld || dnf install -y python3 python3-pip iptables firewalld
elif [[ "$OS" == "arch" ]]; then
    echo "[INFO] Using Pacman package manager"
    pacman -Sy --noconfirm python python-pip iptables
else
    echo "[WARN] Unknown distribution - attempting generic install"
fi

echo "[OK] System packages installed"

# Install Python packages
echo ""
echo "[STEP 2/7] Installing Python packages..."
pip3 install --upgrade pip --break-system-packages
pip3 install --break-system-packages websockets requests python-dotenv

echo "[OK] Python packages installed"

# Create agent directory
echo ""
echo "[STEP 3/7] Creating agent directory..."

AGENT_DIR="/opt/threatguard_agent"
mkdir -p $AGENT_DIR
mkdir -p $AGENT_DIR/logs
cd $AGENT_DIR

echo "[OK] Agent directory created: $AGENT_DIR"

# Copy agent files (assuming they exist in vm_agent subdirectory)
echo ""
echo "[STEP 4/7] Setting up agent files..."

# If running from the project directory, copy files
if [ -f "../vm_agent/blocking_agent.py" ]; then
    cp ../vm_agent/blocking_agent.py $AGENT_DIR/
    echo "[OK] Copied blocking_agent.py"
else
    echo "[INFO] blocking_agent.py not found in ../vm_agent/"
    echo "[INFO] Please manually copy blocking_agent.py to $AGENT_DIR/"
fi

# Create default configuration
echo ""
echo "[STEP 5/7] Creating default configuration..."

cat > $AGENT_DIR/agent_config.json << 'EOF'
{
  "agent_id": "vm-agent-1",
  "websocket_url": "ws://192.168.1.100:8765",
  "api_url": "http://192.168.1.100:5000",
  "heartbeat_interval": 30,
  "reconnect_delay": 5,
  "jwt_token": null
}
EOF

echo "[OK] Created agent_config.json"
echo ""
echo "IMPORTANT: Edit $AGENT_DIR/agent_config.json with:"
echo "  - websocket_url: Your Windows host IP and port"
echo "  - api_url: Your Windows host API URL"
echo "  - jwt_token: Admin JWT token from Windows host"

# Configure firewall
echo ""
echo "[STEP 6/7] Configuring firewall..."

# Check which firewall is in use
if command -v ufw &> /dev/null && ufw status | grep -q "Status: active"; then
    echo "[INFO] UFW firewall detected and active"
    FIREWALL_TYPE="ufw"
elif command -v iptables &> /dev/null; then
    echo "[INFO] iptables detected"
    FIREWALL_TYPE="iptables"
    
    # Create custom chain for ThreatGuard
    iptables -N THREATGUARD_BLOCK 2>/dev/null || echo "[INFO] Chain already exists"
    iptables -C INPUT -j THREATGUARD_BLOCK 2>/dev/null || iptables -I INPUT -j THREATGUARD_BLOCK
    
    echo "[OK] Created iptables chain: THREATGUARD_BLOCK"
else
    echo "[WARN] No firewall detected - blocking may not work"
    FIREWALL_TYPE="none"
fi

echo "[OK] Firewall type: $FIREWALL_TYPE"

# Configure sudo permissions for blocking agent
echo ""
echo "[STEP 7/7] Configuring sudo permissions..."

SUDOERS_FILE="/etc/sudoers.d/threatguard"

cat > $SUDOERS_FILE << 'EOF'
# ThreatGuard Agent - Allow iptables/ufw commands without password
# This allows the blocking agent to manage firewall rules

# Allow all users to run iptables commands for ThreatGuard
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -A THREATGUARD_BLOCK *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -D THREATGUARD_BLOCK *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -A INPUT *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -D INPUT *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -A OUTPUT *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -D OUTPUT *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -I INPUT *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -I OUTPUT *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -N *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables -C *

# Allow UFW commands
ALL ALL=(ALL) NOPASSWD: /usr/sbin/ufw deny *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/ufw delete *
ALL ALL=(ALL) NOPASSWD: /usr/sbin/ufw status
EOF

chmod 0440 $SUDOERS_FILE

echo "[OK] Sudo permissions configured"

# Create systemd service
echo ""
echo "Creating systemd service..."

cat > /etc/systemd/system/threatguard-agent.service << EOF
[Unit]
Description=ThreatGuard IP Blocking Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$AGENT_DIR
ExecStart=/usr/bin/python3 $AGENT_DIR/blocking_agent.py
Restart=always
RestartSec=10
StandardOutput=append:$AGENT_DIR/logs/service.log
StandardError=append:$AGENT_DIR/logs/service_error.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo "[OK] Systemd service created: threatguard-agent.service"

# Create manual start script
cat > $AGENT_DIR/start_agent.sh << 'EOF'
#!/bin/bash
# Start ThreatGuard Agent manually

AGENT_DIR="/opt/threatguard_agent"
cd $AGENT_DIR

echo "Starting ThreatGuard Blocking Agent..."
echo "Press Ctrl+C to stop"
echo ""

python3 blocking_agent.py
EOF

chmod +x $AGENT_DIR/start_agent.sh

# Display final instructions
cat << 'EOF'

========================================================================
    Installation Complete!
========================================================================

Configuration Required:
-----------------------
1. Edit the configuration file:
   sudo nano /opt/threatguard_agent/agent_config.json

   Update the following:
   - websocket_url: ws://[WINDOWS_HOST_IP]:8765
   - api_url: http://[WINDOWS_HOST_IP]:5000
   - jwt_token: [PASTE_ADMIN_JWT_TOKEN_HERE]

2. Get JWT token from Windows host:
   - On Windows, run: python generate_admin_token.py
   - Copy the generated token
   - Paste it into agent_config.json

Starting the Agent:
-------------------

Option 1 - Run as systemd service (recommended):
  sudo systemctl enable threatguard-agent
  sudo systemctl start threatguard-agent
  sudo systemctl status threatguard-agent

Option 2 - Run manually (for testing):
  cd /opt/threatguard_agent
  sudo bash start_agent.sh

Verify Agent is Working:
------------------------
  # Check logs
  tail -f /opt/threatguard_agent/logs/blocking_agent.log

  # Check systemd service
  sudo systemctl status threatguard-agent

  # View blocked IPs
  cat /opt/threatguard_agent/blocked_ips.json

Firewall Commands:
------------------
  # View iptables rules
  sudo iptables -L THREATGUARD_BLOCK -n -v

  # View all blocked IPs
  sudo iptables -L INPUT -n -v | grep DROP

  # UFW status (if using UFW)
  sudo ufw status numbered

Troubleshooting:
----------------
  # If agent fails to connect:
  - Check Windows host IP is correct in config
  - Ensure port 8765 is open on Windows firewall
  - Verify JWT token is valid

  # If blocking fails:
  - Check sudo permissions: sudo -l
  - Test iptables manually: sudo iptables -L

========================================================================

Installation Directory: /opt/threatguard_agent

Press Enter to continue...
EOF

read

echo ""
echo "[SUCCESS] ThreatGuard VM Agent setup complete!"
echo ""
