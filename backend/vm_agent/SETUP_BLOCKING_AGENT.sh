#!/bin/bash
# IP Blocking Synchronization System - Kali Linux Setup
# Run this on your Kali Linux VM

set -e

echo "=========================================="
echo "🚀 Kali Blocking Agent Setup"
echo "=========================================="
echo ""

# Check if running as root for some operations
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "⚠️  Some operations require root privileges"
        echo "You may be prompted for your password"
    fi
}

# Check Python
echo "📋 Checking Python installation..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found. Installing..."
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip
else
    PYTHON_VER=$(python3 --version)
    echo "✅ Found: $PYTHON_VER"
fi

# Install Python dependencies
echo ""
echo "📦 Installing Python dependencies..."
pip3 install flask requests --upgrade
echo "✅ Dependencies installed"

# Create agent directory
echo ""
echo "📁 Setting up agent directory..."
AGENT_DIR="/opt/threatguard"
if [ ! -d "$AGENT_DIR" ]; then
    echo "Creating $AGENT_DIR..."
    sudo mkdir -p "$AGENT_DIR"
    sudo chown $USER:$USER "$AGENT_DIR"
else
    echo "✅ $AGENT_DIR already exists"
fi

# Create logs directory
sudo mkdir -p "$AGENT_DIR/logs"
sudo chown $USER:$USER "$AGENT_DIR/logs"

# Create agent config
echo ""
echo "⚙️ Creating agent configuration..."
cat > "$AGENT_DIR/agent_config.json" << 'EOF'
{
  "api_port": 5001,
  "api_token": "from_env",
  "firewall_type": "auto",
  "blocked_ips_file": "/opt/threatguard/blocked_ips.json",
  "log_file": "/opt/threatguard/logs/blocking_agent.log"
}
EOF
echo "✅ Configuration created at $AGENT_DIR/agent_config.json"

# Setup firewall (iptables/ufw)
echo ""
echo "🔧 Setting up firewall..."
check_root

# Check if ufw is available
if command -v ufw &> /dev/null; then
    echo "✅ UFW detected. Checking status..."
    sudo ufw status | head -1
else
    echo "⚠️  UFW not found. Installing..."
    sudo apt-get install -y ufw
fi

# Setup iptables chain
echo "Setting up iptables THREATGUARD chain..."
sudo iptables -N THREATGUARD 2>/dev/null || echo "  (Chain may already exist)"
sudo iptables -I INPUT -j THREATGUARD 2>/dev/null || echo "  (INPUT rule may already exist)"
sudo iptables -I OUTPUT -j THREATGUARD 2>/dev/null || echo "  (OUTPUT rule may already exist)"
echo "✅ iptables chain ready"

# Make persistent
if [ -f /etc/iptables/rules.v4 ]; then
    echo "Saving iptables rules..."
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 > /dev/null
fi

# Request API token from user
echo ""
echo "🔐 API Token Configuration"
read -p "Enter the API token from Windows host: " API_TOKEN

# Create systemd service
echo ""
echo "📝 Creating systemd service..."
cat > "/tmp/threatguard-agent.service" << EOF
[Unit]
Description=ThreatGuard IP Blocking Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$AGENT_DIR
Environment="BLOCKING_API_TOKEN=$API_TOKEN"
Environment="BLOCKING_AGENT_PORT=5001"
Environment="DEBUG=false"
ExecStart=/usr/bin/python3 $AGENT_DIR/enhanced_blocking_agent.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo cp /tmp/threatguard-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "✅ Systemd service created"

# Summary
echo ""
echo "=========================================="
echo "✅ Setup Complete!"
echo "=========================================="
echo ""
echo "Next Steps:"
echo ""
echo "1. Copy the enhanced blocking agent to $AGENT_DIR:"
echo "   scp enhanced_blocking_agent.py kali@<your-ip>:$AGENT_DIR/"
echo ""
echo "2. Start the blocking agent:"
echo "   sudo systemctl enable threatguard-agent"
echo "   sudo systemctl start threatguard-agent"
echo ""
echo "3. Verify it's running:"
echo "   sudo systemctl status threatguard-agent"
echo "   tail -f $AGENT_DIR/logs/blocking_agent.log"
echo ""
echo "4. Test the API:"
echo "   curl -H 'Authorization: Bearer $API_TOKEN' http://localhost:5001/api/health"
echo ""
echo "📋 Service Logs:"
echo "   journalctl -u threatguard-agent -f"
echo ""
echo "🔧 Firewall Rules:"
echo "   sudo iptables -L THREATGUARD -n"
echo ""
echo "=========================================="
