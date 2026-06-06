#!/bin/bash
# ============================================================================
# CyberShield Firewall Setup
# Configures Raspberry Pi as transparent firewall/gateway
# ============================================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN} CyberShield Firewall Setup${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root: sudo bash setup_firewall.sh${NC}"
    exit 1
fi

# ============================================================
# DETECT NETWORK INTERFACES
# ============================================================
echo -e "${YELLOW}[1/8] Detecting network interfaces...${NC}"

# Show available interfaces
echo ""
echo "Available interfaces:"
ip -o link show | grep -v "lo:" | awk -F': ' '{printf "  - %s\n", $2}'
echo ""

# External interface (connected to internet/router)
echo -n "External interface (internet) [eth0]: "
read EXTERNAL
EXTERNAL=${EXTERNAL:-eth0}

# Internal interface (connected to LAN/protected devices)
echo -n "Internal interface (LAN) [wlan0]: "
read INTERNAL
INTERNAL=${INTERNAL:-wlan0}

echo ""
echo -e "Configuration:"
echo -e "  External: ${GREEN}${EXTERNAL}${NC}"
echo -e "  Internal: ${GREEN}${INTERNAL}${NC}"
echo ""

read -p "Continue? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ]; then
    echo "Aborted."
    exit 0
fi

# ============================================================
# ENABLE IP FORWARDING
# ============================================================
echo -e "${YELLOW}[2/8] Enabling IP forwarding...${NC}"
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf 2>/dev/null || true
echo -e "${GREEN}✓ IP forwarding enabled${NC}"

# ============================================================
# FLUSH EXISTING RULES
# ============================================================
echo -e "${YELLOW}[3/8] Clearing existing firewall rules...${NC}"
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
echo -e "${GREEN}✓ Rules cleared${NC}"

# ============================================================
# SET DEFAULT POLICIES
# ============================================================
echo -e "${YELLOW}[4/8] Setting default policies...${NC}"

# Default: DROP input, ACCEPT forward and output
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

echo -e "${GREEN}✓ Policies set (INPUT=DROP, FORWARD=ACCEPT, OUTPUT=ACCEPT)${NC}"

# ============================================================
# ALLOW ESSENTIAL TRAFFIC
# ============================================================
echo -e "${YELLOW}[5/8] Allowing essential traffic...${NC}"

# Loopback
iptables -A INPUT -i lo -j ACCEPT
echo "  ✓ Loopback"

# Established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
echo "  ✓ Established connections"

# SSH (port 22)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
echo "  ✓ SSH (22)"

# Dashboard (port 5000)
iptables -A INPUT -p tcp --dport 5000 -j ACCEPT
echo "  ✓ Dashboard (5000)"

# DNS
iptables -A INPUT -p udp --dport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
echo "  ✓ DNS (53)"

# DHCP
iptables -A INPUT -p udp --dport 67:68 -j ACCEPT
echo "  ✓ DHCP (67-68)"

# HTTP/HTTPS (if Pi hosts services)
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
echo "  ✓ HTTP/HTTPS (80,443)"

# ICMP (ping)
iptables -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
echo "  ✓ ICMP (ping)"

echo -e "${GREEN}✓ Essential traffic allowed${NC}"

# ============================================================
# SETUP NAT (MASQUERADE)
# ============================================================
echo -e "${YELLOW}[6/8] Setting up NAT...${NC}"

# Enable MASQUERADE for internet sharing
iptables -t nat -A POSTROUTING -o ${EXTERNAL} -j MASQUERADE
echo -e "${GREEN}✓ NAT enabled (${INTERNAL} → ${EXTERNAL})${NC}"

# ============================================================
# REDIRECT HTTP FOR DEEP INSPECTION (OPTIONAL)
# ============================================================
echo -e "${YELLOW}[7/8] Setting up traffic redirection...${NC}"

# Redirect HTTP to detection proxy (if using transparent proxy)
read -p "Enable HTTP redirection for deep inspection? (y/n): " ENABLE_REDIRECT

if [ "$ENABLE_REDIRECT" = "y" ]; then
    # Redirect HTTP (80) to port 8080 where detection proxy runs
    iptables -t nat -A PREROUTING -i ${INTERNAL} -p tcp --dport 80 \
        -j REDIRECT --to-port 8080
    echo -e "${GREEN}✓ HTTP redirection enabled (80 → 8080)${NC}"
else
    echo "  Skipped HTTP redirection"
fi

# ============================================================
# SAVE RULES
# ============================================================
echo -e "${YELLOW}[8/8] Saving firewall rules...${NC}"

# Try iptables-persistent first
if command -v iptables-save &> /dev/null; then
    # Save to different possible locations
    if [ -d "/etc/iptables" ]; then
        iptables-save > /etc/iptables/rules.v4
        echo -e "${GREEN}✓ Rules saved to /etc/iptables/rules.v4${NC}"
    elif [ -f "/etc/iptables/rules.v4" ]; then
        iptables-save > /etc/iptables/rules.v4
        echo -e "${GREEN}✓ Rules saved to /etc/iptables/rules.v4${NC}"
    else
        iptables-save > /etc/iptables.rules
        echo -e "${GREEN}✓ Rules saved to /etc/iptables.rules${NC}"
        echo -e "${YELLOW}  To restore on boot, add to /etc/rc.local:${NC}"
        echo -e "  iptables-restore < /etc/iptables.rules"
    fi
else
    echo -e "${YELLOW}  iptables-save not found${NC}"
    echo -e "${YELLOW}  Install with: apt install iptables-persistent${NC}"
fi

# ============================================================
# DONE
# ============================================================
echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN} FIREWALL SETUP COMPLETE!${NC}"
echo -e "${CYAN}============================================${NC}"
echo ""
echo -e "${GREEN}Your Raspberry Pi is now a transparent firewall.${NC}"
echo ""
echo "Network Flow:"
echo "  Internet → Router → [${EXTERNAL}] Pi [${INTERNAL}] → Protected Devices"
echo ""
echo "To test:"
echo "  1. Connect device to ${INTERNAL}"
echo "  2. Start CyberShield: sudo python3 run_live.py -i ${INTERNAL}"
echo "  3. Dashboard: http://<pi-ip>:5000"
echo ""
echo "To make rules permanent:"
echo "  sudo apt install iptables-persistent"
echo "  sudo netfilter-persistent save"
echo ""

# Make script executable
chmod +x "$0"