#!/bin/bash
# Process Monitor Uninstallation Script

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/process-monitor"
SERVICE_NAME="process-monitor"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Process Monitor Uninstallation Script"
echo "===================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Stop service
echo "Stopping service..."
systemctl stop $SERVICE_NAME 2>/dev/null || true
systemctl disable $SERVICE_NAME 2>/dev/null || true
echo -e "${GREEN}✓${NC} Service stopped and disabled"

# Remove systemd service
echo "Removing systemd service..."
rm -f /etc/systemd/system/$SERVICE_NAME.service
systemctl daemon-reload
echo -e "${GREEN}✓${NC} Systemd service removed"

# Remove ld.so.preload entry
echo "Removing ld.so.preload entry..."
if [ -f /etc/ld.so.preload ]; then
    grep -v "libprocess_monitor.so" /etc/ld.so.preload > /tmp/ld.so.preload.tmp
    mv /tmp/ld.so.preload.tmp /etc/ld.so.preload
fi
rm -f /usr/local/lib/libprocess_monitor.so
echo -e "${GREEN}✓${NC} ld.so.preload entry removed"

# Remove cron entry
echo "Removing cron entry..."
(crontab -l 2>/dev/null | grep -v "process-monitor-daemon") | crontab - 2>/dev/null || true
echo -e "${GREEN}✓${NC} Cron entry removed"

# Unload kernel module
echo "Unloading kernel module..."
rmmod monitor_hide 2>/dev/null || true
echo -e "${GREEN}✓${NC} Kernel module unloaded"

# Remove files
echo "Removing files..."
rm -f "$INSTALL_DIR/process-monitor-daemon"
rm -f "$INSTALL_DIR/config-publisher"
rm -f /var/run/process-monitor.pid
rm -rf "$CONFIG_DIR"
rm -rf /var/backups/process-monitor
echo -e "${GREEN}✓${NC} Files removed"

# Note about logs
echo ""
echo -e "${YELLOW}Note:${NC} Log files in /var/log/process-monitor/ were not removed."
echo "To remove them manually: rm -rf /var/log/process-monitor"
echo ""
echo -e "${GREEN}Uninstallation complete!${NC}"
