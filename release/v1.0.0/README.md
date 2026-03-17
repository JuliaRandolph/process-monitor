# Linux Process Monitor & Persistence System

A comprehensive Linux process monitoring system with kernel-level hiding capabilities and multiple persistence mechanisms.

## Features

- **Blacklist Monitoring**: Real-time detection and termination of blacklisted processes
- **Whitelist Protection**: Hide critical processes with auto-restart capability
- **Kernel-Level Hiding**: Process hiding via kernel module syscall hooks
- **Encrypted Configuration**: AES-256-GCM encrypted configuration files
- **Multiple Persistence**: systemd, cron, ld.so.preload, XDG autostart, and more
- **Auto-Update**: Daily configuration checks from GitHub with automatic updates
- **Anti-Debugging**: Protection against analysis and debugging

## Components

- `daemon` - Main monitoring daemon
- `kernel/` - Kernel module for process hiding
- `config-publisher` - Tool for publishing configuration updates

## Installation

```bash
make build
sudo make install
sudo make load-module
```

## Usage

```bash
# Start daemon
sudo systemctl start process-monitor

# View status
sudo systemctl status process-monitor

# Manual reload configuration
sudo kill -HUP $(pidof process-monitor-daemon)
```

## Configuration

Configuration files are encrypted and stored in `/etc/process-monitor/config.yaml.enc`

## License

MIT License - For educational and authorized security research purposes only.
