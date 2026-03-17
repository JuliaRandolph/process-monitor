package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jrandolph2/process-monitor/internal/config"
	"github.com/jrandolph2/process-monitor/internal/kernel"
	"github.com/jrandolph2/process-monitor/internal/monitor"
	"github.com/jrandolph2/process-monitor/internal/persistence"
	"github.com/jrandolph2/process-monitor/internal/security"
)

var (
	version   = "1.0.0"
	buildTime = "unknown"
)

type Options struct {
	ConfigPath    string
	LogFile       string
	Daemonize     bool
	PidFile       string
	NoKernel      bool
	Verbose       bool
	InstallMode   bool
	UninstallMode bool
}

func main() {
	opts := parseOptions()

	if opts.InstallMode {
		if err := runInstall(); err != nil {
			log.Fatalf("Installation failed: %v", err)
		}
		return
	}

	if opts.UninstallMode {
		if err := runUninstall(); err != nil {
			log.Fatalf("Uninstallation failed: %v", err)
		}
		return
	}

	// Setup logging
	if err := setupLogging(opts); err != nil {
		log.Fatalf("Failed to setup logging: %v", err)
	}

	log.Printf("Process Monitor Daemon v%s (built: %s)", version, buildTime)

	// Daemonize if requested
	if opts.Daemonize {
		if err := daemonize(opts.PidFile); err != nil {
			log.Fatalf("Failed to daemonize: %v", err)
		}
	}

	// Initialize and run daemon
	if err := runDaemon(opts); err != nil {
		log.Fatalf("Daemon error: %v", err)
	}
}

func parseOptions() Options {
	opts := Options{
		ConfigPath: "/etc/process-monitor/config.yaml.enc",
		LogFile:    "/var/log/process-monitor/daemon.log",
		PidFile:    "/var/run/process-monitor.pid",
	}

	flag.StringVar(&opts.ConfigPath, "config", opts.ConfigPath, "Path to configuration file")
	flag.StringVar(&opts.LogFile, "log", opts.LogFile, "Path to log file")
	flag.BoolVar(&opts.Daemonize, "daemon", false, "Run as daemon")
	flag.StringVar(&opts.PidFile, "pidfile", opts.PidFile, "Path to PID file")
	flag.BoolVar(&opts.NoKernel, "no-kernel", false, "Disable kernel module")
	flag.BoolVar(&opts.Verbose, "verbose", false, "Verbose logging")
	flag.BoolVar(&opts.InstallMode, "install", false, "Install the daemon")
	flag.BoolVar(&opts.UninstallMode, "uninstall", false, "Uninstall the daemon")

	flag.Parse()

	return opts
}

func setupLogging(opts Options) error {
	// Ensure log directory exists
	logDir := filepath.Dir(opts.LogFile)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open log file
	logFile, err := os.OpenFile(opts.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	// Redirect logs
	log.SetOutput(logFile)
	if opts.Verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}

	return nil
}

func daemonize(pidFile string) error {
	// Fork the process
	pid, err := syscall.ForkInt(os.Args[0], os.Args, os.Environ())
	if err != nil {
		return err
	}

	if pid > 0 {
		// Parent process exits
		os.Exit(0)
	}

	// Child process continues
	// Create new session
	_, err = syscall.Setsid()
	if err != nil {
		return err
	}

	// Write PID file
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
		return err
	}

	return nil
}

func runDaemon(opts Options) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Generate master key
	masterKey, err := config.GenerateMasterKey()
	if err != nil {
		return fmt.Errorf("failed to generate master key: %w", err)
	}

	// Load configuration
	cfgManager := config.NewConfigManager(opts.ConfigPath, masterKey)
	cfg, err := cfgManager.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	log.Printf("Configuration loaded (version %s)", cfg.Version)

	// Initialize kernel communicator
	var kernelComm kernel.KernelCommunicator
	if !opts.NoKernel && cfg.Monitor.KernelModule {
		kernelComm, err = kernel.NewAutoCommunicator()
		if err != nil {
			log.Printf("Warning: Failed to initialize kernel communication: %v", err)
			log.Println("Running without kernel module support")
		} else {
			log.Printf("Kernel module connected via %s", kernelComm.(*kernel.AutoCommunicator).GetMethod())
		}
	}

	// Initialize monitor
	m := monitor.NewMonitor(cfg, kernelComm)

	// Initialize security
	if cfg.Security.EnableAntiDebug {
		antiDebug := security.NewAntiDebugger(security.DefaultConfig())
		go antiDebug.Run(ctx)
		log.Println("Anti-debugging protection enabled")
	}

	// Initialize persistence
	p := persistence.NewManager(cfg, persistence.Config{
		ServiceName: "process-monitor",
		BinaryPath:  "/usr/local/bin/process-monitor-daemon",
		ConfigPath:  opts.ConfigPath,
	})

	// Setup persistence
	if err := p.Setup(); err != nil {
		log.Printf("Warning: Failed to setup persistence: %v", err)
	}

	// Start monitoring
	if err := m.Start(); err != nil {
		return fmt.Errorf("failed to start monitor: %w", err)
	}
	log.Println("Process monitoring started")

	// Initialize auto-updater
	if cfg.Update.EnableAutoUpdate {
		updater := persistence.NewConfigUpdater(cfg, cfgManager)
		go updater.Start(ctx)
		log.Println("Auto-update enabled")
	}

	// Setup signal handlers
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Main loop
	log.Println("Daemon running")
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Shutting down...")
			m.Stop()
			return nil

		case sig := <-sigChan:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				log.Printf("Received signal %v, shutting down...", sig)
				cancel()
				m.Stop()
				return nil

			case syscall.SIGHUP:
				log.Println("Received SIGHUP, reloading configuration...")
				newCfg, err := cfgManager.Reload()
				if err != nil {
					log.Printf("Failed to reload configuration: %v", err)
					continue
				}
				if err := m.ReloadConfig(newCfg); err != nil {
					log.Printf("Failed to apply new configuration: %v", err)
					continue
				}
				log.Println("Configuration reloaded successfully")
			}

		case <-ticker.C:
			// Periodic status logging
			stats := m.GetStats()
			log.Printf("Stats: Scans=%d Terminations=%d Restarts=%d Uptime=%s",
				stats.ScansPerformed,
				stats.BlacklistTerminations,
				stats.WhitelistRestarts,
				stats.Uptime.Round(time.Second))
		}
	}
}

func runInstall() error {
	fmt.Println("Installing Process Monitor Daemon...")

	// Install binary
	binaryPath := "/usr/local/bin/process-monitor-daemon"
	selfPath, err := os.Executable()
	if err != nil {
		return err
	}

	// Copy binary
	if err := copyFile(selfPath, binaryPath, 0755); err != nil {
		return fmt.Errorf("failed to install binary: %w", err)
	}
	fmt.Printf("Installed binary to %s\n", binaryPath)

	// Create config directory
	configDir := "/etc/process-monitor"
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Create log directory
	logDir := "/var/log/process-monitor"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Generate default config
	masterKey, _ := config.GenerateMasterKey()
	cfgManager := config.NewConfigManager(filepath.Join(configDir, "config.yaml.enc"), masterKey)
	defaultCfg := config.DefaultConfig()
	if err := cfgManager.Save(defaultCfg); err != nil {
		return fmt.Errorf("failed to save default config: %w", err)
	}
	fmt.Printf("Created default configuration at %s\n", cfgManager.configPath)

	// Setup persistence
	p := persistence.NewManager(defaultCfg, persistence.Config{
		ServiceName: "process-monitor",
		BinaryPath:  binaryPath,
		ConfigPath:  cfgManager.configPath,
	})

	if err := p.InstallAll(); err != nil {
		return fmt.Errorf("failed to setup persistence: %w", err)
	}
	fmt.Println("Persistence methods installed")

	fmt.Println("\nInstallation complete!")
	fmt.Printf("Start with: systemctl start process-monitor\n")
	fmt.Printf("Enable on boot: systemctl enable process-monitor\n")

	return nil
}

func runUninstall() error {
	fmt.Println("Uninstalling Process Monitor Daemon...")

	// Stop daemon
	if err := syscall.Exec("/bin/systemctl", []string{"systemctl", "stop", "process-monitor"}, os.Environ()); err != nil {
		// Ignore if systemctl fails
	}

	// Remove persistence
	configPath := "/etc/process-monitor/config.yaml.enc"
	masterKey, _ := config.GenerateMasterKey()
	cfgManager := config.NewConfigManager(configPath, masterKey)
	cfg, _ := cfgManager.Load()

	if cfg != nil {
		p := persistence.NewManager(cfg, persistence.Config{
			ServiceName: "process-monitor",
			BinaryPath:  "/usr/local/bin/process-monitor-daemon",
			ConfigPath:  configPath,
		})
		p.RemoveAll()
	}

	// Remove files
	binaryPath := "/usr/local/bin/process-monitor-daemon"
	os.Remove(binaryPath)
	os.RemoveAll("/etc/process-monitor")
	os.Remove("/var/run/process-monitor.pid")

	fmt.Println("Uninstallation complete!")
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, mode)
}
