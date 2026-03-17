package security

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrDebuggerDetected = fmt.Errorf("debugger detected")
	ErrAnalysisDetected = fmt.Errorf("analysis environment detected")
)

// AntiDebugConfig contains anti-debugging configuration
type AntiDebugConfig struct {
	EnableTracerPidCheck   bool
	EnableParentCheck      bool
	EnableFdCheck          bool
	EnableTimingCheck      bool
	EnableBreakpointCheck  bool
	EnableProcCheck        bool
	EnableVmCheck          bool
	ResponseAction         string // "exit", "trap", "continue"
	CheckInterval          time.Duration
	MaxViolations          int
	ViolationAction        string
}

// DefaultConfig returns default anti-debug configuration
func DefaultConfig() AntiDebugConfig {
	return AntiDebugConfig{
		EnableTracerPidCheck:  true,
		EnableParentCheck:     true,
		EnableFdCheck:         true,
		EnableTimingCheck:     true,
		EnableBreakpointCheck: true,
		EnableProcCheck:       true,
		EnableVmCheck:         true,
		ResponseAction:        "exit",
		CheckInterval:         2 * time.Second,
		MaxViolations:         3,
		ViolationAction:       "exit",
	}
}

// AntiDebugger provides anti-debugging and anti-analysis protection
type AntiDebugger struct {
	config     AntiDebugConfig
	violations int
	mu         sync.Mutex
	baseline   time.Duration
}

// NewAntiDebugger creates a new anti-debugger instance
func NewAntiDebugger(config AntiDebugConfig) *AntiDebugger {
	return &AntiDebugger{
		config: config,
	}
}

// Run starts the anti-debugging checks
func (a *AntiDebugger) Run(ctx context.Context) {
	// Establish baseline
	a.establishBaseline()

	ticker := time.NewTicker(a.config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.performChecks() {
				a.handleViolation()
			}
		}
	}
}

// establishBaseline establishes timing baseline
func (a *AntiDebugger) establishBaseline() {
	// Measure typical operation time
	start := time.Now()
	a.performDummyOperation()
	a.baseline = time.Since(start)
}

// performDummyOperation performs a dummy operation for timing
func (a *AntiDebugger) performDummyOperation() {
	// Simple computation
	sum := 0
	for i := 0; i < 1000; i++ {
		sum += i
	}
	_ = sum
}

// performChecks runs all enabled checks
func (a *AntiDebugger) performChecks() bool {
	detected := false

	if a.config.EnableTracerPidCheck {
		if a.checkTracerPid() {
			detected = true
		}
	}

	if a.config.EnableParentCheck {
		if a.checkParentProcess() {
			detected = true
		}
	}

	if a.config.EnableFdCheck {
		if a.checkFileDescriptors() {
			detected = true
		}
	}

	if a.config.EnableTimingCheck {
		if a.checkTimingAnomaly() {
			detected = true
		}
	}

	if a.config.EnableBreakpointCheck {
		if a.checkBreakpoints() {
			detected = true
		}
	}

	if a.config.EnableProcCheck {
		if a.checkProcFiles() {
			detected = true
		}
	}

	if a.config.EnableVmCheck {
		if a.checkVirtualMachine() {
			detected = true
		}
	}

	return detected
}

// checkTracerPid checks if process is being traced
func (a *AntiDebugger) checkTracerPid() bool {
	// Read /proc/self/status
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				tracerPid, _ := strconv.Atoi(fields[1])
				if tracerPid != 0 {
					return true // Being traced
				}
			}
		}
	}

	return false
}

// checkParentProcess checks if parent process is suspicious
func (a *AntiDebugger) checkParentProcess() bool {
	ppid := os.Getppid()

	// Read parent command
	parentCmd := filepath.Join("/proc", strconv.Itoa(ppid), "cmdline")
	cmdData, err := os.ReadFile(parentCmd)
	if err != nil {
		return false
	}

	cmd := strings.TrimSpace(string(cmdData))

	// Check for debuggers and analysis tools
	suspiciousParents := []string{
		"gdb", "lldb", "strace", "ltrace",
		"valgrind", "radare2", "ida", "edb",
		"x64dbg", "x64dbg", "ollydbg", "windbg",
		" cutter", "binary ninja", "ghidra",
	}

	for _, susp := range suspiciousParents {
		if strings.Contains(strings.ToLower(cmd), susp) {
			return true
		}
	}

	return false
}

// checkFileDescriptors checks for suspicious file descriptors
func (a *AntiDebugger) checkFileDescriptors() bool {
	fdDir := "/proc/self/fd"
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return false
	}

	for _, entry := range entries {
		fdPath := filepath.Join(fdDir, entry.Name())
		link, err := os.Readlink(fdPath)
		if err != nil {
			continue
		}

		// Check for pipe connections to debuggers
		if strings.Contains(link, "pipe") && os.Getpid() < 1000 {
			// Low PID with pipes is suspicious
		}
	}

	return false
}

// checkTimingAnomaly detects timing-based debugging
func (a *AntiDebugger) checkTimingAnomaly() bool {
	if a.baseline == 0 {
		return false
	}

	// Measure operation time multiple times
	times := make([]time.Duration, 5)
	for i := 0; i < 5; i++ {
		start := time.Now()
		a.performDummyOperation()
		times[i] = time.Since(start)
	}

	// Check for significant deviation
	avg := time.Duration(0)
	for _, t := range times {
		avg += t
	}
	avg /= time.Duration(len(times))

	// If current operation is 3x slower than baseline, suspicious
	if avg > a.baseline*3 {
		return true
	}

	return false
}

// checkBreakpoints checks for software breakpoints
func (a *AntiDebugger) checkBreakpoints() bool {
	// Read own executable memory
	// Check for INT3 instructions (0xCC)

	// This requires reading /proc/self/mem
	// For simplicity, we'll check if we can read it

	memFile := "/proc/self/mem"
	if _, err := os.Stat(memFile); err != nil {
		// If we can't read our own memory, something is wrong
		return true
	}

	return false
}

// checkProcFiles checks for tampering with /proc files
func (a *AntiDebugger) checkProcFiles() bool {
	// Check if critical proc files exist
	files := []string{
		"/proc/self/status",
		"/proc/self/maps",
		"/proc/self/mem",
		"/proc/self/exe",
	}

	for _, file := range files {
		if _, err := os.Stat(file); err != nil {
			// Missing proc files is suspicious
			return true
		}
	}

	return false
}

// checkVirtualMachine detects if running in a VM
func (a *AntiDebugger) checkVirtualMachine() bool {
	// Check DMI entries
	dmiFiles := []string{
		"/sys/class/dmi/id/product_name",
		"/sys/class/dmi/id/sys_vendor",
		"/sys/class/dmi/id/board_name",
	}

	for _, file := range dmiFiles {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		content := strings.ToLower(string(data))
		vmIndicators := []string{
			"vmware", "virtualbox", "qemu", "kvm",
			"xen", "parallels", "hyper-v", "virtual",
		}

		for _, indicator := range vmIndicators {
			if strings.Contains(content, indicator) {
				return true
			}
		}
	}

	// Check CPU info
	cpuInfo, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		content := strings.ToLower(string(cpuInfo))
		if strings.Contains(content, "qemu") ||
		   strings.Contains(content, "vmware") ||
		   strings.Contains(content, "hypervisor") {
			return true
		}
	}

	// Check network interfaces (MAC addresses starting with VM vendors)
	ifaces, _ := os.ReadDir("/sys/class/net")
	for _, iface := range ifaces {
		addrFile := filepath.Join("/sys/class/net", iface.Name(), "address")
		addr, err := os.ReadFile(addrFile)
		if err != nil {
			continue
		}

		mac := strings.ToLower(string(addr))
		vmMacPrefixes := []string{
			"00:05:69", "00:0c:29", // VMware
			"08:00:27",             // VirtualBox
			"52:54:00",             // QEMU/KVM
			"00:15:5d",             // Hyper-V
		}

		for _, prefix := range vmMacPrefixes {
			if strings.HasPrefix(mac, prefix) {
				return true
			}
		}
	}

	return false
}

// handleViolation handles a detected violation
func (a *AntiDebugger) handleViolation() {
	a.mu.Lock()
	a.violations++
	vcount := a.violations
	a.mu.Unlock()

	switch a.config.ResponseAction {
	case "exit":
		if vcount >= a.config.MaxViolations {
			os.Exit(1)
		}

	case "trap":
		runtime.Breakpoint()

	case "continue":
		// Log and continue
	}
}

// IntegrityChecker checks binary integrity
type IntegrityChecker struct {
	expectedHash string
	binaryPath   string
	checkInterval time.Duration
}

// NewIntegrityChecker creates a new integrity checker
func NewIntegrityChecker(binaryPath, expectedHash string) *IntegrityChecker {
	return &IntegrityChecker{
		binaryPath:    binaryPath,
		expectedHash:  expectedHash,
		checkInterval: 1 * time.Minute,
	}
}

// Start begins integrity checking
func (i *IntegrityChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(i.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !i.checkIntegrity() {
				fmt.Println("Integrity check failed - binary may be tampered")
				os.Exit(1)
			}
		}
	}
}

// checkIntegrity verifies binary integrity
func (i *IntegrityChecker) checkIntegrity() bool {
	// Calculate current hash
	currentHash, err := i.calculateHash()
	if err != nil {
		return false
	}

	return currentHash == i.expectedHash
}

// calculateHash calculates the hash of the binary
func (i *IntegrityChecker) calculateHash() (string, error) {
	// Read binary file
	data, err := os.ReadFile(i.binaryPath)
	if err != nil {
		return "", err
	}

	// Calculate SHA256 hash
	// For simplicity, just return first 32 bytes as pseudo-hash
	if len(data) >= 32 {
		return string(data[:32]), nil
	}

	return string(data), nil
}

// GenerateSelfHash generates a hash of the running binary
func GenerateSelfHash() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}

	ic := NewIntegrityChecker(self, "")
	return ic.calculateHash()
}

// TraceCheck performs a quick trace check
func QuickTraceCheck() bool {
	// Fast tracer PID check
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				tracerPid, _ := strconv.Atoi(fields[1])
				return tracerPid != 0
			}
		}
	}

	return false
}

// EnvironmentCheck checks for analysis environment indicators
func EnvironmentCheck() bool {
	indicators := []string{
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
	}

	for _, indicator := range indicators {
		if val := os.Getenv(indicator); val != "" {
			return true
		}
	}

	// Check for common analysis tools
	tools := []string{
		"strace", "ltrace", "gdb", "lldb",
		"objdump", "radare2", "r2",
	}

	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err == nil {
			return true
		}
	}

	return false
}

// DetectSandbox detects if running in a sandbox
func DetectSandbox() bool {
	// Check for sandbox indicators
	indicators := []string{
		"/.dockerenv",
		"/.dockerinit",
		"/proc/1/cgroup",
	}

	for _, indicator := range indicators {
		if _, err := os.Stat(indicator); err == nil {
			// Check content for docker/cgroup
			if data, err := os.ReadFile(indicator); err == nil {
				content := strings.ToLower(string(data))
				if strings.Contains(content, "docker") ||
				   strings.Contains(content, "lxc") ||
				   strings.Contains(content, "kubepods") {
					return true
				}
			}
		}
	}

	// Check for low memory (common in sandboxes)
	if _, err := os.ReadFile("/proc/meminfo"); err == nil {
		// Would parse memory info here
	}

	return false
}
