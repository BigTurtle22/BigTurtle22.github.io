package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

// Configuration structure for the SSH filter
type Config struct {
	Server struct {
		ListenAddr    string `yaml:"listen_addr"`
		SSHPort       int    `yaml:"ssh_port"`
		MaxConns      int    `yaml:"max_connections"`
		ReadTimeout   int    `yaml:"read_timeout"`
		WriteTimeout  int    `yaml:"write_timeout"`
		BufferSize    int    `yaml:"buffer_size"`
	} `yaml:"server"`

	Security struct {
		MaxFailures       int      `yaml:"max_failures"`
		BanDuration       int      `yaml:"ban_duration"`
		RateLimit         int      `yaml:"rate_limit"`
		AllowedCountries  []string `yaml:"allowed_countries"`
		BlockedCountries  []string `yaml:"blocked_countries"`
		BlockTor          bool     `yaml:"block_tor"`
		BlockVPN          bool     `yaml:"block_vpn"`
		MinKeySize        int      `yaml:"min_key_size"`
		AllowedAlgorithms []string `yaml:"allowed_algorithms"`
		HoneypotEnabled   bool     `yaml:"honeypot_enabled"`
		TarpitDelay       int      `yaml:"tarpit_delay"`
	} `yaml:"security"`

	ML struct {
		Enabled           bool    `yaml:"enabled"`
		ModelPath         string  `yaml:"model_path"`
		TrainingData      string  `yaml:"training_data"`
		AnomalyThreshold  float64 `yaml:"anomaly_threshold"`
		UpdateInterval    int     `yaml:"update_interval"`
		FeatureWindow     int     `yaml:"feature_window"`
	} `yaml:"ml"`

	Logging struct {
		Level       string `yaml:"level"`
		File        string `yaml:"file"`
		MaxSize     int    `yaml:"max_size"`
		Syslog      bool   `yaml:"syslog"`
		SIEMEndpoint string `yaml:"siem_endpoint"`
	} `yaml:"logging"`

	Database struct {
		Path           string `yaml:"path"`
		MaxConnections int    `yaml:"max_connections"`
		BackupInterval int    `yaml:"backup_interval"`
	} `yaml:"database"`

	Intelligence struct {
		UpdateInterval    int    `yaml:"update_interval"`
		MaxMindKey        string `yaml:"maxmind_key"`
		ThreatFeeds       []string `yaml:"threat_feeds"`
		TorNodeListURL    string `yaml:"tor_node_list_url"`
		VPNRangesURL      string `yaml:"vpn_ranges_url"`
	} `yaml:"intelligence"`
}

// SSH Protocol Constants
const (
	SSH_MSG_DISCONNECT        = 1
	SSH_MSG_IGNORE           = 2
	SSH_MSG_UNIMPLEMENTED    = 3
	SSH_MSG_DEBUG            = 4
	SSH_MSG_SERVICE_REQUEST  = 5
	SSH_MSG_SERVICE_ACCEPT   = 6
	SSH_MSG_KEXINIT          = 20
	SSH_MSG_NEWKEYS          = 21
	SSH_MSG_KEXDH_INIT       = 30
	SSH_MSG_KEXDH_REPLY      = 31
	SSH_MSG_USERAUTH_REQUEST = 50
	SSH_MSG_USERAUTH_FAILURE = 51
	SSH_MSG_USERAUTH_SUCCESS = 52
)

// Threat Intelligence Data Structures
type ThreatIntel struct {
	mu           sync.RWMutex
	torNodes     map[string]bool
	vpnRanges    []*net.IPNet
	maliciousIPs map[string]ThreatInfo
	geoIPDB      map[string]string
	lastUpdate   time.Time
}

type ThreatInfo struct {
	Reputation int       `json:"reputation"`
	Category   string    `json:"category"`
	LastSeen   time.Time `json:"last_seen"`
	Source     string    `json:"source"`
}

// Machine Learning Feature Vector
type FeatureVector struct {
	PacketSizes      []float64 `json:"packet_sizes"`
	InterArrivalTime []float64 `json:"inter_arrival_time"`
	PayloadEntropy   float64   `json:"payload_entropy"`
	ConnectionTime   float64   `json:"connection_time"`
	KeyExchangeTime  float64   `json:"key_exchange_time"`
	AuthAttempts     float64   `json:"auth_attempts"`
	ProtocolVersion  float64   `json:"protocol_version"`
	CipherSuite      float64   `json:"cipher_suite"`
	CompressionRatio float64   `json:"compression_ratio"`
	BehaviorPattern  float64   `json:"behavior_pattern"`
}

// Behavioral Profile for tracking connection patterns
type BehaviorProfile struct {
	IP                string    `json:"ip"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	ConnectionCount   int64     `json:"connection_count"`
	FailedAttempts    int64     `json:"failed_attempts"`
	AverageSessionTime float64  `json:"average_session_time"`
	TypicalUserAgents []string  `json:"typical_user_agents"`
	GeoLocations      []string  `json:"geo_locations"`
	ThreatScore       float64   `json:"threat_score"`
	AnomalyScore      float64   `json:"anomaly_score"`
	Features          []FeatureVector `json:"features"`
}

// SSH Connection Context
type SSHConnection struct {
	conn            net.Conn
	remoteAddr      string
	startTime       time.Time
	bytesRead       int64
	bytesWritten    int64
	protocolVersion string
	clientSoftware  string
	serverSoftware  string
	keyExchange     SSHKeyExchange
	authenticated   bool
	username        string
	authMethods     []string
	compressionAlgs []string
	encryptionAlgs  []string
	macAlgorithms   []string
	packets         []SSHPacket
	behaviorProfile *BehaviorProfile
	threatScore     float64
	blocked         bool
	honeypot        bool
}

type SSHKeyExchange struct {
	ClientKexAlgs    []string `json:"client_kex_algs"`
	ServerKexAlgs    []string `json:"server_kex_algs"`
	ClientHostKeyAlgs []string `json:"client_host_key_algs"`
	ServerHostKeyAlgs []string `json:"server_host_key_algs"`
	EncryptionAlgsCS  []string `json:"encryption_algs_cs"`
	EncryptionAlgsSC  []string `json:"encryption_algs_sc"`
	MacAlgsCS         []string `json:"mac_algs_cs"`
	MacAlgsSC         []string `json:"mac_algs_sc"`
	CompressionAlgsCS []string `json:"compression_algs_cs"`
	CompressionAlgsSC []string `json:"compression_algs_sc"`
	FirstKexFollows   bool     `json:"first_kex_follows"`
	Reserved          uint32   `json:"reserved"`
}

type SSHPacket struct {
	Type      uint8     `json:"type"`
	Length    uint32    `json:"length"`
	Payload   []byte    `json:"payload"`
	Timestamp time.Time `json:"timestamp"`
}

// Advanced ML Model for Anomaly Detection
type MLModel struct {
	mu               sync.RWMutex
	weights          [][]float64
	biases           []float64
	featureScalers   []FeatureScaler
	trainingData     []TrainingExample
	lastTrained      time.Time
	accuracy         float64
	falsePositiveRate float64
	truePositiveRate float64
}

type FeatureScaler struct {
	Min  float64 `json:"min"`
	Max  float64 `json:"max"`
	Mean float64 `json:"mean"`
	Std  float64 `json:"std"`
}

type TrainingExample struct {
	Features FeatureVector `json:"features"`
	Label    float64       `json:"label"`
}

// Security Filter Main Structure
type SSHSecurityFilter struct {
	config          *Config
	db              *sql.DB
	threatIntel     *ThreatIntel
	mlModel         *MLModel
	behaviorDB      map[string]*BehaviorProfile
	connectionPool  sync.Pool
	stats           SecurityStats
	logger          *SecurityLogger
	honeypot        *HoneypotSystem
	rateLimiter     *RateLimiter
	cryptoValidator *CryptoValidator
	packetCapture   *PacketCapture
	alertSystem     *AlertSystem
	running         int32
	shutdown        chan struct{}
	wg              sync.WaitGroup
	mu              sync.RWMutex
}

type SecurityStats struct {
	TotalConnections     int64 `json:"total_connections"`
	BlockedConnections   int64 `json:"blocked_connections"`
	HoneypotConnections  int64 `json:"honeypot_connections"`
	ThreatDetections     int64 `json:"threat_detections"`
	AnomalyDetections    int64 `json:"anomaly_detections"`
	GeoBlocks           int64 `json:"geo_blocks"`
	TorBlocks           int64 `json:"tor_blocks"`
	VPNBlocks           int64 `json:"vpn_blocks"`
	CryptoViolations    int64 `json:"crypto_violations"`
	RateLimitViolations int64 `json:"rate_limit_violations"`
	StartTime           time.Time `json:"start_time"`
}

// Advanced Logging System
type SecurityLogger struct {
	mu       sync.Mutex
	file     *os.File
	syslog   bool
	siemURL  string
	buffer   chan LogEntry
	shutdown chan struct{}
}

type LogEntry struct {
	Timestamp   time.Time   `json:"timestamp"`
	Level       string      `json:"level"`
	Source      string      `json:"source"`
	Message     string      `json:"message"`
	RemoteAddr  string      `json:"remote_addr"`
	ThreatScore float64     `json:"threat_score"`
	Action      string      `json:"action"`
	Details     interface{} `json:"details"`
}

// Advanced Honeypot System
type HoneypotSystem struct {
	mu            sync.RWMutex
	interactions  map[string][]HoneypotInteraction
	commands      []string
	responses     map[string]string
	attackerProfiles map[string]*AttackerProfile
	tarpit        *TarpitManager
}

type HoneypotInteraction struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
	Response  string    `json:"response"`
	Duration  time.Duration `json:"duration"`
}

type AttackerProfile struct {
	IP            string    `json:"ip"`
	FirstContact  time.Time `json:"first_contact"`
	LastContact   time.Time `json:"last_contact"`
	Interactions  int       `json:"interactions"`
	Commands      []string  `json:"commands"`
	ThreatLevel   int       `json:"threat_level"`
	Fingerprint   string    `json:"fingerprint"`
}

type TarpitManager struct {
	connections map[string]*TarpitConnection
	mu          sync.RWMutex
}

type TarpitConnection struct {
	conn       net.Conn
	startTime  time.Time
	delay      time.Duration
	active     bool
}

// Rate Limiting System
type RateLimiter struct {
	mu      sync.RWMutex
	buckets map[string]*TokenBucket
	cleanup chan struct{}
}

type TokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64
	lastRefill time.Time
}

// Cryptographic Validation System
type CryptoValidator struct {
	allowedKexAlgs    map[string]bool
	allowedCiphers    map[string]bool
	allowedMACs       map[string]bool
	minKeySize        int
	bannedAlgorithms  map[string]string
}

// Packet Capture System
type PacketCapture struct {
	handle    interface{}
	filter    string
	packets   chan RawPacket
	shutdown  chan struct{}
}

type RawPacket struct {
	Data      []byte
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
}

// Alert System
type AlertSystem struct {
	alerts    chan Alert
	webhooks  []string
	emailSMTP string
	shutdown  chan struct{}
}

type Alert struct {
	ID          string      `json:"id"`
	Timestamp   time.Time   `json:"timestamp"`
	Severity    string      `json:"severity"`
	Type        string      `json:"type"`
	Source      string      `json:"source"`
	Description string      `json:"description"`
	Details     interface{} `json:"details"`
}

// Default configuration
func getDefaultConfig() *Config {
	return &Config{
		Server: struct {
			ListenAddr   string `yaml:"listen_addr"`
			SSHPort      int    `yaml:"ssh_port"`
			MaxConns     int    `yaml:"max_connections"`
			ReadTimeout  int    `yaml:"read_timeout"`
			WriteTimeout int    `yaml:"write_timeout"`
			BufferSize   int    `yaml:"buffer_size"`
		}{
			ListenAddr:   "0.0.0.0:2222",
			SSHPort:      22,
			MaxConns:     1000,
			ReadTimeout:  30,
			WriteTimeout: 30,
			BufferSize:   4096,
		},
		Security: struct {
			MaxFailures       int      `yaml:"max_failures"`
			BanDuration       int      `yaml:"ban_duration"`
			RateLimit         int      `yaml:"rate_limit"`
			AllowedCountries  []string `yaml:"allowed_countries"`
			BlockedCountries  []string `yaml:"blocked_countries"`
			BlockTor          bool     `yaml:"block_tor"`
			BlockVPN          bool     `yaml:"block_vpn"`
			MinKeySize        int      `yaml:"min_key_size"`
			AllowedAlgorithms []string `yaml:"allowed_algorithms"`
			HoneypotEnabled   bool     `yaml:"honeypot_enabled"`
			TarpitDelay       int      `yaml:"tarpit_delay"`
		}{
			MaxFailures:      3,
			BanDuration:      3600,
			RateLimit:        10,
			AllowedCountries: []string{"US", "CA", "GB", "DE", "FR"},
			BlockedCountries: []string{"CN", "RU", "KP", "IR"},
			BlockTor:         true,
			BlockVPN:         true,
			MinKeySize:       2048,
			AllowedAlgorithms: []string{
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group16-sha512",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
			},
			HoneypotEnabled: true,
			TarpitDelay:     5,
		},
		ML: struct {
			Enabled          bool    `yaml:"enabled"`
			ModelPath        string  `yaml:"model_path"`
			TrainingData     string  `yaml:"training_data"`
			AnomalyThreshold float64 `yaml:"anomaly_threshold"`
			UpdateInterval   int     `yaml:"update_interval"`
			FeatureWindow    int     `yaml:"feature_window"`
		}{
			Enabled:          true,
			ModelPath:        "./models/ssh_anomaly.json",
			TrainingData:     "./data/training.json",
			AnomalyThreshold: 0.7,
			UpdateInterval:   3600,
			FeatureWindow:    100,
		},
		Logging: struct {
			Level        string `yaml:"level"`
			File         string `yaml:"file"`
			MaxSize      int    `yaml:"max_size"`
			Syslog       bool   `yaml:"syslog"`
			SIEMEndpoint string `yaml:"siem_endpoint"`
		}{
			Level:        "INFO",
			File:         "./logs/ssh_filter.log",
			MaxSize:      100,
			Syslog:       true,
			SIEMEndpoint: "",
		},
		Database: struct {
			Path           string `yaml:"path"`
			MaxConnections int    `yaml:"max_connections"`
			BackupInterval int    `yaml:"backup_interval"`
		}{
			Path:           "./data/ssh_filter.db",
			MaxConnections: 10,
			BackupInterval: 3600,
		},
		Intelligence: struct {
			UpdateInterval int      `yaml:"update_interval"`
			MaxMindKey     string   `yaml:"maxmind_key"`
			ThreatFeeds    []string `yaml:"threat_feeds"`
			TorNodeListURL string   `yaml:"tor_node_list_url"`
			VPNRangesURL   string   `yaml:"vpn_ranges_url"`
		}{
			UpdateInterval: 3600,
			MaxMindKey:     "",
			ThreatFeeds: []string{
				"https://reputation.alienvault.com/reputation.data",
				"https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist",
			},
			TorNodeListURL: "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1",
			VPNRangesURL:   "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/ipv4.txt",
		},
	}
}

// Initialize the SSH Security Filter
func NewSSHSecurityFilter(configPath string) (*SSHSecurityFilter, error) {
	var config *Config
	
	if configPath != "" {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read config file: %v", err)
		}
		
		config = &Config{}
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, fmt.Errorf("failed to parse config: %v", err)
		}
	} else {
		config = getDefaultConfig()
	}

	// Initialize database
	if err := os.MkdirAll(filepath.Dir(config.Database.Path), 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %v", err)
	}

	db, err := sql.Open("sqlite3", config.Database.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Initialize all components
	filter := &SSHSecurityFilter{
		config:         config,
		db:             db,
		threatIntel:    NewThreatIntel(),
		mlModel:        NewMLModel(),
		behaviorDB:     make(map[string]*BehaviorProfile),
		stats:          SecurityStats{StartTime: time.Now()},
		shutdown:       make(chan struct{}),
	}

	// Initialize logging system
	if filter.logger, err = NewSecurityLogger(config); err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %v", err)
	}

	// Initialize honeypot system
	if filter.honeypot, err = NewHoneypotSystem(config); err != nil {
		return nil, fmt.Errorf("failed to initialize honeypot: %v", err)
	}

	// Initialize rate limiter
	filter.rateLimiter = NewRateLimiter(config.Security.RateLimit)

	// Initialize crypto validator
	filter.cryptoValidator = NewCryptoValidator(config)

	// Initialize alert system
	if filter.alertSystem, err = NewAlertSystem(config); err != nil {
		return nil, fmt.Errorf("failed to initialize alert system: %v", err)
	}

	// Initialize database schema
	if err := filter.initDatabase(); err != nil {
		return nil, fmt.Errorf("failed to initialize database: %v", err)
	}

	// Start background services
	filter.startBackgroundServices()

	return filter, nil
}

// Initialize Threat Intelligence
func NewThreatIntel() *ThreatIntel {
	return &ThreatIntel{
		torNodes:     make(map[string]bool),
		vpnRanges:    make([]*net.IPNet, 0),
		maliciousIPs: make(map[string]ThreatInfo),
		geoIPDB:      make(map[string]string),
	}
}

// Initialize ML Model
func NewMLModel() *MLModel {
	return &MLModel{
		weights:        make([][]float64, 0),
		biases:         make([]float64, 0),
		featureScalers: make([]FeatureScaler, 10), // 10 features
		trainingData:   make([]TrainingExample, 0),
	}
}

// Initialize Security Logger
func NewSecurityLogger(config *Config) (*SecurityLogger, error) {
	logger := &SecurityLogger{
		buffer:   make(chan LogEntry, 1000),
		shutdown: make(chan struct{}),
		siemURL:  config.Logging.SIEMEndpoint,
		syslog:   config.Logging.Syslog,
	}

	if config.Logging.File != "" {
		if err := os.MkdirAll(filepath.Dir(config.Logging.File), 0755); err != nil {
			return nil, err
		}

		file, err := os.OpenFile(config.Logging.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
		logger.file = file
	}

	go logger.processLogs()
	return logger, nil
}

// Initialize Honeypot System
func NewHoneypotSystem(config *Config) (*HoneypotSystem, error) {
	honeypot := &HoneypotSystem{
		interactions:     make(map[string][]HoneypotInteraction),
		attackerProfiles: make(map[string]*AttackerProfile),
		tarpit:          &TarpitManager{connections: make(map[string]*TarpitConnection)},
		commands: []string{
			"ls", "pwd", "whoami", "id", "uname -a", "cat /etc/passwd",
			"ps aux", "netstat -an", "ifconfig", "route -n", "iptables -L",
		},
		responses: map[string]string{
			"ls":             "bin\nboot\ndev\netc\nhome\nlib\nopt\nroot\ntmp\nusr\nvar",
			"pwd":            "/home/admin",
			"whoami":         "admin",
			"id":             "uid=1000(admin) gid=1000(admin) groups=1000(admin)",
			"uname -a":       "Linux honeypot 5.4.0-74-generic #83-Ubuntu SMP",
			"cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash",
		},
	}

	return honeypot, nil
}

// Initialize Rate Limiter
func NewRateLimiter(rate int) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*TokenBucket),
		cleanup: make(chan struct{}),
	}

	go rl.cleanupBuckets()
	return rl
}

// Initialize Crypto Validator
func NewCryptoValidator(config *Config) *CryptoValidator {
	validator := &CryptoValidator{
		allowedKexAlgs: make(map[string]bool),
		allowedCiphers: make(map[string]bool),
		allowedMACs:    make(map[string]bool),
		minKeySize:     config.Security.MinKeySize,
		bannedAlgorithms: map[string]string{
			"diffie-hellman-group1-sha1":  "Weak key exchange",
			"diffie-hellman-group14-sha1": "Weak hash",
			"ssh-rsa":                     "Deprecated",
			"ssh-dss":                     "Weak signature",
			"arcfour":                     "Weak cipher",
			"arcfour128":                  "Weak cipher",
			"arcfour256":                  "Weak cipher",
			"des":                         "Weak cipher",
			"3des":                        "Weak cipher",
		},
	}

	// Populate allowed algorithms
	for _, alg := range config.Security.AllowedAlgorithms {
		validator.allowedKexAlgs[alg] = true
	}

	// Strong ciphers
	strongCiphers := []string{
		"aes128-ctr", "aes192-ctr", "aes256-ctr",
		"aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
		"chacha20-poly1305@openssh.com",
	}
	for _, cipher := range strongCiphers {
		validator.allowedCiphers[cipher] = true
	}

	// Strong MACs
	strongMACs := []string{
		"hmac-sha2-256", "hmac-sha2-512",
		"hmac-sha2-256-etm@openssh.com",
		"hmac-sha2-512-etm@openssh.com",
	}
	for _, mac := range strongMACs {
		validator.allowedMACs[mac] = true
	}

	return validator
}

// Initialize Alert System
func NewAlertSystem(config *Config) (*AlertSystem, error) {
	alertSystem := &AlertSystem{
		alerts:   make(chan Alert, 1000),
		webhooks: make([]string, 0),
		shutdown: make(chan struct{}),
	}

	go alertSystem.processAlerts()
	return alertSystem, nil
}

// Initialize database schema
func (f *SSHSecurityFilter) initDatabase() error {
	schema := `
	CREATE TABLE IF NOT EXISTS connections (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		remote_addr TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		protocol_version TEXT,
		client_software TEXT,
		threat_score REAL,
		blocked BOOLEAN,
		honeypot BOOLEAN,
		duration INTEGER,
		bytes_read INTEGER,
		bytes_written INTEGER
	);

	CREATE TABLE IF NOT EXISTS threat_intel (
		ip TEXT PRIMARY KEY,
		reputation INTEGER,
		category TEXT,
		last_seen DATETIME,
		source TEXT
	);

	CREATE TABLE IF NOT EXISTS behavior_profiles (
		ip TEXT PRIMARY KEY,
		first_seen DATETIME,
		last_seen DATETIME,
		connection_count INTEGER,
		failed_attempts INTEGER,
		threat_score REAL,
		profile_data TEXT
	);

	CREATE TABLE IF NOT EXISTS ml_training (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		features TEXT,
		label REAL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS security_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		event_type TEXT,
		source_ip TEXT,
		severity TEXT,
		description TEXT,
		details TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_connections_addr ON connections(remote_addr);
	CREATE INDEX IF NOT EXISTS idx_connections_timestamp ON connections(timestamp);
	CREATE INDEX IF NOT EXISTS idx_threat_intel_reputation ON threat_intel(reputation);
	CREATE INDEX IF NOT EXISTS idx_behavior_ip ON behavior_profiles(ip);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
	`

	_, err := f.db.Exec(schema)
	return err
}

// Start background services
func (f *SSHSecurityFilter) startBackgroundServices() {
	// Threat intelligence updater
	go f.updateThreatIntelligence()

	// ML model trainer
	go f.trainMLModel()

	// Database cleanup
	go f.databaseCleanup()

	// Statistics collector
	go f.collectStatistics()

	// Packet capture if enabled
	if f.config.Server.BufferSize > 0 {
		go f.startPacketCapture()
	}
}

// Main connection handler
func (f *SSHSecurityFilter) handleConnection(conn net.Conn) {
	defer conn.Close()
	atomic.AddInt64(&f.stats.TotalConnections, 1)

	remoteAddr := conn.RemoteAddr().String()
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		f.logger.Log("ERROR", "Invalid remote address", remoteAddr, 0, "REJECT", err)
		return
	}

	sshConn := &SSHConnection{
		conn:       conn,
		remoteAddr: remoteAddr,
		startTime:  time.Now(),
		packets:    make([]SSHPacket, 0),
	}

	// Apply rate limiting
	if !f.rateLimiter.Allow(ip) {
		atomic.AddInt64(&f.stats.RateLimitViolations, 1)
		f.logger.Log("WARN", "Rate limit exceeded", remoteAddr, 0, "REJECT", nil)
		f.sendAlert("RATE_LIMIT", "HIGH", remoteAddr, "Rate limit exceeded")
		return
	}

	// Check threat intelligence
	if f.checkThreatIntelligence(ip, sshConn) {
		atomic.AddInt64(&f.stats.ThreatDetections, 1)
		return
	}

	// Geographic filtering
	if f.checkGeographicRestrictions(ip, sshConn) {
		atomic.AddInt64(&f.stats.GeoBlocks, 1)
		return
	}

	// Deep packet inspection and protocol analysis
	if f.analyzeSSHProtocol(sshConn) {
		// Connection passed initial checks
		f.handleSSHSession(sshConn)
	}

	f.updateBehaviorProfile(sshConn)
	f.recordConnection(sshConn)
}

// Check threat intelligence against IP
func (f *SSHSecurityFilter) checkThreatIntelligence(ip string, sshConn *SSHConnection) bool {
	f.threatIntel.mu.RLock()
	defer f.threatIntel.mu.RUnlock()

	// Check if IP is a known Tor exit node
	if f.config.Security.BlockTor && f.threatIntel.torNodes[ip] {
		atomic.AddInt64(&f.stats.TorBlocks, 1)
		f.logger.Log("WARN", "Tor exit node detected", ip, 1.0, "BLOCK", nil)
		f.sendAlert("TOR_NODE", "HIGH", ip, "Connection from Tor exit node blocked")
		sshConn.blocked = true
		return true
	}

	// Check VPN ranges
	if f.config.Security.BlockVPN {
		clientIP := net.ParseIP(ip)
		for _, vpnRange := range f.threatIntel.vpnRanges {
			if vpnRange.Contains(clientIP) {
				atomic.AddInt64(&f.stats.VPNBlocks, 1)
				f.logger.Log("WARN", "VPN IP detected", ip, 0.8, "BLOCK", nil)
				f.sendAlert("VPN_IP", "MEDIUM", ip, "Connection from VPN IP blocked")
				sshConn.blocked = true
				return true
			}
		}
	}

	// Check malicious IP database
	if threatInfo, exists := f.threatIntel.maliciousIPs[ip]; exists {
		threatScore := float64(threatInfo.Reputation) / 100.0
		if threatScore >= 0.7 {
			f.logger.Log("WARN", "Known malicious IP", ip, threatScore, "BLOCK", threatInfo)
			f.sendAlert("MALICIOUS_IP", "HIGH", ip, fmt.Sprintf("Known malicious IP: %s", threatInfo.Category))
			sshConn.blocked = true
			return true
		}
		sshConn.threatScore = threatScore
	}

	return false
}

// Check geographic restrictions
func (f *SSHSecurityFilter) checkGeographicRestrictions(ip string, sshConn *SSHConnection) bool {
	f.threatIntel.mu.RLock()
	country, exists := f.threatIntel.geoIPDB[ip]
	f.threatIntel.mu.RUnlock()

	if !exists {
		// Try to resolve country via external API
		country = f.resolveCountry(ip)
		if country != "" {
			f.threatIntel.mu.Lock()
			f.threatIntel.geoIPDB[ip] = country
			f.threatIntel.mu.Unlock()
		}
	}

	if country != "" {
		// Check blocked countries
		for _, blocked := range f.config.Security.BlockedCountries {
			if country == blocked {
				f.logger.Log("WARN", "Blocked country", ip, 0.6, "BLOCK", map[string]string{"country": country})
				f.sendAlert("GEO_BLOCK", "MEDIUM", ip, fmt.Sprintf("Connection from blocked country: %s", country))
				sshConn.blocked = true
				return true
			}
		}

		// Check if country is in allowed list (if specified)
		if len(f.config.Security.AllowedCountries) > 0 {
			allowed := false
			for _, allowedCountry := range f.config.Security.AllowedCountries {
				if country == allowedCountry {
					allowed = true
					break
				}
			}
			if !allowed {
				f.logger.Log("WARN", "Country not in allowlist", ip, 0.5, "BLOCK", map[string]string{"country": country})
				f.sendAlert("GEO_RESTRICT", "MEDIUM", ip, fmt.Sprintf("Connection from non-allowed country: %s", country))
				sshConn.blocked = true
				return true
			}
		}
	}

	return false
}

// Analyze SSH protocol for anomalies and attacks
func (f *SSHSecurityFilter) analyzeSSHProtocol(sshConn *SSHConnection) bool {
	conn := sshConn.conn
	
	// Set read timeout
	conn.SetReadDeadline(time.Now().Add(time.Duration(f.config.Server.ReadTimeout) * time.Second))

	// Read SSH identification string
	reader := bufio.NewReader(conn)
	identLine, isPrefix, err := reader.ReadLine()
	if err != nil || isPrefix {
		f.logger.Log("ERROR", "Failed to read SSH identification", sshConn.remoteAddr, 0, "REJECT", err)
		return false
	}

	identStr := string(identLine)
	if !strings.HasPrefix(identStr, "SSH-") {
		f.logger.Log("WARN", "Invalid SSH identification", sshConn.remoteAddr, 0.8, "REJECT", identStr)
		f.sendAlert("PROTOCOL_VIOLATION", "HIGH", sshConn.remoteAddr, "Invalid SSH identification string")
		return false
	}

	// Parse protocol version and client software
	parts := strings.Split(identStr, "-")
	if len(parts) >= 3 {
		sshConn.protocolVersion = parts[1]
		sshConn.clientSoftware = strings.Join(parts[2:], "-")
	}

	// Check for known malicious client signatures
	if f.checkMaliciousClientSignature(sshConn.clientSoftware) {
		f.logger.Log("WARN", "Malicious client signature", sshConn.remoteAddr, 0.9, "BLOCK", sshConn.clientSoftware)
		f.sendAlert("MALICIOUS_CLIENT", "HIGH", sshConn.remoteAddr, fmt.Sprintf("Malicious client: %s", sshConn.clientSoftware))
		sshConn.blocked = true
		return false
	}

	// Send server identification
	serverIdent := "SSH-2.0-SecureFilter_1.0"
	sshConn.serverSoftware = serverIdent
	conn.Write([]byte(serverIdent + "\r\n"))

	// Handle key exchange
	if !f.handleKeyExchange(sshConn, reader) {
		return false
	}

	// Perform deep packet inspection
	if !f.performDeepPacketInspection(sshConn, reader) {
		return false
	}

	// ML-based anomaly detection
	if f.config.ML.Enabled {
		anomalyScore := f.performAnomalyDetection(sshConn)
		if anomalyScore > f.config.ML.AnomalyThreshold {
			atomic.AddInt64(&f.stats.AnomalyDetections, 1)
			f.logger.Log("WARN", "ML anomaly detected", sshConn.remoteAddr, anomalyScore, "BLOCK", nil)
			f.sendAlert("ML_ANOMALY", "HIGH", sshConn.remoteAddr, fmt.Sprintf("Anomaly score: %.3f", anomalyScore))
			sshConn.blocked = true
			return false
		}
	}

	return true
}

// Handle SSH key exchange with cryptographic validation
func (f *SSHSecurityFilter) handleKeyExchange(sshConn *SSHConnection, reader *bufio.Reader) bool {
	// Read KEXINIT packet
	packet, err := f.readSSHPacket(reader)
	if err != nil {
		f.logger.Log("ERROR", "Failed to read KEXINIT", sshConn.remoteAddr, 0, "REJECT", err)
		return false
	}

	if packet.Type != SSH_MSG_KEXINIT {
		f.logger.Log("WARN", "Expected KEXINIT", sshConn.remoteAddr, 0.7, "REJECT", packet.Type)
		return false
	}

	// Parse KEXINIT payload
	kexInit, err := f.parseKexInit(packet.Payload)
	if err != nil {
		f.logger.Log("ERROR", "Failed to parse KEXINIT", sshConn.remoteAddr, 0, "REJECT", err)
		return false
	}

	sshConn.keyExchange = *kexInit

	// Validate cryptographic algorithms
	if !f.cryptoValidator.ValidateKeyExchange(kexInit) {
		atomic.AddInt64(&f.stats.CryptoViolations, 1)
		f.logger.Log("WARN", "Weak cryptographic algorithms", sshConn.remoteAddr, 0.8, "REJECT", kexInit)
		f.sendAlert("CRYPTO_VIOLATION", "HIGH", sshConn.remoteAddr, "Weak cryptographic algorithms detected")
		return false
	}

	// Send server KEXINIT
	serverKexInit := f.generateServerKexInit()
	f.sendSSHPacket(sshConn.conn, SSH_MSG_KEXINIT, serverKexInit)

	return true
}

// Perform deep packet inspection
func (f *SSHSecurityFilter) performDeepPacketInspection(sshConn *SSHConnection, reader *bufio.Reader) bool {
	packetCount := 0
	suspiciousPatterns := 0
	
	for packetCount < 50 { // Analyze first 50 packets
		sshConn.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		
		packet, err := f.readSSHPacket(reader)
		if err != nil {
			if packetCount > 10 { // Allow some packets to be analyzed
				break
			}
			f.logger.Log("ERROR", "DPI read error", sshConn.remoteAddr, 0, "REJECT", err)
			return false
		}

		sshConn.packets = append(sshConn.packets, *packet)
		packetCount++

		// Analyze packet for suspicious patterns
		if f.analyzeSuspiciousPatterns(packet) {
			suspiciousPatterns++
		}

		// Check for buffer overflow attempts
		if len(packet.Payload) > 1024*1024 { // 1MB limit
			f.logger.Log("WARN", "Oversized packet detected", sshConn.remoteAddr, 0.9, "BLOCK", len(packet.Payload))
			f.sendAlert("BUFFER_OVERFLOW", "CRITICAL", sshConn.remoteAddr, fmt.Sprintf("Packet size: %d bytes", len(packet.Payload)))
			return false
		}

		// Check for protocol violations
		if !f.validateProtocolCompliance(packet, sshConn) {
			f.logger.Log("WARN", "Protocol violation", sshConn.remoteAddr, 0.8, "BLOCK", packet.Type)
			return false
		}
	}

	// Evaluate suspicious pattern ratio
	if packetCount > 0 && float64(suspiciousPatterns)/float64(packetCount) > 0.3 {
		f.logger.Log("WARN", "High suspicious pattern ratio", sshConn.remoteAddr, 0.85, "BLOCK", 
			map[string]int{"suspicious": suspiciousPatterns, "total": packetCount})
		f.sendAlert("SUSPICIOUS_PATTERNS", "HIGH", sshConn.remoteAddr, 
			fmt.Sprintf("Suspicious patterns: %d/%d", suspiciousPatterns, packetCount))
		return false
	}

	return true
}

// Handle SSH session (honeypot or legitimate forwarding)
func (f *SSHSecurityFilter) handleSSHSession(sshConn *SSHConnection) {
	// Determine if this should go to honeypot
	shouldHoneypot := f.shouldUseHoneypot(sshConn)
	
	if shouldHoneypot {
		atomic.AddInt64(&f.stats.HoneypotConnections, 1)
		sshConn.honeypot = true
		f.honeypot.HandleConnection(sshConn)
	} else {
		// Forward to real SSH server
		f.forwardToSSHServer(sshConn)
	}
}

// Determine if connection should go to honeypot
func (f *SSHSecurityFilter) shouldUseHoneypot(sshConn *SSHConnection) bool {
	if !f.config.Security.HoneypotEnabled {
		return false
	}

	// High threat score connections go to honeypot
	if sshConn.threatScore > 0.5 {
		return true
	}

	// Connections with suspicious patterns go to honeypot
	if len(sshConn.packets) > 0 {
		suspiciousCount := 0
		for _, packet := range sshConn.packets {
			if f.analyzeSuspiciousPatterns(&packet) {
				suspiciousCount++
			}
		}
		if float64(suspiciousCount)/float64(len(sshConn.packets)) > 0.2 {
			return true
		}
	}

	// Check behavioral profile
	if profile := f.getBehaviorProfile(sshConn.remoteAddr); profile != nil {
		if profile.ThreatScore > 0.6 || profile.FailedAttempts > 5 {
			return true
		}
	}

	return false
}

// Forward connection to real SSH server
func (f *SSHSecurityFilter) forwardToSSHServer(sshConn *SSHConnection) {
	// Connect to real SSH server
	serverConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", f.config.Server.SSHPort))
	if err != nil {
		f.logger.Log("ERROR", "Failed to connect to SSH server", sshConn.remoteAddr, 0, "ERROR", err)
		return
	}
	defer serverConn.Close()

	// Start bidirectional forwarding
	go f.forwardData(sshConn.conn, serverConn, &sshConn.bytesWritten)
	f.forwardData(serverConn, sshConn.conn, &sshConn.bytesRead)
}

// Forward data between connections
func (f *SSHSecurityFilter) forwardData(src, dst net.Conn, byteCounter *int64) {
	buffer := make([]byte, f.config.Server.BufferSize)
	for {
		n, err := src.Read(buffer)
		if err != nil {
			break
		}
		
		atomic.AddInt64(byteCounter, int64(n))
		
		_, err = dst.Write(buffer[:n])
		if err != nil {
			break
		}
	}
}

// ML-based anomaly detection
func (f *SSHSecurityFilter) performAnomalyDetection(sshConn *SSHConnection) float64 {
	features := f.extractFeatures(sshConn)
	return f.mlModel.Predict(features)
}

// Extract features for ML model
func (f *SSHSecurityFilter) extractFeatures(sshConn *SSHConnection) FeatureVector {
	features := FeatureVector{
		ConnectionTime: time.Since(sshConn.startTime).Seconds(),
		AuthAttempts:   0, // Will be updated during auth phase
	}

	// Extract packet-based features
	if len(sshConn.packets) > 0 {
		packetSizes := make([]float64, 0, len(sshConn.packets))
		interArrivalTimes := make([]float64, 0, len(sshConn.packets)-1)
		
		for i, packet := range sshConn.packets {
			packetSizes = append(packetSizes, float64(packet.Length))
			
			if i > 0 {
				timeDiff := packet.Timestamp.Sub(sshConn.packets[i-1].Timestamp).Seconds()
				interArrivalTimes = append(interArrivalTimes, timeDiff)
			}
		}
		
		features.PacketSizes = packetSizes
		features.InterArrivalTime = interArrivalTimes
		features.PayloadEntropy = f.calculateEntropy(sshConn.packets)
	}

	// Protocol-based features
	features.ProtocolVersion = f.encodeProtocolVersion(sshConn.protocolVersion)
	features.CipherSuite = f.encodeCipherSuite(sshConn.keyExchange.EncryptionAlgsCS)

	// Behavioral features
	if profile := f.getBehaviorProfile(sshConn.remoteAddr); profile != nil {
		features.BehaviorPattern = profile.AnomalyScore
	}

	return features
}

// Rate limiter implementation
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.buckets[ip]
	
	if !exists {
		bucket = &TokenBucket{
			tokens:     10.0,
			maxTokens:  10.0,
			refillRate: 1.0,
			lastRefill: now,
		}
		rl.buckets[ip] = bucket
	}

	// Refill tokens
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens = math.Min(bucket.maxTokens, bucket.tokens+elapsed*bucket.refillRate)
	bucket.lastRefill = now

	if bucket.tokens >= 1.0 {
		bucket.tokens--
		return true
	}

	return false
}

// Crypto validator methods
func (cv *CryptoValidator) ValidateKeyExchange(kex *SSHKeyExchange) bool {
	// Check key exchange algorithms
	for _, alg := range kex.ClientKexAlgs {
		if _, banned := cv.bannedAlgorithms[alg]; banned {
			return false
		}
		if len(cv.allowedKexAlgs) > 0 && !cv.allowedKexAlgs[alg] {
			return false
		}
	}

	// Check encryption algorithms
	for _, alg := range kex.EncryptionAlgsCS {
		if _, banned := cv.bannedAlgorithms[alg]; banned {
			return false
		}
		if len(cv.allowedCiphers) > 0 && !cv.allowedCiphers[alg] {
			return false
		}
	}

	// Check MAC algorithms
	for _, alg := range kex.MacAlgsCS {
		if _, banned := cv.bannedAlgorithms[alg]; banned {
			return false
		}
		if len(cv.allowedMACs) > 0 && !cv.allowedMACs[alg] {
			return false
		}
	}

	return true
}

// Honeypot system methods
func (h *HoneypotSystem) HandleConnection(sshConn *SSHConnection) {
	h.mu.Lock()
	defer h.mu.Unlock()

	ip, _, _ := net.SplitHostPort(sshConn.remoteAddr)
	
	// Create or update attacker profile
	profile, exists := h.attackerProfiles[ip]
	if !exists {
		profile = &AttackerProfile{
			IP:           ip,
			FirstContact: time.Now(),
			Commands:     make([]string, 0),
			ThreatLevel:  1,
		}
		h.attackerProfiles[ip] = profile
	}
	
	profile.LastContact = time.Now()
	profile.Interactions++

	// Simulate SSH session
	h.simulateSSHSession(sshConn, profile)
}

func (h *HoneypotSystem) simulateSSHSession(sshConn *SSHConnection, profile *AttackerProfile) {
	conn := sshConn.conn
	scanner := bufio.NewScanner(conn)

	// Send fake prompt
	conn.Write([]byte("admin@honeypot:~$ "))

	for scanner.Scan() {
		command := strings.TrimSpace(scanner.Text())
		if command == "" {
			continue
		}

		// Log the command
		interaction := HoneypotInteraction{
			Timestamp: time.Now(),
			Command:   command,
			Duration:  time.Since(sshConn.startTime),
		}

		profile.Commands = append(profile.Commands, command)
		
		// Generate response
		response := h.generateResponse(command)
		interaction.Response = response
		
		// Add to interactions
		if h.interactions[sshConn.remoteAddr] == nil {
			h.interactions[sshConn.remoteAddr] = make([]HoneypotInteraction, 0)
		}
		h.interactions[sshConn.remoteAddr] = append(h.interactions[sshConn.remoteAddr], interaction)

		// Send response with delay (tarpit)
		time.Sleep(time.Duration(mathrand.Intn(3)+1) * time.Second)
		conn.Write([]byte(response + "\nadmin@honeypot:~$ "))

		// Update threat level based on commands
		if h.isMaliciousCommand(command) {
			profile.ThreatLevel++
		}

		// Break on exit commands
		if command == "exit" || command == "quit" {
			break
		}
	}
}

func (h *HoneypotSystem) generateResponse(command string) string {
	if response, exists := h.responses[command]; exists {
		return response
	}

	// Pattern-based responses
	if strings.Contains(command, "wget") || strings.Contains(command, "curl") {
		return "bash: " + strings.Fields(command)[0] + ": command not found"
	}
	
	if strings.Contains(command, "cat") && strings.Contains(command, "/proc/") {
		return "cat: " + strings.Fields(command)[1] + ": Permission denied"
	}

	// Default response
	return "bash: " + strings.Fields(command)[0] + ": command not found"
}

func (h *HoneypotSystem) isMaliciousCommand(command string) bool {
	maliciousPatterns := []string{
		"wget", "curl", "nc", "netcat", "/tmp/", "/var/tmp/",
		"chmod +x", "nohup", "/proc/", "iptables", "ufw",
		"systemctl", "service", "crontab", "base64",
	}

	for _, pattern := range maliciousPatterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}
	return false
}

// ML Model methods
func (ml *MLModel) Predict(features FeatureVector) float64 {
	ml.mu.RLock()
	defer ml.mu.RUnlock()

	if len(ml.weights) == 0 {
		return 0.0 // No model trained yet
	}

	// Normalize features
	normalizedFeatures := ml.normalizeFeatures(features)
	
	// Simple neural network prediction
	score := 0.0
	featureSlice := ml.featuresToSlice(normalizedFeatures)
	
	for i, weight := range ml.weights[0] {
		if i < len(featureSlice) {
			score += weight * featureSlice[i]
		}
	}
	
	// Add bias
	if len(ml.biases) > 0 {
		score += ml.biases[0]
	}

	// Sigmoid activation
	return 1.0 / (1.0 + math.Exp(-score))
}

func (ml *MLModel) normalizeFeatures(features FeatureVector) FeatureVector {
	normalized := features
	
	// Normalize each feature using stored scalers
	if len(ml.featureScalers) >= 10 {
		normalized.ConnectionTime = (features.ConnectionTime - ml.featureScalers[0].Mean) / ml.featureScalers[0].Std
		normalized.AuthAttempts = (features.AuthAttempts - ml.featureScalers[1].Mean) / ml.featureScalers[1].Std
		normalized.PayloadEntropy = (features.PayloadEntropy - ml.featureScalers[2].Mean) / ml.featureScalers[2].Std
		normalized.ProtocolVersion = (features.ProtocolVersion - ml.featureScalers[3].Mean) / ml.featureScalers[3].Std
		normalized.CipherSuite = (features.CipherSuite - ml.featureScalers[4].Mean) / ml.featureScalers[4].Std
		normalized.CompressionRatio = (features.CompressionRatio - ml.featureScalers[5].Mean) / ml.featureScalers[5].Std
		normalized.BehaviorPattern = (features.BehaviorPattern - ml.featureScalers[6].Mean) / ml.featureScalers[6].Std
	}

	return normalized
}

func (ml *MLModel) featuresToSlice(features FeatureVector) []float64 {
	return []float64{
		features.ConnectionTime,
		features.AuthAttempts,
		features.PayloadEntropy,
		features.ProtocolVersion,
		features.CipherSuite,
		features.CompressionRatio,
		features.BehaviorPattern,
		features.KeyExchangeTime,
	}
}

// Utility functions
func (f *SSHSecurityFilter) readSSHPacket(reader *bufio.Reader) (*SSHPacket, error) {
	// Read packet length
	lengthBytes := make([]byte, 4)
	_, err := io.ReadFull(reader, lengthBytes)
	if err != nil {
		return nil, err
	}

	packetLength := binary.BigEndian.Uint32(lengthBytes)
	if packetLength > 1024*1024 { // 1MB limit
		return nil, fmt.Errorf("packet too large: %d bytes", packetLength)
	}

	// Read padding length
	paddingLength := make([]byte, 1)
	_, err = io.ReadFull(reader, paddingLength)
	if err != nil {
		return nil, err
	}

	// Read payload and padding
	payloadAndPadding := make([]byte, packetLength-1)
	_, err = io.ReadFull(reader, payloadAndPadding)
	if err != nil {
		return nil, err
	}

	payloadLength := int(packetLength) - int(paddingLength[0]) - 1
	payload := payloadAndPadding[:payloadLength]

	packet := &SSHPacket{
		Type:      payload[0],
		Length:    packetLength,
		Payload:   payload[1:], // Skip message type byte
		Timestamp: time.Now(),
	}

	return packet, nil
}

func (f *SSHSecurityFilter) sendSSHPacket(conn net.Conn, msgType uint8, payload []byte) error {
	paddingLength := uint8(4) // Minimum padding
	packetLength := uint32(1 + len(payload) + int(paddingLength))
	
	// Write packet length
	lengthBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBytes, packetLength)
	conn.Write(lengthBytes)
	
	// Write padding length
	conn.Write([]byte{paddingLength})
	
	// Write message type
	conn.Write([]byte{msgType})
	
	// Write payload
	conn.Write(payload)
	
	// Write padding
	padding := make([]byte, paddingLength)
	rand.Read(padding)
	conn.Write(padding)
	
	return nil
}

func (f *SSHSecurityFilter) parseKexInit(payload []byte) (*SSHKeyExchange, error) {
	if len(payload) < 16 {
		return nil, fmt.Errorf("KEXINIT payload too short")
	}

	kex := &SSHKeyExchange{}
	offset := 16 // Skip random bytes

	// Parse algorithm lists
	var err error
	kex.ClientKexAlgs, offset, err = f.parseStringList(payload, offset)
	if err != nil {
		return nil, err
	}

	kex.ClientHostKeyAlgs, offset, err = f.parseStringList(payload, offset)
	if err != nil {
		return nil, err
	}

	kex.EncryptionAlgsCS, offset, err = f.parseStringList(payload, offset)
	if err != nil {
		return nil, err
	}

	kex.EncryptionAlgsSC, offset, err = f.parseStringList(payload, offset)
	if err != nil {
		return nil, err
	}

	kex.MacAlgsCS, offset, err = f.parseStringList(payload, offset)
	if err != nil {
		return nil, err
	}

	kex.MacAlgsSC, offset, err = f.parseStringList(payload, offset)
	if err != nil {
		return nil, err
	}

	kex.CompressionAlgsCS, offset, err = f.parseStringList(payload, offset)
	if err != nil {
		return nil, err
	}

	kex.CompressionAlgsSC, offset, err = f.parseStringList(payload, offset)
	if err != nil {
		return nil, err
	}

	return kex, nil
}

func (f *SSHSecurityFilter) parseStringList(data []byte, offset int) ([]string, int, error) {
	if offset+4 > len(data) {
		return nil, offset, fmt.Errorf("insufficient data for string list length")
	}

	listLength := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if offset+int(listLength) > len(data) {
		return nil, offset, fmt.Errorf("insufficient data for string list")
	}

	listData := string(data[offset : offset+int(listLength)])
	offset += int(listLength)

	algorithms := strings.Split(listData, ",")
	return algorithms, offset, nil
}

func (f *SSHSecurityFilter) generateServerKexInit() []byte {
	// Generate 16 random bytes
	random := make([]byte, 16)
	rand.Read(random)

	payload := random

	// Add algorithm lists
	serverAlgs := [][]string{
		{"diffie-hellman-group14-sha256"}, // kex_algorithms
		{"ssh-rsa"},                      // server_host_key_algorithms
		{"aes256-ctr"},                   // encryption_algorithms_client_to_server
		{"aes256-ctr"},                   // encryption_algorithms_server_to_client
		{"hmac-sha2-256"},                // mac_algorithms_client_to_server
		{"hmac-sha2-256"},                // mac_algorithms_server_to_client
		{"none"},                         // compression_algorithms_client_to_server
		{"none"},                         // compression_algorithms_server_to_client
	}

	for _, algList := range serverAlgs {
		algString := strings.Join(algList, ",")
		lengthBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(lengthBytes, uint32(len(algString)))
		payload = append(payload, lengthBytes...)
		payload = append(payload, []byte(algString)...)
	}

	// Add first_kex_packet_follows (false) and reserved (0)
	payload = append(payload, 0, 0, 0, 0, 0)

	return payload
}

func (f *SSHSecurityFilter) checkMaliciousClientSignature(clientSoftware string) bool {
	maliciousSignatures := []string{
		"libssh", "paramiko", "pexpect", "fabric", "twisted",
		"go", "python", "perl", "ruby", "bot", "scan",
	}

	clientLower := strings.ToLower(clientSoftware)
	for _, sig := range maliciousSignatures {
		if strings.Contains(clientLower, sig) {
			return true
		}
	}

	return false
}

func (f *SSHSecurityFilter) analyzeSuspiciousPatterns(packet *SSHPacket) bool {
	payload := packet.Payload
	
	// Check for buffer overflow patterns
	if len(payload) > 8192 {
		return true
	}

	// Check for repeated patterns (potential DoS)
	if len(payload) > 100 {
		sample := payload[:100]
		repeated := 0
		for i := 100; i < len(payload)-100; i += 100 {
			if bytes.Equal(sample, payload[i:i+100]) {
				repeated++
				if repeated > 5 {
					return true
				}
			}
		}
	}

	// Check for common attack patterns
	suspiciousBytes := [][]byte{
		[]byte("\x90\x90\x90\x90"), // NOP sled
		[]byte("AAAA"),              // Buffer overflow test
		[]byte("/bin/sh"),           // Shell injection
		[]byte("../../../../"),       // Directory traversal
		[]byte("%2e%2e%2f"),        // URL encoded traversal
	}

	for _, pattern := range suspiciousBytes {
		if bytes.Contains(payload, pattern) {
			return true
		}
	}

	return false
}

func (f *SSHSecurityFilter) validateProtocolCompliance(packet *SSHPacket, sshConn *SSHConnection) bool {
	// Check message type validity
	validTypes := map[uint8]bool{
		SSH_MSG_DISCONNECT:        true,
		SSH_MSG_IGNORE:           true,
		SSH_MSG_UNIMPLEMENTED:    true,
		SSH_MSG_DEBUG:            true,
		SSH_MSG_SERVICE_REQUEST:  true,
		SSH_MSG_SERVICE_ACCEPT:   true,
		SSH_MSG_KEXINIT:          true,
		SSH_MSG_NEWKEYS:          true,
		SSH_MSG_KEXDH_INIT:       true,
		SSH_MSG_KEXDH_REPLY:      true,
		SSH_MSG_USERAUTH_REQUEST: true,
		SSH_MSG_USERAUTH_FAILURE: true,
		SSH_MSG_USERAUTH_SUCCESS: true,
	}

	if !validTypes[packet.Type] && packet.Type < 50 {
		return false
	}

	// Check packet ordering
	if len(sshConn.packets) > 0 {
		lastPacket := sshConn.packets[len(sshConn.packets)-1]
		
		// KEXINIT should be followed by key exchange messages
		if lastPacket.Type == SSH_MSG_KEXINIT && 
		   packet.Type != SSH_MSG_KEXDH_INIT && 
		   packet.Type != SSH_MSG_KEXINIT {
			return false
		}
	}

	return true
}

func (f *SSHSecurityFilter) calculateEntropy(packets []SSHPacket) float64 {
	if len(packets) == 0 {
		return 0.0
	}

	// Combine all payload data
	var allData []byte
	for _, packet := range packets {
		allData = append(allData, packet.Payload...)
	}

	if len(allData) == 0 {
		return 0.0
	}

	// Calculate byte frequency
	freq := make(map[byte]int)
	for _, b := range allData {
		freq[b]++
	}

	// Calculate Shannon entropy
	entropy := 0.0
	length := float64(len(allData))
	
	for _, count := range freq {
		if count > 0 {
			p := float64(count) / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (f *SSHSecurityFilter) encodeProtocolVersion(version string) float64 {
	if version == "2.0" {
		return 2.0
	} else if version == "1.99" {
		return 1.99
	} else if version == "1.5" {
		return 1.5
	}
	return 0.0
}

func (f *SSHSecurityFilter) encodeCipherSuite(ciphers []string) float64 {
	score := 0.0
	for _, cipher := range ciphers {
		switch {
		case strings.Contains(cipher, "aes256"):
			score += 3.0
		case strings.Contains(cipher, "aes128"):
			score += 2.0
		case strings.Contains(cipher, "3des"):
			score += 1.0
		case strings.Contains(cipher, "arcfour"):
			score -= 1.0
		}
	}
	return score
}

func (f *SSHSecurityFilter) getBehaviorProfile(remoteAddr string) *BehaviorProfile {
	f.mu.RLock()
	defer f.mu.RUnlock()
	
	ip, _, _ := net.SplitHostPort(remoteAddr)
	return f.behaviorDB[ip]
}

func (f *SSHSecurityFilter) updateBehaviorProfile(sshConn *SSHConnection) {
	f.mu.Lock()
	defer f.mu.Unlock()

	ip, _, _ := net.SplitHostPort(sshConn.remoteAddr)
	
	profile, exists := f.behaviorDB[ip]
	if !exists {
		profile = &BehaviorProfile{
			IP:        ip,
			FirstSeen: time.Now(),
			Features:  make([]FeatureVector, 0),
		}
		f.behaviorDB[ip] = profile
	}

	// Update profile
	profile.LastSeen = time.Now()
	profile.ConnectionCount++
	
	if sshConn.blocked {
		profile.FailedAttempts++
	}

	// Calculate average session time
	sessionTime := time.Since(sshConn.startTime).Seconds()
	profile.AverageSessionTime = (profile.AverageSessionTime*float64(profile.ConnectionCount-1) + sessionTime) / float64(profile.ConnectionCount)

	// Add features
	if f.config.ML.Enabled {
		features := f.extractFeatures(sshConn)
		profile.Features = append(profile.Features, features)
		
		// Keep only recent features
		if len(profile.Features) > f.config.ML.FeatureWindow {
			profile.Features = profile.Features[len(profile.Features)-f.config.ML.FeatureWindow:]
		}
	}

	// Update threat score
	profile.ThreatScore = f.calculateThreatScore(profile, sshConn)
	
	// Update anomaly score if ML is enabled
	if f.config.ML.Enabled && len(profile.Features) > 0 {
		profile.AnomalyScore = f.mlModel.Predict(profile.Features[len(profile.Features)-1])
	}

	// Save to database
	f.saveBehaviorProfile(profile)
}

func (f *SSHSecurityFilter) calculateThreatScore(profile *BehaviorProfile, sshConn *SSHConnection) float64 {
	score := 0.0

	// Failed attempts factor
	if profile.ConnectionCount > 0 {
		failureRate := float64(profile.FailedAttempts) / float64(profile.ConnectionCount)
		score += failureRate * 0.4
	}

	// Frequency factor
	timeSinceFirst := time.Since(profile.FirstSeen).Hours()
	if timeSinceFirst > 0 {
		connectionsPerHour := float64(profile.ConnectionCount) / timeSinceFirst
		if connectionsPerHour > 10 {
			score += 0.3
		}
	}

	// External threat score
	score += sshConn.threatScore * 0.3

	return math.Min(score, 1.0)
}

func (f *SSHSecurityFilter) recordConnection(sshConn *SSHConnection) {
	query := `
		INSERT INTO connections 
		(remote_addr, protocol_version, client_software, threat_score, blocked, honeypot, duration, bytes_read, bytes_written)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	duration := time.Since(sshConn.startTime).Milliseconds()
	
	_, err := f.db.Exec(query,
		sshConn.remoteAddr,
		sshConn.protocolVersion,
		sshConn.clientSoftware,
		sshConn.threatScore,
		sshConn.blocked,
		sshConn.honeypot,
		duration,
		sshConn.bytesRead,
		sshConn.bytesWritten,
	)

	if err != nil {
		f.logger.Log("ERROR", "Failed to record connection", sshConn.remoteAddr, 0, "ERROR", err)
	}
}

func (f *SSHSecurityFilter) saveBehaviorProfile(profile *BehaviorProfile) {
	profileData, _ := json.Marshal(profile)
	
	query := `
		INSERT OR REPLACE INTO behavior_profiles 
		(ip, first_seen, last_seen, connection_count, failed_attempts, threat_score, profile_data)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	_, err := f.db.Exec(query,
		profile.IP,
		profile.FirstSeen,
		profile.LastSeen,
		profile.ConnectionCount,
		profile.FailedAttempts,
		profile.ThreatScore,
		string(profileData),
	)

	if err != nil {
		f.logger.Log("ERROR", "Failed to save behavior profile", profile.IP, 0, "ERROR", err)
	}
}

func (f *SSHSecurityFilter) resolveCountry(ip string) string {
	// Simple GeoIP resolution - in production, use MaxMind or similar
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=countryCode", ip))
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	var result struct {
		CountryCode string `json:"countryCode"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return ""
	}

	return result.CountryCode
}

// Background service methods
func (f *SSHSecurityFilter) updateThreatIntelligence() {
	ticker := time.NewTicker(time.Duration(f.config.Intelligence.UpdateInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.updateTorNodes()
			f.updateVPNRanges()
			f.updateThreatFeeds()
		case <-f.shutdown:
			return
		}
	}
}

func (f *SSHSecurityFilter) updateTorNodes() {
	if f.config.Intelligence.TorNodeListURL == "" {
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(f.config.Intelligence.TorNodeListURL)
	if err != nil {
		f.logger.Log("ERROR", "Failed to update Tor nodes", "", 0, "ERROR", err)
		return
	}
	defer resp.Body.Close()

	f.threatIntel.mu.Lock()
	defer f.threatIntel.mu.Unlock()

	// Clear existing nodes
	f.threatIntel.torNodes = make(map[string]bool)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		ip := strings.TrimSpace(scanner.Text())
		if net.ParseIP(ip) != nil {
			f.threatIntel.torNodes[ip] = true
		}
	}

	f.logger.Log("INFO", "Updated Tor nodes", "", 0, "INFO", len(f.threatIntel.torNodes))
}

func (f *SSHSecurityFilter) updateVPNRanges() {
	if f.config.Intelligence.VPNRangesURL == "" {
		return
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(f.config.Intelligence.VPNRangesURL)
	if err != nil {
		f.logger.Log("ERROR", "Failed to update VPN ranges", "", 0, "ERROR", err)
		return
	}
	defer resp.Body.Close()

	f.threatIntel.mu.Lock()
	defer f.threatIntel.mu.Unlock()

	// Clear existing ranges
	f.threatIntel.vpnRanges = make([]*net.IPNet, 0)

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		cidr := strings.TrimSpace(scanner.Text())
		_, ipNet, err := net.ParseCIDR(cidr)
		if err == nil {
			f.threatIntel.vpnRanges = append(f.threatIntel.vpnRanges, ipNet)
		}
	}

	f.logger.Log("INFO", "Updated VPN ranges", "", 0, "INFO", len(f.threatIntel.vpnRanges))
}

func (f *SSHSecurityFilter) updateThreatFeeds() {
	for _, feedURL := range f.config.Intelligence.ThreatFeeds {
		f.updateSingleThreatFeed(feedURL)
	}
}

func (f *SSHSecurityFilter) updateSingleThreatFeed(feedURL string) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(feedURL)
	if err != nil {
		f.logger.Log("ERROR", "Failed to update threat feed", feedURL, 0, "ERROR", err)
		return
	}
	defer resp.Body.Close()

	f.threatIntel.mu.Lock()
	defer f.threatIntel.mu.Unlock()

	scanner := bufio.NewScanner(resp.Body)
	updated := 0
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse different feed formats
		parts := strings.Fields(line)
		if len(parts) > 0 {
			ip := parts[0]
			if net.ParseIP(ip) != nil {
				threatInfo := ThreatInfo{
					Reputation: 80, // Default high reputation
					Category:   "malicious",
					LastSeen:   time.Now(),
					Source:     feedURL,
				}
				f.threatIntel.maliciousIPs[ip] = threatInfo
				updated++
			}
		}
	}

	f.logger.Log("INFO", "Updated threat feed", feedURL, 0, "INFO", updated)
}

func (f *SSHSecurityFilter) trainMLModel() {
	if !f.config.ML.Enabled {
		return
	}

	ticker := time.NewTicker(time.Duration(f.config.ML.UpdateInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.performMLTraining()
		case <-f.shutdown:
			return
		}
	}
}

func (f *SSHSecurityFilter) performMLTraining() {
	// Load training data from database
	query := `
		SELECT features, label FROM ml_training 
		WHERE timestamp > datetime('now', '-24 hours')
		ORDER BY timestamp DESC
		LIMIT 10000
	`

	rows, err := f.db.Query(query)
	if err != nil {
		f.logger.Log("ERROR", "Failed to load training data", "", 0, "ERROR", err)
		return
	}
	defer rows.Close()

	var trainingData []TrainingExample
	for rows.Next() {
		var featuresJSON string
		var label float64
		
		if err := rows.Scan(&featuresJSON, &label); err != nil {
			continue
		}

		var features FeatureVector
		if err := json.Unmarshal([]byte(featuresJSON), &features); err != nil {
			continue
		}

		trainingData = append(trainingData, TrainingExample{
			Features: features,
			Label:    label,
		})
	}

	if len(trainingData) < 100 {
		f.logger.Log("INFO", "Insufficient training data", "", 0, "INFO", len(trainingData))
		return
	}

	// Train simple model
	f.mlModel.mu.Lock()
	defer f.mlModel.mu.Unlock()

	f.mlModel.trainingData = trainingData
	f.trainNeuralNetwork()
	f.mlModel.lastTrained = time.Now()

	f.logger.Log("INFO", "ML model retrained", "", 0, "INFO", len(trainingData))
}

func (f *SSHSecurityFilter) trainNeuralNetwork() {
	if len(f.mlModel.trainingData) == 0 {
		return
	}

	// Simple perceptron training
	featureCount := 8
	f.mlModel.weights = make([][]float64, 1)
	f.mlModel.weights[0] = make([]float64, featureCount)
	f.mlModel.biases = make([]float64, 1)

	// Initialize weights randomly
	for i := range f.mlModel.weights[0] {
		f.mlModel.weights[0][i] = (mathrand.Float64() - 0.5) * 0.1
	}

	// Training loop
	learningRate := 0.01
	epochs := 100

	for epoch := 0; epoch < epochs; epoch++ {
		totalError := 0.0
		
		for _, example := range f.mlModel.trainingData {
			features := f.mlModel.featuresToSlice(example.Features)
			prediction := f.mlModel.Predict(example.Features)
			error := example.Label - prediction
			totalError += error * error

			// Update weights
			for i, feature := range features {
				if i < len(f.mlModel.weights[0]) {
					f.mlModel.weights[0][i] += learningRate * error * feature
				}
			}
			f.mlModel.biases[0] += learningRate * error
		}

		if totalError < 0.01 {
			break
		}
	}

	// Calculate accuracy
	f.calculateModelAccuracy()
}

func (f *SSHSecurityFilter) calculateModelAccuracy() {
	if len(f.mlModel.trainingData) == 0 {
		return
	}

	correct := 0
	truePositives := 0
	falsePositives := 0
	trueNegatives := 0
	falseNegatives := 0

	for _, example := range f.mlModel.trainingData {
		prediction := f.mlModel.Predict(example.Features)
		predicted := 0.0
		if prediction > 0.5 {
			predicted = 1.0
		}

		if predicted == example.Label {
			correct++
			if example.Label == 1.0 {
				truePositives++
			} else {
				trueNegatives++
			}
		} else {
			if predicted == 1.0 {
				falsePositives++
			} else {
				falseNegatives++
			}
		}
	}

	f.mlModel.accuracy = float64(correct) / float64(len(f.mlModel.trainingData))
	
	if truePositives+falsePositives > 0 {
		precision := float64(truePositives) / float64(truePositives+falsePositives)
		f.mlModel.truePositiveRate = precision
	}
	
	if falsePositives+trueNegatives > 0 {
		f.mlModel.falsePositiveRate = float64(falsePositives) / float64(falsePositives+trueNegatives)
	}
}

func (f *SSHSecurityFilter) databaseCleanup() {
	ticker := time.NewTicker(time.Duration(f.config.Database.BackupInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.performDatabaseCleanup()
		case <-f.shutdown:
			return
		}
	}
}

func (f *SSHSecurityFilter) performDatabaseCleanup() {
	// Remove old connections (older than 30 days)
	_, err := f.db.Exec("DELETE FROM connections WHERE timestamp < datetime('now', '-30 days')")
	if err != nil {
		f.logger.Log("ERROR", "Database cleanup failed", "", 0, "ERROR", err)
	}

	// Remove old training data (older than 7 days)
	_, err = f.db.Exec("DELETE FROM ml_training WHERE timestamp < datetime('now', '-7 days')")
	if err != nil {
		f.logger.Log("ERROR", "Training data cleanup failed", "", 0, "ERROR", err)
	}

	// Vacuum database
	_, err = f.db.Exec("VACUUM")
	if err != nil {
		f.logger.Log("ERROR", "Database vacuum failed", "", 0, "ERROR", err)
	}

	f.logger.Log("INFO", "Database cleanup completed", "", 0, "INFO", nil)
}

func (f *SSHSecurityFilter) collectStatistics() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			f.logStatistics()
		case <-f.shutdown:
			return
		}
	}
}

func (f *SSHSecurityFilter) logStatistics() {
	stats := map[string]interface{}{
		"total_connections":      atomic.LoadInt64(&f.stats.TotalConnections),
		"blocked_connections":    atomic.LoadInt64(&f.stats.BlockedConnections),
		"honeypot_connections":   atomic.LoadInt64(&f.stats.HoneypotConnections),
		"threat_detections":      atomic.LoadInt64(&f.stats.ThreatDetections),
		"anomaly_detections":     atomic.LoadInt64(&f.stats.AnomalyDetections),
		"geo_blocks":            atomic.LoadInt64(&f.stats.GeoBlocks),
		"tor_blocks":            atomic.LoadInt64(&f.stats.TorBlocks),
		"vpn_blocks":            atomic.LoadInt64(&f.stats.VPNBlocks),
		"crypto_violations":     atomic.LoadInt64(&f.stats.CryptoViolations),
		"rate_limit_violations": atomic.LoadInt64(&f.stats.RateLimitViolations),
		"uptime_hours":          time.Since(f.stats.StartTime).Hours(),
		"goroutines":            runtime.NumGoroutine(),
	}

	f.logger.Log("INFO", "Statistics", "", 0, "STATS", stats)
}

func (f *SSHSecurityFilter) startPacketCapture() {
	// This would implement raw packet capture using pcap or eBPF
	// For brevity, this is a simplified version
	f.logger.Log("INFO", "Packet capture started", "", 0, "INFO", nil)
}

// Logging methods
func (logger *SecurityLogger) Log(level, message, remoteAddr string, threatScore float64, action string, details interface{}) {
	entry := LogEntry{
		Timestamp:   time.Now(),
		Level:       level,
		Source:      "SSH_FILTER",
		Message:     message,
		RemoteAddr:  remoteAddr,
		ThreatScore: threatScore,
		Action:      action,
		Details:     details,
	}

	select {
	case logger.buffer <- entry:
	default:
		// Buffer full, drop log entry
	}
}

func (logger *SecurityLogger) processLogs() {
	for {
		select {
		case entry := <-logger.buffer:
			logger.writeLog(entry)
		case <-logger.shutdown:
			return
		}
	}
}

func (logger *SecurityLogger) writeLog(entry LogEntry) {
	logger.mu.Lock()
	defer logger.mu.Unlock()

	logLine, _ := json.Marshal(entry)
	
	// Write to file
	if logger.file != nil {
		logger.file.Write(logLine)
		logger.file.Write([]byte("\n"))
	}

	// Send to SIEM
	if logger.siemURL != "" {
		go logger.sendToSIEM(entry)
	}

	// Write to syslog
	if logger.syslog {
		log.Printf("[%s] %s: %s", entry.Level, entry.RemoteAddr, entry.Message)
	}
}

func (logger *SecurityLogger) sendToSIEM(entry LogEntry) {
	if logger.siemURL == "" {
		return
	}

	client := &http.Client{Timeout: 5 * time.Second}
	jsonData, _ := json.Marshal(entry)
	
	resp, err := client.Post(logger.siemURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// Alert system methods
func (f *SSHSecurityFilter) sendAlert(alertType, severity, source, description string) {
	alert := Alert{
		ID:          f.generateAlertID(),
		Timestamp:   time.Now(),
		Severity:    severity,
		Type:        alertType,
		Source:      source,
		Description: description,
	}

	select {
	case f.alertSystem.alerts <- alert:
	default:
		// Alert buffer full
	}
}

func (f *SSHSecurityFilter) generateAlertID() string {
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d%d", time.Now().UnixNano(), mathrand.Int63())))
	return hex.EncodeToString(hash[:8])
}

func (alertSystem *AlertSystem) processAlerts() {
	for {
		select {
		case alert := <-alertSystem.alerts:
			alertSystem.handleAlert(alert)
		case <-alertSystem.shutdown:
			return
		}
	}
}

func (alertSystem *AlertSystem) handleAlert(alert Alert) {
	// Send to webhooks
	for _, webhook := range alertSystem.webhooks {
		go alertSystem.sendWebhook(webhook, alert)
	}

	// Log critical alerts
	if alert.Severity == "CRITICAL" {
		log.Printf("CRITICAL ALERT: %s - %s", alert.Type, alert.Description)
	}
}

func (alertSystem *AlertSystem) sendWebhook(webhook string, alert Alert) {
	client := &http.Client{Timeout: 10 * time.Second}
	jsonData, _ := json.Marshal(alert)
	
	resp, err := client.Post(webhook, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}
	defer resp.Body.Close()
}

// Rate limiter cleanup
func (rl *RateLimiter) cleanupBuckets() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, bucket := range rl.buckets {
				if now.Sub(bucket.lastRefill) > 10*time.Minute {
					delete(rl.buckets, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.cleanup:
			return
		}
	}
}

// Main server
func (f *SSHSecurityFilter) Start() error {
	if !atomic.CompareAndSwapInt32(&f.running, 0, 1) {
		return fmt.Errorf("server already running")
	}

	listener, err := net.Listen("tcp", f.config.Server.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer listener.Close()

	f.logger.Log("INFO", "SSH Security Filter started", f.config.Server.ListenAddr, 0, "START", nil)

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		f.logger.Log("INFO", "Shutdown signal received", "", 0, "SHUTDOWN", nil)
		f.Stop()
		listener.Close()
	}()

	// Connection handling loop
	for atomic.LoadInt32(&f.running) == 1 {
		conn, err := listener.Accept()
		if err != nil {
			if atomic.LoadInt32(&f.running) == 0 {
				break
			}
			continue
		}

		// Check connection limits
		if atomic.LoadInt64(&f.stats.TotalConnections) >= int64(f.config.Server.MaxConns) {
			conn.Close()
			continue
		}

		f.wg.Add(1)
		go func() {
			defer f.wg.Done()
			f.handleConnection(conn)
		}()
	}

	return nil
}

func (f *SSHSecurityFilter) Stop() {
	if !atomic.CompareAndSwapInt32(&f.running, 1, 0) {
		return
	}

	close(f.shutdown)
	f.wg.Wait()

	// Close resources
	if f.db != nil {
		f.db.Close()
	}

	if f.logger != nil && f.logger.file != nil {
		f.logger.file.Close()
	}

	f.logger.Log("INFO", "SSH Security Filter stopped", "", 0, "STOP", nil)
}

// Configuration management
func (f *SSHSecurityFilter) LoadConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	newConfig := &Config{}
	if err := yaml.Unmarshal(data, newConfig); err != nil {
		return err
	}

	f.config = newConfig
	return nil
}

func (f *SSHSecurityFilter) SaveConfig(configPath string) error {
	data, err := yaml.Marshal(f.config)
	if err != nil {
		return err
	}

	return os.WriteFile(configPath, data, 0644)
}

// API endpoints for management
func (f *SSHSecurityFilter) StartManagementAPI() {
	http.HandleFunc("/api/stats", f.handleStats)
	http.HandleFunc("/api/threats", f.handleThreats)
	http.HandleFunc("/api/behavior", f.handleBehavior)
	http.HandleFunc("/api/config", f.handleConfig)
	http.HandleFunc("/api/alerts", f.handleAlerts)
	http.HandleFunc("/api/honeypot", f.handleHoneypot)

	go http.ListenAndServe(":8080", nil)
	f.logger.Log("INFO", "Management API started on :8080", "", 0, "INFO", nil)
}

func (f *SSHSecurityFilter) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := map[string]interface{}{
		"total_connections":      atomic.LoadInt64(&f.stats.TotalConnections),
		"blocked_connections":    atomic.LoadInt64(&f.stats.BlockedConnections),
		"honeypot_connections":   atomic.LoadInt64(&f.stats.HoneypotConnections),
		"threat_detections":      atomic.LoadInt64(&f.stats.ThreatDetections),
		"anomaly_detections":     atomic.LoadInt64(&f.stats.AnomalyDetections),
		"geo_blocks":            atomic.LoadInt64(&f.stats.GeoBlocks),
		"tor_blocks":            atomic.LoadInt64(&f.stats.TorBlocks),
		"vpn_blocks":            atomic.LoadInt64(&f.stats.VPNBlocks),
		"crypto_violations":     atomic.LoadInt64(&f.stats.CryptoViolations),
		"rate_limit_violations": atomic.LoadInt64(&f.stats.RateLimitViolations),
		"start_time":            f.stats.StartTime,
		"uptime":                time.Since(f.stats.StartTime).String(),
		"ml_model_accuracy":     f.mlModel.accuracy,
		"behavior_profiles":     len(f.behaviorDB),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func (f *SSHSecurityFilter) handleThreats(w http.ResponseWriter, r *http.Request) {
	f.threatIntel.mu.RLock()
	defer f.threatIntel.mu.RUnlock()

	threats := map[string]interface{}{
		"tor_nodes":     len(f.threatIntel.torNodes),
		"vpn_ranges":    len(f.threatIntel.vpnRanges),
		"malicious_ips": len(f.threatIntel.maliciousIPs),
		"last_update":   f.threatIntel.lastUpdate,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

func (f *SSHSecurityFilter) handleBehavior(w http.ResponseWriter, r *http.Request) {
	f.mu.RLock()
	profiles := make([]*BehaviorProfile, 0, len(f.behaviorDB))
	for _, profile := range f.behaviorDB {
		profiles = append(profiles, profile)
	}
	f.mu.RUnlock()

	// Sort by threat score
	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].ThreatScore > profiles[j].ThreatScore
	})

	// Return top 100 profiles
	if len(profiles) > 100 {
		profiles = profiles[:100]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles)
}

func (f *SSHSecurityFilter) handleConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(f.config)
	} else if r.Method == "POST" {
		var newConfig Config
		if err := json.NewDecoder(r.Body).Decode(&newConfig); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.config = &newConfig
		w.WriteHeader(http.StatusOK)
	}
}

func (f *SSHSecurityFilter) handleAlerts(w http.ResponseWriter, r *http.Request) {
	// Return recent alerts from database
	query := `
		SELECT timestamp, event_type, source_ip, severity, description 
		FROM security_events 
		ORDER BY timestamp DESC 
		LIMIT 100
	`

	rows, err := f.db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var alerts []map[string]interface{}
	for rows.Next() {
		var timestamp, eventType, sourceIP, severity, description string
		if err := rows.Scan(&timestamp, &eventType, &sourceIP, &severity, &description); err != nil {
			continue
		}

		alerts = append(alerts, map[string]interface{}{
			"timestamp":   timestamp,
			"type":        eventType,
			"source_ip":   sourceIP,
			"severity":    severity,
			"description": description,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(alerts)
}

func (f *SSHSecurityFilter) handleHoneypot(w http.ResponseWriter, r *http.Request) {
	f.honeypot.mu.RLock()
	defer f.honeypot.mu.RUnlock()

	honeypotData := map[string]interface{}{
		"total_interactions": len(f.honeypot.interactions),
		"attacker_profiles":  len(f.honeypot.attackerProfiles),
		"recent_commands":    f.getRecentHoneypotCommands(),
		"top_attackers":      f.getTopAttackers(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(honeypotData)
}

func (f *SSHSecurityFilter) getRecentHoneypotCommands() []string {
	commands := make([]string, 0)
	count := 0
	
	for _, interactions := range f.honeypot.interactions {
		for i := len(interactions) - 1; i >= 0 && count < 50; i-- {
			commands = append(commands, interactions[i].Command)
			count++
		}
		if count >= 50 {
			break
		}
	}
	
	return commands
}

func (f *SSHSecurityFilter) getTopAttackers() []map[string]interface{} {
	attackers := make([]map[string]interface{}, 0)
	
	for ip, profile := range f.honeypot.attackerProfiles {
		attackers = append(attackers, map[string]interface{}{
			"ip":            ip,
			"interactions":  profile.Interactions,
			"threat_level":  profile.ThreatLevel,
			"first_contact": profile.FirstContact,
			"last_contact":  profile.LastContact,
		})
	}
	
	// Sort by threat level
	sort.Slice(attackers, func(i, j int) bool {
		return attackers[i]["threat_level"].(int) > attackers[j]["threat_level"].(int)
	})
	
	if len(attackers) > 20 {
		attackers = attackers[:20]
	}
	
	return attackers
}

// System integration functions
func (f *SSHSecurityFilter) InstallSystemService() error {
	serviceContent := `[Unit]
Description=SSH Layer-7 Security Filter
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ssh-l7-filter -config /etc/ssh-l7-filter/config.yaml
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

	if err := os.WriteFile("/etc/systemd/system/ssh-l7-filter.service", []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %v", err)
	}

	// Create config directory
	if err := os.MkdirAll("/etc/ssh-l7-filter", 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Install default config
	defaultConfig := getDefaultConfig()
	configData, _ := yaml.Marshal(defaultConfig)
	if err := os.WriteFile("/etc/ssh-l7-filter/config.yaml", configData, 0644); err != nil {
		return fmt.Errorf("failed to install config: %v", err)
	}

	// Enable and start service
	exec.Command("systemctl", "daemon-reload").Run()
	exec.Command("systemctl", "enable", "ssh-l7-filter").Run()

	return nil
}

func (f *SSHSecurityFilter) UpdateThreatDatabases() error {
	f.logger.Log("INFO", "Updating threat databases", "", 0, "UPDATE", nil)
	
	// Force update all threat intelligence
	f.updateTorNodes()
	f.updateVPNRanges()
	f.updateThreatFeeds()
	
	// Update GeoIP database (would use MaxMind in production)
	if f.config.Intelligence.MaxMindKey != "" {
		f.updateMaxMindDB()
	}
	
	f.threatIntel.lastUpdate = time.Now()
	f.logger.Log("INFO", "Threat databases updated", "", 0, "UPDATE", nil)
	
	return nil
}

func (f *SSHSecurityFilter) updateMaxMindDB() {
	// In production, this would download and update MaxMind GeoIP database
	f.logger.Log("INFO", "MaxMind GeoIP database update would occur here", "", 0, "INFO", nil)
}

// Security audit functions
func (f *SSHSecurityFilter) RunSecurityAudit() (map[string]interface{}, error) {
	audit := map[string]interface{}{
		"timestamp": time.Now(),
		"version":   "1.0.0",
		"checks":    make(map[string]interface{}),
	}

	checks := audit["checks"].(map[string]interface{})

	// Check configuration security
	checks["config_security"] = f.auditConfiguration()
	
	// Check database security
	checks["database_security"] = f.auditDatabase()
	
	// Check ML model performance
	checks["ml_performance"] = f.auditMLModel()
	
	// Check threat intelligence freshness
	checks["threat_intel"] = f.auditThreatIntelligence()
	
	// Check system resources
	checks["system_resources"] = f.auditSystemResources()

	return audit, nil
}

func (f *SSHSecurityFilter) auditConfiguration() map[string]interface{} {
	issues := make([]string, 0)
	score := 100

	// Check for weak settings
	if f.config.Security.MaxFailures > 5 {
		issues = append(issues, "MaxFailures too high (>5)")
		score -= 10
	}

	if f.config.Security.BanDuration < 3600 {
		issues = append(issues, "BanDuration too low (<1 hour)")
		score -= 15
	}

	if !f.config.Security.BlockTor {
		issues = append(issues, "Tor blocking disabled")
		score -= 20
	}

	if !f.config.Security.HoneypotEnabled {
		issues = append(issues, "Honeypot disabled")
		score -= 10
	}

	if f.config.Security.MinKeySize < 2048 {
		issues = append(issues, "Minimum key size too low (<2048)")
		score -= 25
	}

	return map[string]interface{}{
		"score":  score,
		"issues": issues,
		"status": f.getStatusFromScore(score),
	}
}

func (f *SSHSecurityFilter) auditDatabase() map[string]interface{} {
	issues := make([]string, 0)
	score := 100

	// Check database file permissions
	if info, err := os.Stat(f.config.Database.Path); err == nil {
		if info.Mode().Perm() != 0600 {
			issues = append(issues, "Database file permissions too permissive")
			score -= 30
		}
	}

	// Check database size
	var count int
	f.db.QueryRow("SELECT COUNT(*) FROM connections").Scan(&count)
	if count > 1000000 {
		issues = append(issues, "Database growing too large, cleanup needed")
		score -= 10
	}

	return map[string]interface{}{
		"score":       score,
		"issues":      issues,
		"status":      f.getStatusFromScore(score),
		"connections": count,
	}
}

func (f *SSHSecurityFilter) auditMLModel() map[string]interface{} {
	f.mlModel.mu.RLock()
	defer f.mlModel.mu.RUnlock()

	issues := make([]string, 0)
	score := 100

	if !f.config.ML.Enabled {
		issues = append(issues, "ML anomaly detection disabled")
		score -= 50
	} else {
		if f.mlModel.accuracy < 0.8 {
			issues = append(issues, "ML model accuracy too low (<80%)")
			score -= 30
		}

		if f.mlModel.falsePositiveRate > 0.1 {
			issues = append(issues, "ML model false positive rate too high (>10%)")
			score -= 20
		}

		if time.Since(f.mlModel.lastTrained) > 24*time.Hour {
			issues = append(issues, "ML model not recently trained")
			score -= 15
		}
	}

	return map[string]interface{}{
		"score":               score,
		"issues":              issues,
		"status":              f.getStatusFromScore(score),
		"accuracy":            f.mlModel.accuracy,
		"false_positive_rate": f.mlModel.falsePositiveRate,
		"last_trained":        f.mlModel.lastTrained,
	}
}

func (f *SSHSecurityFilter) auditThreatIntelligence() map[string]interface{} {
	f.threatIntel.mu.RLock()
	defer f.threatIntel.mu.RUnlock()

	issues := make([]string, 0)
	score := 100

	if time.Since(f.threatIntel.lastUpdate) > 6*time.Hour {
		issues = append(issues, "Threat intelligence data stale (>6 hours)")
		score -= 20
	}

	if len(f.threatIntel.torNodes) == 0 && f.config.Security.BlockTor {
		issues = append(issues, "No Tor nodes in database but Tor blocking enabled")
		score -= 30
	}

	if len(f.threatIntel.vpnRanges) == 0 && f.config.Security.BlockVPN {
		issues = append(issues, "No VPN ranges in database but VPN blocking enabled")
		score -= 30
	}

	return map[string]interface{}{
		"score":        score,
		"issues":       issues,
		"status":       f.getStatusFromScore(score),
		"tor_nodes":    len(f.threatIntel.torNodes),
		"vpn_ranges":   len(f.threatIntel.vpnRanges),
		"malicious_ips": len(f.threatIntel.maliciousIPs),
		"last_update":  f.threatIntel.lastUpdate,
	}
}

func (f *SSHSecurityFilter) auditSystemResources() map[string]interface{} {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	issues := make([]string, 0)
	score := 100

	// Check memory usage
	memoryMB := float64(m.Alloc) / 1024 / 1024
	if memoryMB > 500 {
		issues = append(issues, "High memory usage (>500MB)")
		score -= 20
	}

	// Check goroutine count
	goroutines := runtime.NumGoroutine()
	if goroutines > 1000 {
		issues = append(issues, "High goroutine count (>1000)")
		score -= 15
	}

	// Check database connections
	dbStats := f.db.Stats()
	if dbStats.OpenConnections > f.config.Database.MaxConnections {
		issues = append(issues, "Database connection limit exceeded")
		score -= 25
	}

	return map[string]interface{}{
		"score":              score,
		"issues":             issues,
		"status":             f.getStatusFromScore(score),
		"memory_mb":          memoryMB,
		"goroutines":         goroutines,
		"db_connections":     dbStats.OpenConnections,
		"max_db_connections": f.config.Database.MaxConnections,
	}
}

func (f *SSHSecurityFilter) getStatusFromScore(score int) string {
	if score >= 90 {
		return "EXCELLENT"
	} else if score >= 80 {
		return "GOOD"
	} else if score >= 70 {
		return "FAIR"
	} else if score >= 60 {
		return "POOR"
	} else {
		return "CRITICAL"
	}
}

// Performance benchmarking
func (f *SSHSecurityFilter) RunBenchmark() (map[string]interface{}, error) {
	benchmark := map[string]interface{}{
		"timestamp": time.Now(),
		"tests":     make(map[string]interface{}),
	}

	tests := benchmark["tests"].(map[string]interface{})

	// Benchmark packet processing
	tests["packet_processing"] = f.benchmarkPacketProcessing()
	
	// Benchmark ML prediction
	tests["ml_prediction"] = f.benchmarkMLPrediction()
	
	// Benchmark database operations
	tests["database_ops"] = f.benchmarkDatabaseOps()
	
	// Benchmark threat intelligence lookup
	tests["threat_lookup"] = f.benchmarkThreatLookup()

	return benchmark, nil
}

func (f *SSHSecurityFilter) benchmarkPacketProcessing() map[string]interface{} {
	// Create test packets
	testPackets := make([]SSHPacket, 1000)
	for i := range testPackets {
		testPackets[i] = SSHPacket{
			Type:      SSH_MSG_KEXINIT,
			Length:    uint32(100 + i%500),
			Payload:   make([]byte, 100+i%500),
			Timestamp: time.Now(),
		}
		rand.Read(testPackets[i].Payload)
	}

	start := time.Now()
	processed := 0
	
	for _, packet := range testPackets {
		if f.analyzeSuspiciousPatterns(&packet) {
			processed++
		}
	}
	
	duration := time.Since(start)
	packetsPerSecond := float64(len(testPackets)) / duration.Seconds()

	return map[string]interface{}{
		"packets_tested":     len(testPackets),
		"suspicious_found":   processed,
		"duration_ms":        duration.Milliseconds(),
		"packets_per_second": packetsPerSecond,
	}
}

func (f *SSHSecurityFilter) benchmarkMLPrediction() map[string]interface{} {
	if !f.config.ML.Enabled {
		return map[string]interface{}{
			"error": "ML disabled",
		}
	}

	// Create test features
	testFeatures := make([]FeatureVector, 1000)
	for i := range testFeatures {
		testFeatures[i] = FeatureVector{
			ConnectionTime:   mathrand.Float64() * 100,
			AuthAttempts:     mathrand.Float64() * 5,
			PayloadEntropy:   mathrand.Float64() * 8,
			ProtocolVersion:  2.0,
			CipherSuite:      mathrand.Float64() * 3,
			CompressionRatio: mathrand.Float64(),
			BehaviorPattern:  mathrand.Float64(),
		}
	}

	start := time.Now()
	totalScore := 0.0
	
	for _, features := range testFeatures {
		score := f.mlModel.Predict(features)
		totalScore += score
	}
	
	duration := time.Since(start)
	predictionsPerSecond := float64(len(testFeatures)) / duration.Seconds()

	return map[string]interface{}{
		"predictions_made":      len(testFeatures),
		"average_score":         totalScore / float64(len(testFeatures)),
		"duration_ms":           duration.Milliseconds(),
		"predictions_per_second": predictionsPerSecond,
	}
}

func (f *SSHSecurityFilter) benchmarkDatabaseOps() map[string]interface{} {
	start := time.Now()
	
	// Test inserts
	for i := 0; i < 100; i++ {
		query := `INSERT INTO connections (remote_addr, threat_score, blocked) VALUES (?, ?, ?)`
		f.db.Exec(query, fmt.Sprintf("192.168.1.%d", i), mathrand.Float64(), mathrand.Intn(2) == 1)
	}
	
	insertDuration := time.Since(start)
	
	start = time.Now()
	
	// Test selects
	for i := 0; i < 100; i++ {
		query := `SELECT COUNT(*) FROM connections WHERE remote_addr LIKE ?`
		var count int
		f.db.QueryRow(query, "192.168.1.%").Scan(&count)
	}
	
	selectDuration := time.Since(start)

	return map[string]interface{}{
		"insert_duration_ms": insertDuration.Milliseconds(),
		"select_duration_ms": selectDuration.Milliseconds(),
		"inserts_per_second": 100.0 / insertDuration.Seconds(),
		"selects_per_second": 100.0 / selectDuration.Seconds(),
	}
}

func (f *SSHSecurityFilter) benchmarkThreatLookup() map[string]interface{} {
	// Test IPs
	testIPs := make([]string, 1000)
	for i := range testIPs {
		testIPs[i] = fmt.Sprintf("192.168.%d.%d", mathrand.Intn(255), mathrand.Intn(255))
	}

	start := time.Now()
	torHits := 0
	vpnHits := 0
	threatHits := 0
	
	f.threatIntel.mu.RLock()
	for _, ip := range testIPs {
		if f.threatIntel.torNodes[ip] {
			torHits++
		}
		
		clientIP := net.ParseIP(ip)
		for _, vpnRange := range f.threatIntel.vpnRanges {
			if vpnRange.Contains(clientIP) {
				vpnHits++
				break
			}
		}
		
		if _, exists := f.threatIntel.maliciousIPs[ip]; exists {
			threatHits++
		}
	}
	f.threatIntel.mu.RUnlock()
	
	duration := time.Since(start)
	lookupsPerSecond := float64(len(testIPs)) / duration.Seconds()

	return map[string]interface{}{
		"ips_tested":         len(testIPs),
		"tor_hits":          torHits,
		"vpn_hits":          vpnHits,
		"threat_hits":       threatHits,
		"duration_ms":       duration.Milliseconds(),
		"lookups_per_second": lookupsPerSecond,
	}
}

// Main function and CLI
func main() {
	var (
		configPath    = flag.String("config", "", "Path to configuration file")
		install       = flag.Bool("install", false, "Install as system service")
		audit         = flag.Bool("audit", false, "Run security audit")
		benchmark     = flag.Bool("benchmark", false, "Run performance benchmark")
		updateThreats = flag.Bool("update-threats", false, "Update threat databases")
		apiOnly       = flag.Bool("api-only", false, "Start only management API")
		version       = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *version {
		fmt.Println("SSH Layer-7 Security Filter v1.0.0")
		fmt.Println("Ultra-Advanced SSH Security Filter with Military-Grade Protection")
		fmt.Println("Features: ML Anomaly Detection, Behavioral Analysis, Honeypot, Deep Packet Inspection")
		return
	}

	// Initialize the filter
	filter, err := NewSSHSecurityFilter(*configPath)
	if err != nil {
		log.Fatalf("Failed to initialize SSH filter: %v", err)
	}

	if *install {
		if err := filter.InstallSystemService(); err != nil {
			log.Fatalf("Failed to install system service: %v", err)
		}
		fmt.Println("SSH L7 Filter installed as system service")
		fmt.Println("Use 'systemctl start ssh-l7-filter' to start the service")
		return
	}

	if *audit {
		auditResult, err := filter.RunSecurityAudit()
		if err != nil {
			log.Fatalf("Security audit failed: %v", err)
		}
		
		auditJSON, _ := json.MarshalIndent(auditResult, "", "  ")
		fmt.Println(string(auditJSON))
		return
	}

	if *benchmark {
		benchmarkResult, err := filter.RunBenchmark()
		if err != nil {
			log.Fatalf("Benchmark failed: %v", err)
		}
		
		benchmarkJSON, _ := json.MarshalIndent(benchmarkResult, "", "  ")
		fmt.Println(string(benchmarkJSON))
		return
	}

	if *updateThreats {
		if err := filter.UpdateThreatDatabases(); err != nil {
			log.Fatalf("Failed to update threat databases: %v", err)
		}
		fmt.Println("Threat databases updated successfully")
		return
	}

	// Start management API
	filter.StartManagementAPI()

	if *apiOnly {
		fmt.Println("Management API running on :8080")
		fmt.Println("Press Ctrl+C to exit")
		
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		return
	}

	// Start the main filter
	fmt.Printf("Starting SSH L7 Security Filter on %s\n", filter.config.Server.ListenAddr)
	fmt.Printf("SSH server port: %d\n", filter.config.Server.SSHPort)
	fmt.Printf("Management API: http://localhost:8080/api/stats\n")
	fmt.Printf("Configuration: %s\n", *configPath)
	
	if err := filter.Start(); err != nil {
		log.Fatalf("Failed to start SSH filter: %v", err)
	}
}
