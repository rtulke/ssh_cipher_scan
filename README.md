# SSH Algorithm Security Scanner - Complete Configuration File
# This file demonstrates all available configuration options with detailed explanations

# ====================================================================
# SCANNER CONFIGURATION - Core scanning behavior settings
# ====================================================================
[scanner]
# Number of concurrent scanning threads (1-500)
# Higher values = faster scanning but more resource usage
# Recommended: 20-50 for most networks, 100+ for high-performance scans
threads = 30

# Connection timeout in seconds (1-120)
# How long to wait for SSH connections before giving up
# Recommended: 10s for reliable networks, 20-30s for slow/unreliable networks
timeout = 15

# Enable SSH connection multiplexing for better performance (true/false)
# Reuses SSH connections for multiple algorithm tests (80-90% faster)
# Disable only if experiencing connection issues with specific SSH servers
use_multiplexing = true

# Number of retry attempts for failed connections (1-10)
# How many times to retry failed connections with exponential backoff
# Higher values = more resilient to network issues but slower on persistent failures
retry_attempts = 3

# DNS cache TTL in seconds (60-3600)
# How long to cache DNS lookups to avoid redundant queries
# Recommended: 300s (5 min) for most cases, 600s+ for large batch scans
dns_cache_ttl = 600

# Enable advanced cryptographic analysis (requires 'cryptography' library)
# Provides detailed algorithm strength analysis and vulnerability detection
enable_crypto_analysis = false

# Maximum number of simultaneous DNS lookups (1-100)
# Limits concurrent DNS queries to avoid overwhelming DNS servers
max_dns_queries = 20

# ====================================================================
# COMPLIANCE FRAMEWORKS - Security standard compliance checking
# ====================================================================
[compliance]
# Primary compliance framework to check against
# Available frameworks:
#   - NIST: NIST Cybersecurity Framework (balanced, widely adopted)
#   - FIPS_140_2: FIPS 140-2 Level 1 (US Federal standard, strict)
#   - BSI_TR_02102: German BSI TR-02102-4 (European standard, very strict)
#   - ANSSI: French ANSSI guidelines (highest security, most restrictive)
#   - PRIVACY_FOCUSED: Anti-surveillance framework (excludes NSA-suspicious algorithms)
framework = "NIST"

# Minimum acceptable security score (0-100)
# Hosts below this score will be flagged as non-compliant
# NIST: 80, FIPS: 90, BSI: 85, ANSSI: 95, Privacy: 90
minimum_score = 80

# Fail entire scan if any host is non-compliant (true/false)
# When true, scanner exits with error code if compliance violations found
fail_on_non_compliance = false

# Additional compliance checks to perform alongside primary framework
# Can specify multiple frameworks for comprehensive compliance checking
additional_frameworks = ["PRIVACY_FOCUSED"]

# Custom compliance rules (advanced users)
[compliance.custom_rules]
# Require specific algorithms to be present
required_ciphers = ["aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com"]
required_kex = ["curve25519-sha256"]
required_hostkey = ["ssh-ed25519"]

# Explicitly forbidden algorithms (overrides framework defaults)
forbidden_ciphers = ["des", "3des-cbc", "arcfour"]
forbidden_kex = ["diffie-hellman-group1-sha1"]
forbidden_hostkey = ["ssh-dss"]

# Maximum allowed algorithm age in years (0 = no limit)
max_algorithm_age = 10

# Require forward secrecy support
require_forward_secrecy = true

# ====================================================================
# ALGORITHM TESTING - What algorithms to test and how
# ====================================================================
[algorithms]
# Specific algorithms to test (empty = test all available)
# When specified, only these algorithms will be tested (much faster)
# Example: explicit_test = ["aes256-gcm@openssh.com", "ssh-ed25519"]
explicit_test = []

# Test for weak/deprecated algorithms specifically
# These will be flagged with high priority in reports
check_weak = [
    # Weak encryption algorithms
    "des", "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    
    # Weak MAC algorithms  
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64",
    
    # Weak key exchange
    "diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
    
    # Weak host key algorithms
    "ssh-dss", "ssh-rsa"
]

# Test for NSA-suspicious algorithms (potential backdoors)
check_nsa_suspicious = [
    # NIST curve-based algorithms (NSA involvement suspected)
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"
]

# Preferred strong algorithms (recommended for secure deployments)
preferred_strong = [
    # Modern encryption (authenticated encryption preferred)
    "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    
    # Secure key exchange (independently developed curves)
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    
    # Modern MAC (Encrypt-then-MAC preferred)
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    
    # Secure host keys (Ed25519 preferred)
    "ssh-ed25519"
]

# Enable post-quantum cryptography analysis
# Identifies algorithms vulnerable to quantum computer attacks
check_quantum_resistance = true

# Algorithm categories to test (all enabled by default)
[algorithms.categories]
encryption = true      # Test symmetric encryption algorithms
mac = true            # Test message authentication codes
kex = true            # Test key exchange algorithms
hostkey = true        # Test host key algorithms

# ====================================================================
# OUTPUT CONFIGURATION - How results are formatted and displayed
# ====================================================================
[output]
# Default output format for results
# Available formats:
#   - table: Human-readable ASCII table (best for terminal viewing)
#   - json: Structured JSON data (best for programmatic processing)
#   - csv: Comma-separated values (best for spreadsheet import)
#   - yaml: YAML format (best for configuration management)
format = "table"

# Include detailed algorithm information in output
include_algorithms = true

# Include SSH server banners in output
# Useful for identifying server software and versions
include_banners = true

# Include timing information for performance analysis
include_timing = true

# Include compliance checking results
include_compliance = true

# Include NSA backdoor risk analysis
include_nsa_analysis = true

# Show only failed/risky hosts (filter out compliant hosts)
show_only_risks = false

# Maximum number of algorithms to show per host in table format
max_algorithms_display = 5

# Truncate long hostnames to specified length (0 = no truncation)
max_hostname_length = 20

# Color output for terminal display (auto/always/never)
# auto: enable if terminal supports colors
color_output = "auto"

# Sort output by specified field
# Options: host, port, security_score, compliance_status, nsa_risk
sort_by = "security_score"

# Sort direction (asc/desc)
sort_direction = "desc"

# ====================================================================
# NETWORK CONFIGURATION - Network-related settings
# ====================================================================
[network]
# Default SSH port to use when not specified
default_port = 22

# Timeout for SSH banner grabbing in seconds
banner_timeout = 5

# Timeout for establishing SSH multiplexing master connection
multiplex_timeout = 10

# Connection timeout for individual algorithm tests
algorithm_test_timeout = 8

# Network interface to bind to (leave empty for default)
# Useful for multi-homed systems or specific routing requirements
bind_interface = ""

# Source IP address to use for connections (leave empty for default)
source_ip = ""

# Enable IPv6 support alongside IPv4
enable_ipv6 = true

# Prefer IPv4 over IPv6 when both are available
prefer_ipv4 = true

# Maximum number of connection attempts per host
max_connection_attempts = 3

# ====================================================================
# LOGGING CONFIGURATION - Log levels and destinations
# ====================================================================
[logging]
# Log level for console output
# Options: DEBUG, INFO, WARNING, ERROR, CRITICAL
level = "INFO"

# Log to file (specify path, leave empty to disable file logging)
# Useful for audit trails and debugging
file = ""

# Include timestamps in console output
timestamps = false

# Enable verbose SSH debugging (very noisy, use only for troubleshooting)
ssh_debug = false

# Log DNS cache statistics
log_dns_stats = true

# Log performance metrics
log_performance = true

# Maximum log file size in MB (0 = unlimited)
max_log_size = 100

# Number of log files to rotate (0 = no rotation)
log_rotation_count = 5

# ====================================================================
# HOST LISTS - Pre-defined host groups for common scanning scenarios
# ====================================================================
[hosts]
# Pre-defined host lists for different environments
# Reference these with --hostlist parameter

# Production environment servers
# production = "/etc/ssh-scanner/prod_hosts.yaml"

# Development environment servers  
# development = "/etc/ssh-scanner/dev_hosts.json"

# DMZ and externally-facing servers
# dmz = "/etc/ssh-scanner/dmz_hosts.csv"

# Critical infrastructure servers
# critical = "/etc/ssh-scanner/critical_hosts.txt"

# Example inline host definitions
[hosts.inline]
# Web servers cluster
web_servers = [
    "web1.example.com:22",
    "web2.example.com:22", 
    "web3.example.com:8022"
]

# Database servers
db_servers = [
    {host = "db1.example.com", port = 22},
    {host = "db2.example.com", port = 2222}
]

# ====================================================================
# REPORTING CONFIGURATION - Report generation and content
# ====================================================================
[reporting]
# Generate executive summary suitable for management
executive_summary = true

# Include detailed security recommendations
include_recommendations = true

# Generate compliance assessment report
compliance_report = true

# Include risk scoring analysis
risk_scoring = true

# Generate algorithm migration recommendations
migration_recommendations = true

# Include vulnerability assessment
vulnerability_assessment = true

# Report template format (html/markdown/text)
template_format = "markdown"

# Custom report sections to include
sections = [
    "executive_summary",
    "security_overview", 
    "compliance_assessment",
    "nsa_backdoor_analysis",
    "algorithm_recommendations",
    "vulnerability_details",
    "migration_timeline",
    "appendix"
]

# Include charts and graphs (requires matplotlib)
include_charts = false

# Report output directory
output_directory = "./reports"

# Automatically timestamp report filenames
timestamp_reports = true

# ====================================================================
# PERFORMANCE TUNING - Advanced performance optimization
# ====================================================================
[performance]
# Enable connection pooling for repeated scans of same hosts
enable_connection_pooling = true

# Maximum number of pooled connections per host
max_pooled_connections = 5

# Connection pool timeout in seconds
pool_timeout = 30

# Enable algorithm result caching
enable_algorithm_caching = true

# Algorithm cache TTL in seconds
algorithm_cache_ttl = 3600

# Optimize for memory usage vs speed (memory/speed/balanced)
optimization_mode = "balanced"

# Pre-allocate result structures for better memory performance
preallocate_results = true

# ====================================================================
# SECURITY CONFIGURATION - Scanner security settings
# ====================================================================
[security]
# Enable NSA backdoor analysis by default
enable_nsa_analysis = true

# Prioritize algorithms without government involvement
prefer_independent_crypto = true

# Warn about algorithms with intelligence agency connections
warn_government_involvement = true

# Check algorithms against known CVE database
check_cve_vulnerabilities = false

# Minimum acceptable encryption key length in bits
min_encryption_bits = 128

# Minimum acceptable hash length in bits  
min_hash_bits = 256

# Require perfect forward secrecy
require_pfs = false

# Check for deprecated algorithms based on date
check_deprecation_dates = true

# ====================================================================
# ALERTING CONFIGURATION - Notifications and thresholds
# ====================================================================
[alerting]
# Enable alerting system
enabled = false

# Alert thresholds
[alerting.thresholds]
# Minimum security score before alerting
min_security_score = 70

# Maximum number of NSA-suspicious algorithms before alerting
max_nsa_algorithms = 0

# Maximum number of weak algorithms before alerting
max_weak_algorithms = 2

# Compliance failure threshold (percentage of non-compliant hosts)
compliance_failure_threshold = 10

# Alert destinations
[alerting.destinations]
# Webhook URLs for alert notifications
# webhooks = ["https://hooks.slack.com/services/..."]

# Email addresses for alerts
# emails = ["security@example.com", "admin@example.com"]

# Log file for alerts
# log_file = "/var/log/ssh-scanner-alerts.log"

# ====================================================================
# INTEGRATION CONFIGURATION - External system integration
# ====================================================================
[integration]
# Enable REST API server mode
api_server = false

# API server port
api_port = 8080

# API authentication token
# api_token = "your-secure-token-here"

# Export results to external systems
[integration.export]
# InfluxDB integration for metrics
# influxdb_url = "http://localhost:8086"
# influxdb_database = "ssh_security"

# Prometheus metrics endpoint
prometheus_metrics = false

# Syslog integration
# syslog_server = "syslog.example.com:514"

# ====================================================================
# ADVANCED CONFIGURATION - Expert-level settings
# ====================================================================
[advanced]
# Custom SSH client path (leave empty for system default)
ssh_client_path = ""

# Additional SSH client options
ssh_extra_options = []

# Custom algorithm definitions file
# algorithm_definitions = "/etc/ssh-scanner/custom_algorithms.yaml"

# Enable experimental features (may be unstable)
enable_experimental = false

# Custom compliance framework definitions
# custom_frameworks = "/etc/ssh-scanner/custom_frameworks.toml"

# Plugin directory for custom extensions
# plugin_directory = "/usr/local/lib/ssh-scanner/plugins"

# Maximum memory usage in MB (0 = unlimited)
max_memory_usage = 0

# Garbage collection frequency (scans between GC runs)
gc_frequency = 100

# ====================================================================
# EXAMPLES AND TEMPLATES
# ====================================================================

# Example: High-security government configuration
[examples.government]
framework = "FIPS_140_2"
minimum_score = 95
fail_on_non_compliance = true
enable_nsa_analysis = true
check_cve_vulnerabilities = true
require_pfs = true

# Example: Enterprise corporate configuration  
[examples.corporate]
framework = "NIST"
minimum_score = 80
threads = 50
include_recommendations = true
executive_summary = true

# Example: Privacy-focused configuration
[examples.privacy]
framework = "PRIVACY_FOCUSED"
minimum_score = 90
enable_nsa_analysis = true
prefer_independent_crypto = true
warn_government_involvement = true

# Example: Performance-optimized configuration
[examples.performance]
threads = 100
use_multiplexing = true
enable_connection_pooling = true
optimization_mode = "speed"
algorithm_cache_ttl = 7200
