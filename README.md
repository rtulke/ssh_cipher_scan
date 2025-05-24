# SSH Algorithm Security Scanner

A comprehensive Python tool for SSH security auditing with advanced features including SSH multiplexing, compliance frameworks, TOML configuration, retry logic, DNS caching, and NSA backdoor detection.

## 🚀 Key Features

### Performance Enhancements
- **SSH Multiplexing**: 80-90% faster scanning through connection reuse
- **DNS Caching**: Eliminates redundant DNS lookups with TTL-based caching
- **Retry Logic**: Exponential backoff for robust connection handling
- **Multi-threaded Architecture**: Configurable concurrent scans (default: 20 threads)

### Security Analysis
- **Compliance Frameworks**: NIST, FIPS 140-2, BSI TR-02102, ANSSI, Privacy-Focused support
- **Security Scoring**: Algorithm strength analysis (0-100 scale)
- **NSA Backdoor Detection**: Identifies SSH algorithms with potential NSA involvement
- **Weak Algorithm Detection**: Flags outdated and insecure algorithms

### Configuration & Flexibility
- **TOML Configuration**: Simple configuration file support
- **Multiple Input Formats**: JSON, YAML, CSV, TXT host lists
- **Multiple Output Formats**: Table, JSON, CSV, YAML
- **Explicit Algorithm Testing**: Test specific algorithms only

## 📦 Installation

### Quick Installation (Debian/Ubuntu)
```bash
# Install dependencies
sudo apt update && apt upgrade -y
sudo apt install python3-toml python3-yaml git -y

# Clone Repository
git clone https://github.com/rtulke/sshscan.git
cd sshscan

# Make executable
chmod +x sshscan.py

# Create configuration directory
mkdir -p ~/.sshscan
```

### Developer Installation (Virtual Environment)
```bash
# Clone Repository
git clone https://github.com/rtulke/sshscan.git
cd sshscan

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run the scanner
python3 ./sshscan.py --help
```

## 🔧 Configuration

### TOML Configuration File
Create a `config.toml` file with the following options:

```toml
# SSH Scanner Configuration
[scanner]
threads = 30              # Number of concurrent threads (1-500)
timeout = 15              # Connection timeout in seconds
use_multiplexing = true   # Enable SSH multiplexing
retry_attempts = 3        # Retry attempts for failed connections
dns_cache_ttl = 600       # DNS cache TTL in seconds

[compliance]
# Available frameworks: NIST, FIPS_140_2, BSI_TR_02102, ANSSI, PRIVACY_FOCUSED
framework = "NIST"
```

### Using Configuration Files
```bash
# Use configuration file
python3 sshscan.py --config config.toml --file servers.txt

# Override specific settings
python3 sshscan.py --config config.toml --threads 50 --timeout 20
```

## 📊 Compliance Frameworks

### Available Frameworks

| Framework | Description | Strictness |
|-----------|-------------|------------|
| `NIST` | NIST Cybersecurity Framework | Balanced |
| `FIPS_140_2` | FIPS 140-2 Level 1 | Strict |
| `BSI_TR_02102` | BSI TR-02102-4 (German Federal) | Very Strict |
| `ANSSI` | French National Cybersecurity | Highest |
| `PRIVACY_FOCUSED` | Anti-surveillance framework | NSA-aware |

### Framework Usage
```bash
# List all frameworks
python3 sshscan.py --list-frameworks

# Scan with specific framework
python3 sshscan.py --host example.com --compliance NIST

# Privacy-focused scan (excludes NSA-suspicious algorithms)
python3 sshscan.py --file hosts.txt --compliance PRIVACY_FOCUSED
```

## 🔍 NSA Backdoor Detection

The scanner automatically detects algorithms with suspected NSA involvement:

### High-Risk Algorithms (NIST Curves)
- **Key Exchange**: `ecdh-sha2-nistp256`, `ecdh-sha2-nistp384`, `ecdh-sha2-nistp521`
- **Host Keys**: `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, `ecdsa-sha2-nistp521`

### Recommended Alternatives
- **Key Exchange**: `curve25519-sha256`
- **Host Keys**: `ssh-ed25519`
- **Encryption**: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`

## 📈 Usage Examples

### Basic Scanning
```bash
# Scan single host
python3 sshscan.py --host example.com

# Scan multiple hosts
python3 sshscan.py --host "server1.com,server2.com:2222,192.168.1.10"

# Scan from file
python3 sshscan.py --file hosts.txt
```

### Performance Tuning
```bash
# High-performance scan (50 threads, multiplexing enabled)
python3 sshscan.py --file large_network.txt --threads 50

# Conservative scan (5 threads, longer timeout)
python3 sshscan.py --file hosts.txt --threads 5 --timeout 30

# Disable multiplexing for compatibility
python3 sshscan.py --host example.com --no-multiplex
```

### Explicit Algorithm Testing
```bash
# Test specific algorithms only
python3 sshscan.py --host example.com \
  --explicit "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"

# Test for weak algorithms
python3 sshscan.py --file hosts.txt \
  --explicit "3des-cbc,des,arcfour,hmac-md5"
```

### Compliance Checking
```bash
# NIST compliance check
python3 sshscan.py --file servers.txt --compliance NIST

# Privacy-focused scan with JSON output
python3 sshscan.py --file hosts.yaml --compliance PRIVACY_FOCUSED \
  --format json --output privacy_audit.json
```

## 📄 Input File Formats

### JSON Format (`hosts.json`)
```json
[
  {"host": "server1.example.com", "port": 22},
  {"host": "server2.example.com", "port": 2222},
  "server3.example.com:22",
  "192.168.1.100"
]
```

### YAML Format (`hosts.yaml`)
```yaml
- host: server1.example.com
  port: 22
- host: server2.example.com
  port: 2222
- server3.example.com:22
- 192.168.1.100
```

### CSV Format (`hosts.csv`)
```csv
server1.example.com,22
server2.example.com,2222
192.168.1.100,22
```

### Text Format (`hosts.txt`)
```
server1.example.com:22
server2.example.com:2222
192.168.1.100
# Comments are supported
another-server.com:2222
```

## 📊 Output Formats

### Table Format (Default)
```
+------------------+------+---------+----------+-----------+------------+----------------------------+--------+
| Host             | Port | Status  | Security | Compliance| NSA Risk   | Banner                     | Time(s)|
+------------------+------+---------+----------+-----------+------------+----------------------------+--------+
| prod-web1.com    | 22   | success | 95/100   | ✓ PASS    | ✓ LOW      | SSH-2.0-OpenSSH_9.3p1      | 1.2    |
| legacy-db.com    | 22   | success | 35/100   | ✗ FAIL    | ⚠️  2 HIGH | SSH-2.0-OpenSSH_6.6.1      | 2.8    |
+------------------+------+---------+----------+-----------+------------+----------------------------+--------+
```

### JSON Format
```bash
python3 sshscan.py --file hosts.txt --format json --output results.json
```

### CSV Format
```bash
python3 sshscan.py --file hosts.txt --format csv --output results.csv
```

### YAML Format
```bash
python3 sshscan.py --file hosts.txt --format yaml --output results.yaml
```

## 🛡️ Security Scoring

The scanner evaluates algorithm strength on a 0-100 scale:

| Score Range | Rating | Description |
|-------------|--------|-------------|
| 90-100 | Excellent | Modern algorithms only |
| 70-89 | Good | Mostly modern, few legacy |
| 50-69 | Fair | Mixed modern/legacy |
| 30-49 | Poor | Many weak algorithms |
| 0-29 | Critical | Predominantly weak |

### Detected Weak Algorithms
- **Encryption**: DES, 3DES-CBC, Arcfour, CBC modes
- **MAC**: HMAC-MD5, HMAC-SHA1-96, UMAC-64
- **Key Exchange**: DH-Group1, DH-Group14-SHA1
- **Host Keys**: DSA, RSA

## ⚡ Performance Characteristics

### Typical Performance Metrics
| Scenario | Performance |
|----------|------------|
| Single host (full scan) | 1-3 seconds |
| 50 hosts with 20 threads | ~1 minute |
| 1000 hosts with multiplexing | ~45 minutes |
| 1000 hosts without multiplexing | ~13 hours |

### DNS Cache Performance
- Hit rate typically > 90% for domain-heavy lists
- Reduces DNS queries by 95%+ for repeated domains
- Configurable TTL (default: 600 seconds)

## 🔧 Complete Command Reference

```
python3 sshscan.py [OPTIONS]

Configuration:
  --config, -c FILE         TOML configuration file path

Host Specification (mutually exclusive):
  --host, -H HOSTS         Single host or comma-separated list
  --file, -f FILE          File containing hosts (.json, .yaml, .csv, .txt)
  --local, -l              Show local SSH client algorithms

Scanning Options:
  --port, -p PORT          Default SSH port (default: 22)
  --threads, -T COUNT      Number of concurrent threads (default: 20)
  --timeout, -t SECONDS    Connection timeout (default: 10)
  --no-multiplex           Disable SSH multiplexing
  --retry-attempts COUNT   Retry attempts for failed connections (default: 3)

Algorithm Testing:
  --explicit, -e ALGOS     Comma-separated list of specific algorithms to test

Compliance:
  --compliance FRAMEWORK   Check compliance (NIST, FIPS_140_2, BSI_TR_02102, ANSSI, PRIVACY_FOCUSED)
  --list-frameworks        List available compliance frameworks

Output Options:
  --format FORMAT          Output format: table, json, csv, yaml (default: table)
  --output, -o FILE        Output file (default: stdout)
  --verbose, -v            Verbose output with debug information
  --stats                  Show performance statistics
```

## 🚧 Roadmap

### Planned Features for Future Releases

#### Version 2.1 (Q2 2025)
- **Enhanced Logging**
  - File-based logging with rotation
  - Syslog integration
  - Structured logging formats

- **Advanced Reporting**
  - HTML report generation with charts
  - Markdown reports for documentation
  - Executive summary templates

#### Version 2.2 (Q3 2025)
- **Performance Optimizations**
  - Connection pooling for repeated scans
  - Algorithm result caching
  - Memory usage optimization

- **Extended Configuration**
  - Pre-defined host lists in config
  - Custom compliance rules
  - Environment-specific profiles

#### Version 3.0 (Q4 2025)
- **Enterprise Features**
  - REST API for integration
  - Real-time alerting system
  - Webhook notifications
  - Slack/Teams integration

- **Advanced Security Analysis**
  - Quantum resistance checking
  - CVE vulnerability correlation
  - Algorithm deprecation tracking
  - Certificate validation

- **Integration Capabilities**
  - InfluxDB metrics export
  - Prometheus endpoint
  - Splunk forwarder
  - SIEM integration

### Community Requested Features
- Windows support improvements
- Docker container
- Ansible playbook integration
- Kubernetes operator
- Web UI dashboard
- Scheduled scanning
- Diff reports between scans
- Custom algorithm definitions
- Plugin system

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Test with various SSH implementations

## 📋 Requirements

- Python 3.6+
- PyYAML (for YAML file support)
- toml (for TOML configuration)
- SSH client (`openssh-client`)
- Network connectivity to target hosts

## 🐛 Troubleshooting

### Common Issues

**"Connection timeout" errors**
- Increase timeout: `--timeout 30`
- Reduce threads: `--threads 10`
- Check network connectivity

**"No matching cipher found" for all algorithms**
- Verify SSH client installation: `ssh -V`
- Check if host allows SSH connections
- Try with `--no-multiplex` option

**High memory usage**
- Reduce thread count
- Process hosts in smaller batches
- Use CSV output format for large scans

**DNS resolution failures**
- Verify DNS connectivity
- Use IP addresses instead of hostnames
- Increase DNS cache TTL in config

## 📄 License

MIT License - See LICENSE file for details
