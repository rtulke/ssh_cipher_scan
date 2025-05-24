#!/usr/bin/env python3
"""
SSH Algorithm Security Scanner - Enhanced Professional Version
Features: SSH-Multiplexing, Compliance Frameworks, TOML Config, Retry Logic, DNS Caching
"""

import subprocess
import socket
import json
import sys
import csv
import yaml
import toml
import threading
import time
import functools
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple, Union, Generator
from dataclasses import dataclass, asdict, field
from pathlib import Path
import argparse
import tempfile
import shutil
import logging
from urllib.parse import urlparse


# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


@dataclass
class SSHAlgorithmInfo:
    """Data class for SSH algorithm information"""
    name: str
    type: str  # 'encryption', 'mac', 'kex', 'hostkey'
    supported: bool = True


@dataclass
class SSHHostResult:
    """Data class for SSH host scan results"""
    host: str
    port: int
    status: str = "unknown"  # success, failed, timeout
    security_score: int = 0
    compliance_status: Dict[str, bool] = field(default_factory=dict)
    algorithms: Dict[str, List[SSHAlgorithmInfo]] = field(default_factory=dict)
    scan_time: float = 0.0
    ssh_banner: str = ""
    error_message: str = ""
    retry_count: int = 0


class DNSCache:
    """Thread-safe DNS resolution cache with TTL"""
    
    def __init__(self, ttl: int = 300, max_size: int = 1000):
        self.cache = {}
        self.ttl = ttl
        self.max_size = max_size
        self.lock = threading.Lock()
        self.stats = {'hits': 0, 'misses': 0, 'errors': 0}
    
    def resolve(self, hostname: str) -> Optional[str]:
        """Resolve hostname with caching"""
        now = time.time()
        
        with self.lock:
            # Check cache first
            if hostname in self.cache:
                ip, timestamp = self.cache[hostname]
                if now - timestamp < self.ttl:
                    self.stats['hits'] += 1
                    return ip
                else:
                    # Expired entry
                    del self.cache[hostname]
        
        # Cache miss - resolve
        try:
            ip = socket.gethostbyname(hostname)
            with self.lock:
                # Manage cache size
                if len(self.cache) >= self.max_size:
                    # Remove oldest entry
                    oldest_key = min(self.cache.keys(), key=lambda k: self.cache[k][1])
                    del self.cache[oldest_key]
                
                self.cache[hostname] = (ip, now)
                self.stats['misses'] += 1
            return ip
            
        except socket.gaierror as e:
            with self.lock:
                self.stats['errors'] += 1
            logger.warning(f"DNS resolution failed for {hostname}: {e}")
            return None
    
    def get_stats(self) -> Dict:
        """Get cache statistics"""
        with self.lock:
            total = self.stats['hits'] + self.stats['misses']
            hit_rate = (self.stats['hits'] / total * 100) if total > 0 else 0
            return {
                'hit_rate': f"{hit_rate:.1f}%",
                'total_lookups': total,
                'cache_size': len(self.cache),
                **self.stats
            }


def retry_on_failure(max_attempts: int = 3, backoff_factor: float = 2.0, exceptions: Tuple = None):
    """Decorator for retry logic with exponential backoff"""
    if exceptions is None:
        exceptions = (subprocess.TimeoutExpired, subprocess.CalledProcessError, ConnectionError)
    
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last_exception = None
            
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    
                    if attempt < max_attempts - 1:  # Don't sleep on last attempt
                        sleep_time = backoff_factor ** attempt
                        logger.debug(f"Attempt {attempt + 1} failed: {e}. Retrying in {sleep_time:.1f}s...")
                        time.sleep(sleep_time)
                    else:
                        logger.warning(f"All {max_attempts} attempts failed for {func.__name__}")
            
            raise last_exception
        return wrapper
    return decorator


class ComplianceFramework:
    """SSH compliance framework definitions"""
    
    FRAMEWORKS = {
        'NIST': {
            'name': 'NIST Cybersecurity Framework',
            'required_ciphers': [
                'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com', 
                'chacha20-poly1305@openssh.com', 'aes256-ctr', 'aes128-ctr'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 
                'arcfour', 'arcfour128', 'arcfour256', 'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
            ],
            'required_mac': [
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com',
                'hmac-sha2-256', 'hmac-sha2-512'
            ],
            'forbidden_mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96', 'umac-64'
            ],
            'required_kex': [
                'curve25519-sha256', 'curve25519-sha256@libssh.org',
                'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1'
            ],
            'required_hostkey': [
                'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'
            ],
            'forbidden_hostkey': [
                'ssh-dss', 'ssh-rsa'
            ],
            'minimum_score': 80
        },
        
        'FIPS_140_2': {
            'name': 'FIPS 140-2 Level 1',
            'required_ciphers': [
                'aes256-ctr', 'aes192-ctr', 'aes128-ctr'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256'
            ],
            'required_mac': [
                'hmac-sha2-256', 'hmac-sha2-512'
            ],
            'forbidden_mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96'
            ],
            'required_kex': [
                'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1'
            ],
            'required_hostkey': [
                'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'
            ],
            'forbidden_hostkey': [
                'ssh-dss'
            ],
            'minimum_score': 90
        },
        
        'BSI_TR_02102': {
            'name': 'BSI TR-02102-4 (German Federal Office)',
            'required_ciphers': [
                'aes256-gcm@openssh.com', 'aes256-ctr', 'chacha20-poly1305@openssh.com'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256',
                'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
            ],
            'required_mac': [
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'
            ],
            'forbidden_mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96', 'umac-64'
            ],
            'required_kex': [
                'curve25519-sha256', 'curve25519-sha256@libssh.org'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1', 'diffie-hellman-group-exchange-sha256'
            ],
            'required_hostkey': [
                'ssh-ed25519'
            ],
            'forbidden_hostkey': [
                'ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256'
            ],
            'minimum_score': 85
        },
        
        'ANSSI': {
            'name': 'ANSSI (French National Cybersecurity Agency)',
            'required_ciphers': [
                'aes256-gcm@openssh.com', 'chacha20-poly1305@openssh.com'
            ],
            'forbidden_ciphers': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256',
                'aes128-cbc', 'aes192-cbc', 'aes256-cbc', 'aes128-ctr'
            ],
            'required_mac': [
                'hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com'
            ],
            'forbidden_mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1', 'hmac-sha1-96', 'umac-64', 'umac-128'
            ],
            'required_kex': [
                'curve25519-sha256@libssh.org'
            ],
            'forbidden_kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1',
                'diffie-hellman-group-exchange-sha1', 'ecdh-sha2-nistp256'
            ],
            'required_hostkey': [
                'ssh-ed25519'
            ],
            'forbidden_hostkey': [
                'ssh-dss', 'ssh-rsa', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521'
            ],
            'minimum_score': 95
        }
    }
    
    @classmethod
    def check_compliance(cls, algorithms: Dict[str, List[SSHAlgorithmInfo]], framework: str) -> Dict[str, bool]:
        """Check compliance against specified framework"""
        if framework not in cls.FRAMEWORKS:
            raise ValueError(f"Unknown framework: {framework}")
        
        fw = cls.FRAMEWORKS[framework]
        compliance_result = {}
        
        # Get supported algorithms by type
        supported_by_type = {}
        for algo_type, algo_list in algorithms.items():
            supported_by_type[algo_type] = [algo.name for algo in algo_list if algo.supported]
        
        # Map internal types to framework types
        type_mapping = {
            'cipher': 'ciphers',
            'mac': 'mac', 
            'kex': 'kex',
            'key': 'hostkey'
        }
        
        for internal_type, fw_type in type_mapping.items():
            if internal_type in supported_by_type:
                supported = set(supported_by_type[internal_type])
                
                # Check required algorithms
                required_key = f'required_{fw_type}'
                if required_key in fw:
                    required = set(fw[required_key])
                    has_required = bool(required & supported)
                    compliance_result[f'{fw_type}_has_required'] = has_required
                
                # Check forbidden algorithms
                forbidden_key = f'forbidden_{fw_type}'
                if forbidden_key in fw:
                    forbidden = set(fw[forbidden_key])
                    has_forbidden = bool(forbidden & supported)
                    compliance_result[f'{fw_type}_has_forbidden'] = has_forbidden
        
        # Overall compliance
        compliance_result['overall_compliant'] = (
            all(v for k, v in compliance_result.items() if 'has_required' in k) and
            not any(v for k, v in compliance_result.items() if 'has_forbidden' in k)
        )
        
        return compliance_result
    
    @classmethod
    def get_framework_list(cls) -> List[str]:
        """Get list of available frameworks"""
        return list(cls.FRAMEWORKS.keys())
    
    @classmethod
    def get_framework_info(cls, framework: str) -> Dict:
        """Get framework information"""
        return cls.FRAMEWORKS.get(framework, {})


class SSHMultiplexer:
    """SSH connection multiplexing manager"""
    
    def __init__(self, base_dir: str = None):
        self.base_dir = base_dir or tempfile.mkdtemp(prefix='ssh_multiplex_')
        self.active_connections = {}
        self.lock = threading.Lock()
        Path(self.base_dir).mkdir(parents=True, exist_ok=True)
    
    def get_control_path(self, host: str, port: int) -> str:
        """Generate control path for SSH multiplexing"""
        return str(Path(self.base_dir) / f"ssh_{host}_{port}")
    
    def establish_master(self, host: str, port: int, timeout: int = 10) -> bool:
        """Establish SSH master connection"""
        control_path = self.get_control_path(host, port)
        
        with self.lock:
            if (host, port) in self.active_connections:
                return True  # Already established
        
        cmd = [
            'ssh',
            '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=5',
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'PreferredAuthentications=none',
            '-o', 'ControlMaster=yes',
            '-o', f'ControlPath={control_path}',
            '-o', 'ControlPersist=30',  # Keep connection for 30 seconds
            '-o', 'LogLevel=quiet',
            f'{host}' if port == 22 else f'{host}:{port}',
            'exit'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
            
            with self.lock:
                if result.returncode in [0, 255]:  # 255 is normal for auth failure
                    self.active_connections[(host, port)] = control_path
                    return True
                return False
                
        except subprocess.TimeoutExpired:
            return False
    
    def test_with_multiplex(self, host: str, port: int, algorithm: str, algo_type: str, timeout: int = 10) -> bool:
        """Test algorithm using multiplexed connection"""
        control_path = self.get_control_path(host, port)
        
        # Map algorithm types to SSH options
        ssh_options = {
            'cipher': f'Ciphers={algorithm}',
            'mac': f'MACs={algorithm}',
            'kex': f'KexAlgorithms={algorithm}',
            'key': f'HostKeyAlgorithms={algorithm}'
        }
        
        if algo_type not in ssh_options:
            return False
        
        cmd = [
            'ssh',
            '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=3',
            '-o', 'StrictHostKeyChecking=no',
            '-o', ssh_options[algo_type],
            '-o', 'PreferredAuthentications=none',
            '-o', 'ControlMaster=no',
            '-o', f'ControlPath={control_path}',
            '-o', 'LogLevel=quiet',
            f'{host}' if port == 22 else f'{host}:{port}',
            'exit'
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
            
            # Check for algorithm-specific rejection messages
            stderr_lower = result.stderr.lower()
            rejection_patterns = [
                'no matching cipher found',
                'no matching mac found', 
                'no matching key exchange method found',
                'no matching host key type found',
                'no mutual signature algorithm'
            ]
            
            return not any(pattern in stderr_lower for pattern in rejection_patterns)
            
        except subprocess.TimeoutExpired:
            return False
    
    def cleanup(self):
        """Clean up multiplexed connections and temp directory"""
        with self.lock:
            for (host, port), control_path in self.active_connections.items():
                try:
                    # Close master connection
                    subprocess.run([
                        'ssh', '-o', f'ControlPath={control_path}', 
                        '-O', 'exit', f'{host}:{port}'
                    ], capture_output=True, timeout=5)
                except:
                    pass
            
            self.active_connections.clear()
        
        # Remove temp directory
        try:
            shutil.rmtree(self.base_dir)
        except:
            pass


class SSHEnhancedScanner:
    """Enhanced SSH scanner with all advanced features"""
    
    def __init__(self, config: Dict = None):
        """Initialize scanner with configuration"""
        self.config = config or {}
        
        # Core settings
        self.timeout = self.config.get('timeout', 10)
        self.max_workers = self.config.get('threads', 20)
        self.use_multiplexing = self.config.get('use_multiplexing', True)
        self.retry_attempts = self.config.get('retry_attempts', 3)
        self.dns_cache_ttl = self.config.get('dns_cache_ttl', 300)
        
        # Initialize components
        self.dns_cache = DNSCache(ttl=self.dns_cache_ttl)
        self.multiplexer = SSHMultiplexer() if self.use_multiplexing else None
        self.lock = threading.Lock()
        
        # Compliance framework
        self.compliance_framework = self.config.get('compliance_framework', None)
        
        logger.info(f"Initialized scanner with {self.max_workers} threads, "
                   f"multiplexing={'enabled' if self.use_multiplexing else 'disabled'}")
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.multiplexer:
            self.multiplexer.cleanup()
    
    def parse_host_string(self, host_string: str) -> Tuple[str, int]:
        """Parse host:port string with DNS caching"""
        if ':' in host_string:
            host, port_str = host_string.rsplit(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 22
        else:
            host = host_string
            port = 22
        
        # Resolve hostname using DNS cache
        resolved_ip = self.dns_cache.resolve(host.strip())
        if resolved_ip:
            return resolved_ip, port
        else:
            logger.warning(f"DNS resolution failed for {host}, using hostname directly")
            return host.strip(), port
    
    def load_hosts_from_file(self, file_path: str) -> List[Tuple[str, int]]:
        """Load hosts from various file formats with error handling"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        hosts = []
        
        try:
            if file_path.suffix.lower() == '.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                hosts.append(self.parse_host_string(item))
                            elif isinstance(item, dict) and 'host' in item:
                                host = item['host']
                                port = item.get('port', 22)
                                resolved_ip = self.dns_cache.resolve(host)
                                hosts.append((resolved_ip or host, port))
            
            elif file_path.suffix.lower() in ['.yml', '.yaml']:
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    if isinstance(data, list):
                        for item in data:
                            if isinstance(item, str):
                                hosts.append(self.parse_host_string(item))
                            elif isinstance(item, dict) and 'host' in item:
                                host = item['host']
                                port = item.get('port', 22)
                                resolved_ip = self.dns_cache.resolve(host)
                                hosts.append((resolved_ip or host, port))
            
            elif file_path.suffix.lower() == '.csv':
                with open(file_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if row and not row[0].startswith('#'):
                            if len(row) >= 2:
                                try:
                                    host = row[0].strip()
                                    port = int(row[1].strip())
                                    resolved_ip = self.dns_cache.resolve(host)
                                    hosts.append((resolved_ip or host, port))
                                except ValueError:
                                    resolved_ip = self.dns_cache.resolve(host)
                                    hosts.append((resolved_ip or host, 22))
                            else:
                                hosts.append(self.parse_host_string(row[0]))
            
            else:  # .txt or other text files
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            hosts.append(self.parse_host_string(line))
        
        except Exception as e:
            raise ValueError(f"Error parsing file {file_path}: {e}")
        
        logger.info(f"Loaded {len(hosts)} hosts from {file_path}")
        return hosts
    
    @retry_on_failure(max_attempts=3, backoff_factor=1.5)
    def get_local_ssh_algorithms(self) -> Dict[str, List[str]]:
        """Query local SSH client for supported algorithms with retry"""
        algorithm_types = ['cipher', 'mac', 'kex', 'key']
        results = {}
        
        for algo_type in algorithm_types:
            try:
                result = subprocess.run(
                    ['ssh', '-Q', algo_type],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout,
                    check=True
                )
                results[algo_type] = [
                    line.strip() for line in result.stdout.split('\n') 
                    if line.strip()
                ]
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
                logger.error(f"Error querying {algo_type}: {e}")
                results[algo_type] = []
        
        return results
    
    @retry_on_failure(max_attempts=2, backoff_factor=1.0)
    def test_algorithm_connection(self, host: str, algorithm: str, algo_type: str, port: int = 22) -> bool:
        """Test algorithm with multiplexing and retry logic"""
        if self.use_multiplexing and self.multiplexer:
            # Try to establish master connection if not exists
            if (host, port) not in self.multiplexer.active_connections:
                self.multiplexer.establish_master(host, port, self.timeout)
            
            # Use multiplexed connection if available
            if (host, port) in self.multiplexer.active_connections:
                return self.multiplexer.test_with_multiplex(host, port, algorithm, algo_type, self.timeout)
        
        # Fallback to regular SSH connection
        ssh_options = {
            'cipher': f'Ciphers={algorithm}',
            'mac': f'MACs={algorithm}',
            'kex': f'KexAlgorithms={algorithm}',
            'key': f'HostKeyAlgorithms={algorithm}'
        }
        
        if algo_type not in ssh_options:
            return False
        
        cmd = [
            'ssh',
            '-o', 'BatchMode=yes',
            '-o', 'ConnectTimeout=3',
            '-o', 'StrictHostKeyChecking=no',
            '-o', ssh_options[algo_type],
            '-o', 'PreferredAuthentications=none',
            '-o', 'LogLevel=quiet',
            f'{host}' if port == 22 else f'{host}:{port}',
            'exit'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                timeout=self.timeout,
                check=False
            )
            
            stderr_lower = result.stderr.lower()
            rejection_patterns = [
                'no matching cipher found',
                'no matching mac found', 
                'no matching key exchange method found',
                'no matching host key type found',
                'no mutual signature algorithm'
            ]
            
            return not any(pattern in stderr_lower for pattern in rejection_patterns)
            
        except subprocess.TimeoutExpired:
            return False
    
    @retry_on_failure(max_attempts=2, backoff_factor=1.0)
    def scan_ssh_banner(self, host: str, port: int = 22) -> Optional[str]:
        """Get SSH banner with retry logic"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(3)
                sock.connect((host, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                return banner
        except (socket.error, socket.timeout):
            return None
    
    def scan_single_host(self, host: str, port: int, explicit_algorithms: List[str] = None) -> SSHHostResult:
        """Scan single host with all enhancements"""
        start_time = time.time()
        result = SSHHostResult(host=host, port=port)
        
        try:
            # Get SSH banner
            result.ssh_banner = self.scan_ssh_banner(host, port) or ""
            
            if explicit_algorithms:
                # Test only explicit algorithms
                explicit_results = self.test_explicit_algorithms(host, port, explicit_algorithms)
                
                for algo, supported in explicit_results.items():
                    if 'explicit' not in result.algorithms:
                        result.algorithms['explicit'] = []
                    result.algorithms['explicit'].append(
                        SSHAlgorithmInfo(name=algo, type='explicit', supported=supported)
                    )
                
                total_tested = len(explicit_results)
                supported_count = sum(1 for supported in explicit_results.values() if supported)
                result.security_score = (supported_count * 100 // total_tested) if total_tested > 0 else 0
                
            else:
                # Full algorithm scan
                result.algorithms = self.scan_all_algorithms(host, port)
                result.security_score = self.calculate_security_score(result.algorithms)
                
                # Check compliance if framework specified
                if self.compliance_framework:
                    result.compliance_status = ComplianceFramework.check_compliance(
                        result.algorithms, self.compliance_framework
                    )
            
            result.status = "success"
            
        except Exception as e:
            result.status = "failed"
            result.error_message = str(e)
            logger.error(f"Scan failed for {host}:{port}: {e}")
        
        result.scan_time = time.time() - start_time
        return result
    
    def test_explicit_algorithms(self, host: str, port: int, algorithms: List[str]) -> Dict[str, bool]:
        """Test explicit algorithms with enhanced error handling"""
        results = {}
        local_algorithms = self.get_local_ssh_algorithms()
        
        algo_type_map = {}
        for algo_type, algo_list in local_algorithms.items():
            for algo in algo_list:
                algo_type_map[algo] = algo_type
        
        for algorithm in algorithms:
            if algorithm in algo_type_map:
                algo_type = algo_type_map[algorithm]
                results[algorithm] = self.test_algorithm_connection(host, algorithm, algo_type, port)
            else:
                # Try all types
                results[algorithm] = False
                for algo_type in ['cipher', 'mac', 'kex', 'key']:
                    if self.test_algorithm_connection(host, algorithm, algo_type, port):
                        results[algorithm] = True
                        break
        
        return results
    
    def scan_all_algorithms(self, host: str, port: int) -> Dict[str, List[SSHAlgorithmInfo]]:
        """Scan all algorithms with enhanced performance"""
        local_algorithms = self.get_local_ssh_algorithms()
        results = {}
        
        algo_type_map = {
            'cipher': 'encryption',
            'mac': 'mac',
            'kex': 'key_exchange', 
            'key': 'host_key'
        }
        
        for algo_type, algo_list in local_algorithms.items():
            if not algo_list:
                continue
                
            supported_algorithms = []
            
            for algorithm in algo_list:
                is_supported = self.test_algorithm_connection(host, algorithm, algo_type, port)
                
                algo_info = SSHAlgorithmInfo(
                    name=algorithm,
                    type=algo_type_map.get(algo_type, algo_type),
                    supported=is_supported
                )
                supported_algorithms.append(algo_info)
            
            results[algo_type] = supported_algorithms
        
        return results
    
    def calculate_security_score(self, algorithms: Dict[str, List[SSHAlgorithmInfo]]) -> int:
        """Calculate security score based on supported algorithms"""
        weak_algorithms = {
            'cipher': [
                'des', '3des-cbc', 'blowfish-cbc', 'cast128-cbc', 'arcfour', 'arcfour128', 'arcfour256',
                'aes128-cbc', 'aes192-cbc', 'aes256-cbc'
            ],
            'mac': [
                'hmac-md5', 'hmac-md5-96', 'hmac-sha1-96', 'umac-64'
            ],
            'kex': [
                'diffie-hellman-group1-sha1', 'diffie-hellman-group14-sha1', 
                'diffie-hellman-group-exchange-sha1'
            ],
            'key': [
                'ssh-dss', 'ssh-rsa'
            ]
        }
        
        total_supported = 0
        weak_count = 0
        
        for algo_type, algo_list in algorithms.items():
            for algo in algo_list:
                if algo.supported:
                    total_supported += 1
                    if algo.name in weak_algorithms.get(algo_type, []):
                        weak_count += 1
        
        if total_supported == 0:
            return 0
        
        return max(0, 100 - (weak_count * 100 // total_supported))
    
    def batch_scan(self, hosts: List[Tuple[str, int]], explicit_algorithms: List[str] = None) -> List[SSHHostResult]:
        """Enhanced batch scanning with all features"""
        results = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {
                executor.submit(self.scan_single_host, host, port, explicit_algorithms): (host, port)
                for host, port in hosts
            }
            
            for future in as_completed(future_to_host):
                host, port = future_to_host[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    with self.lock:
                        status_icon = "✓" if result.status == "success" else "✗"
                        compliance_info = ""
                        if result.compliance_status and 'overall_compliant' in result.compliance_status:
                            compliance = "✓" if result.compliance_status['overall_compliant'] else "✗"
                            compliance_info = f" - Compliance: {compliance}"
                        
                        print(f"{status_icon} {host}:{port} - Score: {result.security_score}/100{compliance_info} - {result.scan_time:.1f}s")
                        
                except Exception as e:
                    with self.lock:
                        print(f"✗ {host}:{port} - Error: {e}")
        
        return sorted(results, key=lambda x: (x.host, x.port))
    
    def format_results_table(self, results: List[SSHHostResult], show_algorithms: bool = True) -> str:
        """Enhanced table formatting with compliance info"""
        if not results:
            return "No results to display"
        
        table_data = []
        headers = ["Host", "Port", "Status", "Security", "Compliance", "Banner", "Time(s)"]
        
        if show_algorithms:
            headers.append("Supported Algorithms")
        
        for result in results:
            supported_algos = []
            if result.algorithms:
                for algo_type, algo_list in result.algorithms.items():
                    for algo in algo_list:
                        if algo.supported:
                            supported_algos.append(algo.name)
            
            # Compliance status
            compliance_status = "N/A"
            if result.compliance_status and 'overall_compliant' in result.compliance_status:
                compliance_status = "✓ PASS" if result.compliance_status['overall_compliant'] else "✗ FAIL"
            
            row = [
                result.host,
                str(result.port),
                result.status,
                f"{result.security_score}/100",
                compliance_status,
                result.ssh_banner[:25] + "..." if len(result.ssh_banner) > 25 else result.ssh_banner,
                f"{result.scan_time:.1f}"
            ]
            
            if show_algorithms:
                algo_summary = ", ".join(supported_algos[:3])
                if len(supported_algos) > 3:
                    algo_summary += f" (+{len(supported_algos)-3} more)"
                row.append(algo_summary)
            
            table_data.append(row)
        
        # Calculate column widths
        col_widths = [len(header) for header in headers]
        for row in table_data:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        
        # Build table
        separator = "+" + "+".join("-" * (width + 2) for width in col_widths) + "+"
        header_row = "|" + "|".join(f" {header:<{col_widths[i]}} " for i, header in enumerate(headers)) + "|"
        
        table_lines = [separator, header_row, separator]
        
        for row in table_data:
            row_line = "|" + "|".join(f" {str(cell):<{col_widths[i]}} " for i, cell in enumerate(row)) + "|"
            table_lines.append(row_line)
        
        table_lines.append(separator)
        
        return "\n".join(table_lines)
    
    def export_results(self, results: List[SSHHostResult], format_type: str = 'json') -> str:
        """Enhanced export with compliance data"""
        if format_type.lower() == 'json':
            json_data = []
            for result in results:
                result_dict = asdict(result)
                json_data.append(result_dict)
            return json.dumps(json_data, indent=2)
        
        elif format_type.lower() == 'csv':
            import io
            output = io.StringIO()
            writer = csv.writer(output)
            
            writer.writerow(['Host', 'Port', 'Status', 'Security_Score', 'Compliance_Status', 
                           'SSH_Banner', 'Scan_Time', 'Supported_Algorithms'])
            
            for result in results:
                supported_algos = []
                if result.algorithms:
                    for algo_type, algo_list in result.algorithms.items():
                        for algo in algo_list:
                            if algo.supported:
                                supported_algos.append(f"{algo.name}({algo.type})")
                
                compliance_status = "N/A"
                if result.compliance_status and 'overall_compliant' in result.compliance_status:
                    compliance_status = "PASS" if result.compliance_status['overall_compliant'] else "FAIL"
                
                writer.writerow([
                    result.host,
                    result.port,
                    result.status,
                    result.security_score,
                    compliance_status,
                    result.ssh_banner,
                    f"{result.scan_time:.2f}",
                    "; ".join(supported_algos)
                ])
            
            return output.getvalue()
        
        elif format_type.lower() == 'yaml':
            yaml_data = []
            for result in results:
                result_dict = asdict(result)
                yaml_data.append(result_dict)
            return yaml.dump(yaml_data, default_flow_style=False)
        
        else:
            return self.format_results_table(results)
    
    def get_performance_stats(self) -> Dict:
        """Get performance statistics"""
        stats = {
            'dns_cache': self.dns_cache.get_stats(),
            'multiplexing_enabled': self.use_multiplexing,
            'max_workers': self.max_workers,
            'retry_attempts': self.retry_attempts
        }
        
        if self.multiplexer:
            stats['active_ssh_connections'] = len(self.multiplexer.active_connections)
        
        return stats


def load_config_file(config_path: str) -> Dict:
    """Load configuration from TOML file"""
    try:
        config_file = Path(config_path)
        if config_file.exists():
            return toml.load(config_file)
        else:
            logger.warning(f"Config file not found: {config_path}")
            return {}
    except Exception as e:
        logger.error(f"Error loading config file {config_path}: {e}")
        return {}


def main():
    """Enhanced main function with configuration support"""
    parser = argparse.ArgumentParser(description='Enhanced SSH Algorithm Security Scanner')
    
    # Configuration
    parser.add_argument('--config', '-c', help='TOML configuration file')
    
    # Host specification options
    host_group = parser.add_mutually_exclusive_group()
    host_group.add_argument('--host', '-H', help='Single host or comma-separated list (host1:port,host2:port)')
    host_group.add_argument('--file', '-f', help='File containing hosts (supports .json, .yaml, .csv, .txt)')
    host_group.add_argument('--local', '-l', action='store_true', help='Show local SSH client algorithms')
    
    # Scanning options
    parser.add_argument('--port', '-p', type=int, default=22, help='Default SSH port (default: 22)')
    parser.add_argument('--explicit', '-e', help='Comma-separated list of specific algorithms to test')
    parser.add_argument('--threads', '-T', type=int, default=20, help='Number of concurrent threads (default: 20)')
    parser.add_argument('--timeout', '-t', type=int, default=10, help='Connection timeout (default: 10)')
    parser.add_argument('--no-multiplex', action='store_true', help='Disable SSH multiplexing')
    parser.add_argument('--retry-attempts', '-r', type=int, default=3, help='Retry attempts for failed connections (default: 3)')
    
    # Compliance options
    parser.add_argument('--compliance', choices=ComplianceFramework.get_framework_list(), 
                       help='Compliance framework to check against')
    parser.add_argument('--list-frameworks', action='store_true', help='List available compliance frameworks')
    
    # Output options
    parser.add_argument('--format', choices=['json', 'csv', 'yaml', 'table'], default='table',
                       help='Output format (default: table)')
    parser.add_argument('--output', '-o', help='Output file (default: stdout)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--stats', action='store_true', help='Show performance statistics')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config:
        config = load_config_file(args.config)
    
    # Override config with command line arguments
    if args.threads:
        config['threads'] = args.threads
    if args.timeout:
        config['timeout'] = args.timeout
    if args.no_multiplex:
        config['use_multiplexing'] = False
    if args.retry_attempts:
        config['retry_attempts'] = args.retry_attempts
    if args.compliance:
        config['compliance_framework'] = args.compliance
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # List frameworks and exit
    if args.list_frameworks:
        print("Available Compliance Frameworks:")
        for fw_name in ComplianceFramework.get_framework_list():
            fw_info = ComplianceFramework.get_framework_info(fw_name)
            print(f"  {fw_name}: {fw_info.get('name', 'Unknown')}")
        return 0
    
    # Show local algorithms
    if args.local:
        print("Local SSH client supported algorithms:")
        with SSHEnhancedScanner(config) as scanner:
            local_algorithms = scanner.get_local_ssh_algorithms()
            
            for algo_type, algo_list in local_algorithms.items():
                print(f"\n{algo_type.upper()} ({len(algo_list)}):")
                for algo in algo_list:
                    print(f"  - {algo}")
        return 0
    
    # Parse explicit algorithms
    explicit_algorithms = None
    if args.explicit:
        explicit_algorithms = [algo.strip() for algo in args.explicit.split(',')]
        print(f"Testing explicit algorithms: {explicit_algorithms}")
    
    # Parse hosts
    hosts = []
    
    with SSHEnhancedScanner(config) as scanner:
        if args.file:
            try:
                hosts = scanner.load_hosts_from_file(args.file)
                print(f"Loaded {len(hosts)} hosts from {args.file}")
            except Exception as e:
                print(f"Error loading file: {e}", file=sys.stderr)
                return 1
        
        elif args.host:
            host_strings = [h.strip() for h in args.host.split(',')]
            for host_string in host_strings:
                host, port = scanner.parse_host_string(host_string)
                hosts.append((host, port if port != 22 else args.port))
        
        else:
            parser.print_help()
            return 1
        
        if not hosts:
            print("No hosts to scan", file=sys.stderr)
            return 1
        
        # Show configuration info
        print(f"\nConfiguration:")
        print(f"  Threads: {scanner.max_workers}")
        print(f"  Timeout: {scanner.timeout}s")
        print(f"  SSH Multiplexing: {'enabled' if scanner.use_multiplexing else 'disabled'}")
        print(f"  DNS Caching: enabled (TTL: {scanner.dns_cache_ttl}s)")
        print(f"  Retry Attempts: {scanner.retry_attempts}")
        if scanner.compliance_framework:
            fw_info = ComplianceFramework.get_framework_info(scanner.compliance_framework)
            print(f"  Compliance Framework: {scanner.compliance_framework} ({fw_info.get('name', 'Unknown')})")
        
        # Perform scanning
        print(f"\nStarting scan of {len(hosts)} hosts...")
        print("=" * 80)
        
        results = scanner.batch_scan(hosts, explicit_algorithms)
        
        # Generate output
        if args.format == 'table':
            output = scanner.format_results_table(results, show_algorithms=not explicit_algorithms)
        else:
            output = scanner.export_results(results, args.format)
        
        # Write output
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f"\nResults written to {args.output}")
        else:
            print("\n" + "=" * 80)
            print("SCAN RESULTS")
            print("=" * 80)
            print(output)
        
        # Summary statistics
        successful_scans = sum(1 for r in results if r.status == "success")
        failed_scans = len(results) - successful_scans
        avg_score = sum(r.security_score for r in results if r.status == "success") / max(successful_scans, 1)
        total_time = sum(r.scan_time for r in results)
        
        print(f"\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total hosts scanned: {len(results)}")
        print(f"Successful scans: {successful_scans}")
        print(f"Failed scans: {failed_scans}")
        print(f"Average security score: {avg_score:.1f}/100")
        print(f"Total scan time: {total_time:.1f}s")
        print(f"Average time per host: {total_time/len(results):.1f}s")
        
        # Compliance summary
        if scanner.compliance_framework and successful_scans > 0:
            compliant_hosts = sum(1 for r in results 
                                if r.compliance_status and r.compliance_status.get('overall_compliant', False))
            compliance_rate = (compliant_hosts / successful_scans) * 100
            print(f"Compliance rate ({scanner.compliance_framework}): {compliant_hosts}/{successful_scans} ({compliance_rate:.1f}%)")
        
        # Performance statistics
        if args.stats:
            print(f"\n" + "=" * 80)
            print("PERFORMANCE STATISTICS")
            print("=" * 80)
            perf_stats = scanner.get_performance_stats()
            for key, value in perf_stats.items():
                if isinstance(value, dict):
                    print(f"{key}:")
                    for subkey, subvalue in value.items():
                        print(f"  {subkey}: {subvalue}")
                else:
                    print(f"{key}: {value}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
