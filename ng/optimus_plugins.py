#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: optimus_plugins.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-06-04 07:36:02
# Modified: 2025-06-04 07:41:05

"""
Plugin system for Optimus - Example custom threat detection plugin
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import re
import logging
from dataclasses import dataclass


@dataclass
class ThreatResult:
    """Result from threat analysis"""
    threat_type: str
    severity: str
    confidence: float
    description: str
    indicators: List[str]
    metadata: Dict[str, Any]


class OptimusPlugin(ABC):
    """Base class for Optimus plugins"""

    @abstractmethod
    def get_name(self) -> str:
        """Return plugin name"""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Return plugin version"""
        pass

    @abstractmethod
    def get_description(self) -> str:
        """Return plugin description"""
        pass

    @abstractmethod
    def analyze_packet(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Analyze packet and return threat information if found"""
        pass

    def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize plugin with configuration"""
        return True

    def cleanup(self):
        """Cleanup plugin resources"""
        pass


class AdvancedThreatHuntingPlugin(OptimusPlugin):
    """Advanced threat hunting plugin with ML-based detection"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.threat_patterns = {}
        self.behavioral_models = {}
        self.load_threat_intelligence()

    def get_name(self) -> str:
        return "AdvancedThreatHunting"

    def get_version(self) -> str:
        return "1.0.0"

    def get_description(self) -> str:
        return "Advanced threat hunting using ML and behavioral analysis"

    def load_threat_intelligence(self):
        """Load threat intelligence feeds"""
        self.threat_patterns = {
            'apt_communication': re.compile(
                r'(?:pastebin\.com|github\.com|twitter\.com)/[a-zA-Z0-9]{8,}',
                re.I
            ),
            'living_off_land': re.compile(
                r'(?:powershell|cmd|wmic|regsvr32|rundll32|certutil)\.exe',
                re.I
            ),
            'suspicious_user_agent': re.compile(
                r'(?:curl|wget|python|powershell|WinHttp|URLDownloadToFile)',
                re.I
            ),
            'data_staging': re.compile(
                r'(?:7z|rar|zip|tar)\.exe.*(?:-p|-password)',
                re.I
            ),
            'lateral_movement': re.compile(
                r'(?:psexec|wmiexec|smbexec|net use|\\\\[0-9]+\.[0-9]+)',
                re.I
            )
        }

    def analyze_packet(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Analyze packet for advanced threats"""
        threats_found = []

        # Analyze HTTP traffic for suspicious patterns
        if packet_data.get('protos', {}).get('l7') == 'http':
            http_threats = self._analyze_http_threats(packet_data)
            threats_found.extend(http_threats)

        # Analyze DNS for suspicious domains
        if packet_data.get('dns'):
            dns_threats = self._analyze_dns_threats(packet_data)
            threats_found.extend(dns_threats)

        # Analyze TLS for certificate anomalies
        if packet_data.get('tls'):
            tls_threats = self._analyze_tls_threats(packet_data)
            threats_found.extend(tls_threats)

        # Return highest severity threat
        if threats_found:
            return max(threats_found, key=lambda x: self._get_severity_score(x.severity))

        return None

    def _analyze_http_threats(self, packet_data: Dict[str, Any]) -> List[ThreatResult]:
        """Analyze HTTP traffic for threats"""
        threats = []
        http_data = packet_data.get('http', {})

        # Check user agent
        user_agent = http_data.get('request', {}).get('header', {}).get('user-agent', '')
        if self.threat_patterns['suspicious_user_agent'].search(user_agent):
            threats.append(ThreatResult(
                threat_type='suspicious_user_agent',
                severity='medium',
                confidence=0.8,
                description='Suspicious user agent detected',
                indicators=[user_agent],
                metadata={'pattern': 'user_agent_analysis'}
            ))

        # Check for APT communication patterns
        uri = http_data.get('request', {}).get('uri', '')
        if self.threat_patterns['apt_communication'].search(uri):
            threats.append(ThreatResult(
                threat_type='apt_communication',
                severity='high',
                confidence=0.9,
                description='Potential APT communication pattern',
                indicators=[uri],
                metadata={'pattern': 'apt_communication'}
            ))

        # Check for data staging indicators
        if self.threat_patterns['data_staging'].search(uri):
            threats.append(ThreatResult(
                threat_type='data_staging',
                severity='high',
                confidence=0.85,
                description='Potential data staging activity',
                indicators=[uri],
                metadata={'pattern': 'data_staging'}
            ))

        return threats

    def _analyze_dns_threats(self, packet_data: Dict[str, Any]) -> List[ThreatResult]:
        """Analyze DNS queries for threats"""
        threats = []
        dns_data = packet_data.get('dns', {})
        domain = dns_data.get('query', '')

        if not domain:
            return threats

        # Advanced DGA detection using multiple algorithms
        if self._detect_advanced_dga(domain):
            threats.append(ThreatResult(
                threat_type='advanced_dga',
                severity='high',
                confidence=0.9,
                description='Advanced DGA domain detected',
                indicators=[domain],
                metadata={
                    'entropy': dns_data.get('entropy', 0),
                    'algorithm': 'advanced_dga'
                }
            ))

        # Fast flux detection
        if self._detect_fast_flux(domain):
            threats.append(ThreatResult(
                threat_type='fast_flux',
                severity='medium',
                confidence=0.75,
                description='Fast flux DNS detected',
                indicators=[domain],
                metadata={'pattern': 'fast_flux'}
            ))

        return threats

    def _analyze_tls_threats(self, packet_data: Dict[str, Any]) -> List[ThreatResult]:
        """Analyze TLS certificates for threats"""
        threats = []
        tls_data = packet_data.get('tls', {})

        # Check for self-signed certificates
        if tls_data.get('self_signed'):
            threats.append(ThreatResult(
                threat_type='self_signed_cert',
                severity='low',
                confidence=0.6,
                description='Self-signed certificate detected',
                indicators=[tls_data.get('fingerprint', '')],
                metadata={'cert_analysis': 'self_signed'}
            ))

        # Check for expired certificates
        if tls_data.get('expired'):
            threats.append(ThreatResult(
                threat_type='expired_cert',
                severity='medium',
                confidence=0.8,
                description='Expired certificate detected',
                indicators=[tls_data.get('fingerprint', '')],
                metadata={'cert_analysis': 'expired'}
            ))

        # Check for suspicious certificate authorities
        issuer = tls_data.get('issuer', '')
        if self._is_suspicious_ca(issuer):
            threats.append(ThreatResult(
                threat_type='suspicious_ca',
                severity='high',
                confidence=0.9,
                description='Certificate from suspicious CA',
                indicators=[issuer],
                metadata={'cert_analysis': 'suspicious_ca'}
            ))

        return threats

    def _detect_advanced_dga(self, domain: str) -> bool:
        """Advanced DGA detection using multiple algorithms"""
        # Remove TLD
        domain_name = domain.split('.')[0] if '.' in domain else domain

        # Multiple DGA detection algorithms
        entropy_score = self._calculate_entropy(domain_name)
        bigram_score = self._calculate_bigram_score(domain_name)
        length_score = self._calculate_length_score(domain_name)
        vowel_consonant_ratio = self._calculate_vowel_consonant_ratio(domain_name)

        # Weighted scoring
        dga_score = (
            entropy_score * 0.3 +
            bigram_score * 0.3 +
            length_score * 0.2 +
            vowel_consonant_ratio * 0.2
        )

        return dga_score > 0.7

    def _detect_fast_flux(self, domain: str) -> bool:
        """Detect fast flux DNS patterns"""
        # This would typically involve DNS resolution history
        # For now, check for patterns indicating fast flux

        # Check for numeric patterns that might indicate fast flux
        numeric_ratio = sum(1 for c in domain if c.isdigit()) / len(domain)

        # Check for short TTL indicators in domain structure
        # This is a simplified heuristic
        return numeric_ratio > 0.3 and len(domain.split('.')) > 3

    def _is_suspicious_ca(self, issuer: str) -> bool:
        """Check if certificate authority is suspicious"""
        suspicious_cas = [
            'WoSign',
            'StartCom',
            'CN=localhost',
            'CN=test',
            'O=Test'
        ]

        return any(sus_ca in issuer for sus_ca in suspicious_cas)

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0

        from collections import Counter
        import math

        counter = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy / 8.0  # Normalize to 0-1 range

    def _calculate_bigram_score(self, text: str) -> float:
        """Calculate bigram frequency score for DGA detection"""
        if len(text) < 2:
            return 0.0

        # Common English bigrams with frequencies
        common_bigrams = {
            'th': 0.0356, 'he': 0.0307, 'in': 0.0243, 'er': 0.0205,
            'an': 0.0199, 're': 0.0185, 'nd': 0.0176, 'on': 0.0176,
            'en': 0.0145, 'at': 0.0144, 'ou': 0.0129, 'ed': 0.0126,
            'ha': 0.0126, 'to': 0.0125, 'or': 0.0117, 'it': 0.0117,
            'is': 0.0113, 'hi': 0.0109, 'es': 0.0108, 'ng': 0.0108
        }

        bigrams = [text[i:i+2].lower() for i in range(len(text)-1)]

        # Calculate score based on presence of common bigrams
        common_count = sum(1 for bg in bigrams if bg in common_bigrams)
        return 1.0 - (common_count / len(bigrams))  # Higher score = more suspicious

    def _calculate_length_score(self, text: str) -> float:
        """Calculate length-based suspicion score"""
        length = len(text)

        # Typical domain lengths vs DGA lengths
        if 8 <= length <= 15:
            return 0.1  # Normal range
        elif 16 <= length <= 25:
            return 0.5  # Somewhat suspicious
        elif length > 25:
            return 0.9  # Very suspicious
        else:
            return 0.3  # Short domains can be suspicious too

    def _calculate_vowel_consonant_ratio(self, text: str) -> float:
        """Calculate vowel to consonant ratio score"""
        vowels = sum(1 for c in text.lower() if c in 'aeiou')
        consonants = sum(1 for c in text.lower() if c.isalpha() and c not in 'aeiou')

        if consonants == 0:
            return 1.0

        ratio = vowels / consonants

        # Normal English ratio is around 0.4-0.6
        if 0.3 <= ratio <= 0.7:
            return 0.1
        else:
            return min(1.0, abs(ratio - 0.5) * 2)

    def _get_severity_score(self, severity: str) -> int:
        """Convert severity to numeric score for comparison"""
        severity_map = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4
        }
        return severity_map.get(severity.lower(), 0)


class IoTBotnetDetectionPlugin(OptimusPlugin):
    """Plugin for detecting IoT botnet activity"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.iot_signatures = self._load_iot_signatures()
        self.scanning_patterns = {}

    def get_name(self) -> str:
        return "IoTBotnetDetection"

    def get_version(self) -> str:
        return "1.0.0"

    def get_description(self) -> str:
        return "Detect IoT botnet activity and malware"

    def _load_iot_signatures(self) -> Dict[str, re.Pattern]:
        """Load IoT malware signatures"""
        return {
            'mirai': re.compile(
                r'(?:busybox|\/bin\/sh|\/proc\/self\/exe|MIRAI)',
                re.I
            ),
            'gafgyt': re.compile(
                r'(?:GAFGYT|\/tmp\/\.ICE|\/dev\/nul)',
                re.I
            ),
            'hajime': re.compile(
                r'(?:\.i|\.m|Just a white rabbit|dHJhY2Vy)',
                re.I
            ),
            'reaper': re.compile(
                r'(?:IoTReaper|\/tmp\/\.sockconf)',
                re.I
            ),
            'torii': re.compile(
                r'(?:Torii|\/etc\/tor)',
                re.I
            )
        }

    def analyze_packet(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Analyze packet for IoT botnet activity"""
        # Check for telnet brute force (common in IoT attacks)
        if self._detect_telnet_bruteforce(packet_data):
            return ThreatResult(
                threat_type='iot_telnet_bruteforce',
                severity='high',
                confidence=0.9,
                description='IoT telnet brute force attack detected',
                indicators=[f"{packet_data.get('ip', {}).get('src', 'unknown')}:23"],
                metadata={'attack_type': 'telnet_bruteforce'}
            )

        # Check for IoT malware signatures in payload
        payload_threats = self._check_payload_signatures(packet_data)
        if payload_threats:
            return payload_threats

        # Check for scanning behavior
        scanning_threat = self._detect_scanning_behavior(packet_data)
        if scanning_threat:
            return scanning_threat

        return None

    def _detect_telnet_bruteforce(self, packet_data: Dict[str, Any]) -> bool:
        """Detect telnet brute force attempts"""
        tcp_data = packet_data.get('tcp', {})
        if tcp_data.get('dstport') == 23:  # Telnet port
            # Check for common IoT credentials in payload
            payload = tcp_data.get('data', '')
            common_creds = [
                'admin:admin', 'root:root', 'admin:password',
                'admin:', 'root:admin', 'admin:123456',
                'root:123456', 'admin:1234', 'root:1234'
            ]

            return any(cred in payload.lower() for cred in common_creds)

        return False

    def _check_payload_signatures(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Check payload for IoT malware signatures"""
        # Check TCP payload
        tcp_data = packet_data.get('tcp', {})
        if tcp_data and tcp_data.get('data'):
            for malware_name, pattern in self.iot_signatures.items():
                if pattern.search(tcp_data['data']):
                    return ThreatResult(
                        threat_type=f'iot_malware_{malware_name}',
                        severity='critical',
                        confidence=0.95,
                        description=f'IoT malware {malware_name} detected',
                        indicators=[tcp_data['data'][:100]],  # First 100 chars
                        metadata={'malware_family': malware_name}
                    )

        # Check UDP payload
        udp_data = packet_data.get('udp', {})
        if udp_data and udp_data.get('data'):
            for malware_name, pattern in self.iot_signatures.items():
                if pattern.search(udp_data['data']):
                    return ThreatResult(
                        threat_type=f'iot_malware_{malware_name}',
                        severity='critical',
                        confidence=0.95,
                        description=f'IoT malware {malware_name} detected',
                        indicators=[udp_data['data'][:100]],
                        metadata={'malware_family': malware_name}
                    )

        return None

    def _detect_scanning_behavior(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Detect port scanning and reconnaissance behavior"""
        ip_data = packet_data.get('ip', {})
        tcp_data = packet_data.get('tcp', {})

        if not ip_data or not tcp_data:
            return None

        src_ip = ip_data.get('src')
        dst_port = tcp_data.get('dstport')
        flags = tcp_data.get('flags', '')

        # Track scanning behavior per source IP
        if src_ip not in self.scanning_patterns:
            self.scanning_patterns[src_ip] = {
                'ports_scanned': set(),
                'syn_packets': 0,
                'start_time': packet_data.get('timestamp')
            }

        pattern = self.scanning_patterns[src_ip]

        # Count SYN packets (potential port scan)
        if 'SYN' in flags and 'ACK' not in flags:
            pattern['syn_packets'] += 1
            pattern['ports_scanned'].add(dst_port)

        # Detect port scanning (multiple ports from same source)
        if len(pattern['ports_scanned']) > 10 and pattern['syn_packets'] > 20:
            return ThreatResult(
                threat_type='iot_port_scan',
                severity='medium',
                confidence=0.8,
                description='IoT device port scanning detected',
                indicators=[src_ip, f"ports: {sorted(list(pattern['ports_scanned']))[:10]}"],
                metadata={
                    'ports_scanned': len(pattern['ports_scanned']),
                    'syn_packets': pattern['syn_packets']
                }
            )

        return None


class CryptocurrencyMiningDetectionPlugin(OptimusPlugin):
    """Plugin for detecting cryptocurrency mining activity"""

    def __init__(self):
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.mining_pools = self._load_mining_pools()
        self.stratum_patterns = self._load_stratum_patterns()

    def get_name(self) -> str:
        return "CryptocurrencyMiningDetection"

    def get_version(self) -> str:
        return "1.0.0"

    def get_description(self) -> str:
        return "Detect cryptocurrency mining and cryptojacking"

    def _load_mining_pools(self) -> List[str]:
        """Load known mining pool domains"""
        return [
            'pool.minergate.com', 'xmr.pool.minergate.com',
            'stratum.slushpool.com', 'eu.stratum.slushpool.com',
            'pool.supportxmr.com', 'mine.moneropool.com',
            'monerohash.com', 'xmrpool.eu', 'dwarfpool.com',
            'nanopool.org', 'ethermine.org', 'f2pool.com'
        ]

    def _load_stratum_patterns(self) -> List[re.Pattern]:
        """Load Stratum protocol patterns"""
        return [
            re.compile(r'stratum\+tcp://', re.I),
            re.compile(r'"method"\s*:\s*"mining\.', re.I),
            re.compile(r'"mining\.authorize"', re.I),
            re.compile(r'"mining\.submit"', re.I),
            re.compile(r'"mining\.subscribe"', re.I),
            re.compile(r'"result"\s*:\s*true.*"error"\s*:\s*null', re.I)
        ]

    def analyze_packet(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Analyze packet for cryptocurrency mining"""
        # Check DNS queries for mining pools
        dns_threat = self._check_mining_pool_dns(packet_data)
        if dns_threat:
            return dns_threat

        # Check TCP traffic for Stratum protocol
        stratum_threat = self._check_stratum_protocol(packet_data)
        if stratum_threat:
            return stratum_threat

        # Check HTTP traffic for browser-based mining
        browser_mining_threat = self._check_browser_mining(packet_data)
        if browser_mining_threat:
            return browser_mining_threat

        return None

    def _check_mining_pool_dns(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Check DNS queries for known mining pools"""
        dns_data = packet_data.get('dns', {})
        query = dns_data.get('query', '').lower()

        for pool in self.mining_pools:
            if pool.lower() in query:
                return ThreatResult(
                    threat_type='crypto_mining_dns',
                    severity='medium',
                    confidence=0.9,
                    description='DNS query to known mining pool',
                    indicators=[query, pool],
                    metadata={'mining_pool': pool}
                )

        return None

    def _check_stratum_protocol(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Check for Stratum mining protocol"""
        tcp_data = packet_data.get('tcp', {})
        payload = tcp_data.get('data', '')

        if not payload:
            return None

        # Check for Stratum protocol patterns
        for pattern in self.stratum_patterns:
            if pattern.search(payload):
                return ThreatResult(
                    threat_type='crypto_mining_stratum',
                    severity='high',
                    confidence=0.95,
                    description='Stratum mining protocol detected',
                    indicators=[payload[:200]],  # First 200 chars
                    metadata={
                        'protocol': 'stratum',
                        'port': tcp_data.get('dstport', 'unknown')
                    }
                )

        return None

    def _check_browser_mining(self, packet_data: Dict[str, Any]) -> Optional[ThreatResult]:
        """Check for browser-based cryptocurrency mining"""
        http_data = packet_data.get('http', {})

        # Check HTTP requests for mining scripts
        if 'request' in http_data:
            uri = http_data['request'].get('uri', '')
            user_agent = http_data['request'].get('header', {}).get('user-agent', '')

            # Known cryptojacking scripts and miners
            mining_scripts = [
                'coinhive', 'cryptoloot', 'jsecoin', 'mineralt',
                'webminerpool', 'crypto-webminer', 'minero.js'
            ]

            for script in mining_scripts:
                if script in uri.lower() or script in user_agent.lower():
                    return ThreatResult(
                        threat_type='browser_cryptojacking',
                        severity='high',
                        confidence=0.85,
                        description='Browser-based cryptojacking detected',
                        indicators=[uri, user_agent],
                        metadata={'mining_script': script}
                    )

        return None


# Plugin manager for loading and managing plugins
class PluginManager:
    """Manage Optimus plugins"""

    def __init__(self, plugin_directory: str = "plugins/"):
        self.plugin_directory = plugin_directory
        self.loaded_plugins: List[OptimusPlugin] = []
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def load_plugins(self) -> List[OptimusPlugin]:
        """Load all plugins from plugin directory"""
        import importlib.util
        import os

        plugins = []

        # Load built-in plugins
        built_in_plugins = [
            AdvancedThreatHuntingPlugin(),
            IoTBotnetDetectionPlugin(),
            CryptocurrencyMiningDetectionPlugin()
        ]

        for plugin in built_in_plugins:
            try:
                if plugin.initialize({}):
                    plugins.append(plugin)
                    self.logger.info(f"Loaded built-in plugin: {plugin.get_name()}")
            except Exception as e:
                self.logger.error(f"Failed to initialize plugin {plugin.get_name()}: {e}")

        # Load external plugins from directory
        if os.path.exists(self.plugin_directory):
            for filename in os.listdir(self.plugin_directory):
                if filename.endswith('.py') and not filename.startswith('__'):
                    try:
                        plugin_path = os.path.join(self.plugin_directory, filename)
                        spec = importlib.util.spec_from_file_location(
                            filename[:-3], plugin_path
                        )
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        # Find plugin classes in module
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (isinstance(attr, type) and
                                issubclass(attr, OptimusPlugin) and
                                attr != OptimusPlugin):

                                plugin_instance = attr()
                                if plugin_instance.initialize({}):
                                    plugins.append(plugin_instance)
                                    self.logger.info(f"Loaded external plugin: {plugin_instance.get_name()}")

                    except Exception as e:
                        self.logger.error(f"Failed to load plugin {filename}: {e}")

        self.loaded_plugins = plugins
        return plugins

    def analyze_packet_with_plugins(self, packet_data: Dict[str, Any]) -> List[ThreatResult]:
        """Analyze packet with all loaded plugins"""
        threat_results = []

        for plugin in self.loaded_plugins:
            try:
                result = plugin.analyze_packet(packet_data)
                if result:
                    threat_results.append(result)
            except Exception as e:
                self.logger.error(f"Plugin {plugin.get_name()} failed: {e}")

        return threat_results

    def cleanup_plugins(self):
        """Cleanup all loaded plugins"""
        for plugin in self.loaded_plugins:
            try:
                plugin.cleanup()
            except Exception as e:
                self.logger.error(f"Failed to cleanup plugin {plugin.get_name()}: {e}")


if __name__ == "__main__":
    # Example usage
    manager = PluginManager()
    plugins = manager.load_plugins()

    print(f"Loaded {len(plugins)} plugins:")
    for plugin in plugins:
        print(f"  - {plugin.get_name()} v{plugin.get_version()}: {plugin.get_description()}")

    # Example packet data for testing
    test_packet = {
        'id': 'test-123',
        'protos': {'l7': 'http'},
        'http': {
            'request': {
                'uri': '/coinhive.min.js',
                'header': {
                    'user-agent': 'Mozilla/5.0 CoinHive Miner'
                }
            }
        },
        'dns': {
            'query': 'pool.minergate.com'
        }
    }

    # Test plugins
    results = manager.analyze_packet_with_plugins(test_packet)
    print(f"\nThreat analysis results: {len(results)} threats found")
    for result in results:
        print(f"  - {result.threat_type}: {result.description} (Severity: {result.severity})")

    manager.cleanup_plugins()
