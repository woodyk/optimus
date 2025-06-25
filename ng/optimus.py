#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# File: optimus.py
# Author: Wadih Khairallah
# Description: 
# Created: 2025-06-04 07:19:16
"""
File: optimus.py
Author: Wadih Khairallah
Description: Network packet analyzer and threat detection platform
Created: 2025-06-03 (Converted from Perl)
"""

import argparse
import asyncio
import json
import logging
import signal
import socket
import struct
import sys
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
import threading

# Third-party imports
import dpkt
import pcap
import requests
import yaml
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError as ESConnectionError
import maxminddb
import dns.resolver
import dns.reversename
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import numpy as np
from scipy import stats
import pandas as pd

# Configuration
CONFIG_FILE = "optimus_config.yaml"
OUI_FILE = "/tmp/wireshark_oui.txt"
OUI_URL = "https://gitlab.com/wireshark/wireshark/-/raw/master/manuf"
GEOIP_DB = "../lib/GeoLite2-City.mmdb"


@dataclass
class PacketData:
    """Data structure for parsed packet information"""
    id: str
    timestamp: str
    hostname: str
    interface: str
    datasource: str
    protos: Dict[str, str]
    mac: Optional[Dict[str, Any]] = None
    ip: Optional[Dict[str, Any]] = None
    tcp: Optional[Dict[str, Any]] = None
    udp: Optional[Dict[str, Any]] = None
    icmp: Optional[Dict[str, Any]] = None
    arp: Optional[Dict[str, Any]] = None
    geoip: Optional[Dict[str, Any]] = None
    dns: Optional[Dict[str, Any]] = None
    threats: Optional[List[str]] = None
    anomalies: Optional[List[str]] = None
    tags: Optional[List[str]] = None


class ThreatDetector:
    """Advanced threat detection engine using pattern matching"""
    
    def __init__(self, rules_file: Optional[str] = None):
        self.signatures = {}
        self.behavioral_patterns = {}
        self.load_default_signatures()
        if rules_file:
            self.load_custom_rules(rules_file)
    
    def load_default_signatures(self):
        """Load built-in threat signatures"""
        self.signatures = {
            'malware_c2': re.compile(r'(?:\.bit|\.onion)\b.*(?:\/[a-f0-9]{32}|\/gate\.php)', re.I),
            'crypto_mining': re.compile(r'stratum\+tcp|mining\.pool|getwork|submit', re.I),
            'data_exfil': re.compile(r'(?:password|login|token|key)[:=]\s*[\w\-]{8,}', re.I),
            'sql_injection': re.compile(r'(?:union.*select|insert.*into|drop.*table)', re.I),
            'xss_attempt': re.compile(r'<script|javascript:|onload=|onerror=', re.I),
            'directory_traversal': re.compile(r'\.\.\/|\.\.\\|%2e%2e%2f', re.I),
        }
    
    def load_custom_rules(self, rules_file: str):
        """Load custom rules from YAML file"""
        try:
            with open(rules_file, 'r') as f:
                rules = yaml.safe_load(f)
                for rule_name, rule_data in rules.get('signatures', {}).items():
                    self.signatures[rule_name] = re.compile(rule_data['pattern'], re.I)
        except Exception as e:
            logging.error(f"Failed to load custom rules: {e}")
    
    def detect_threats(self, payload: str) -> List[str]:
        """Detect threats in packet payload"""
        threats = []
        for threat_name, pattern in self.signatures.items():
            if pattern.search(payload):
                threats.append(threat_name)
        return threats


class ConnectionTracker:
    """Track network connections and detect anomalies"""
    
    def __init__(self, max_connections: int = 10000):
        self.connections = {}
        self.flow_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        self.max_connections = max_connections
        self.lock = threading.Lock()
    
    def track_connection(self, src_ip: str, dst_ip: str, src_port: int, 
                        dst_port: int, proto: str, packet_size: int) -> Dict[str, Any]:
        """Track connection and detect anomalies"""
        flow_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{proto}"
        
        with self.lock:
            if flow_id not in self.connections:
                self.connections[flow_id] = {
                    'start_time': time.time(),
                    'packet_count': 0,
                    'byte_count': 0,
                    'last_seen': time.time(),
                    'flags': [],
                    'anomalies': []
                }
            
            conn = self.connections[flow_id]
            conn['packet_count'] += 1
            conn['byte_count'] += packet_size
            conn['last_seen'] = time.time()
            
            # Detect anomalies
            if self._detect_long_lived_connection(conn):
                conn['anomalies'].append('long_lived_connection')
            
            if self._detect_high_volume_connection(conn):
                conn['anomalies'].append('high_volume_connection')
            
            # Cleanup old connections
            if len(self.connections) > self.max_connections:
                self._cleanup_old_connections()
            
            return conn.copy()
    
    def _detect_long_lived_connection(self, conn: Dict) -> bool:
        """Detect abnormally long-lived connections"""
        duration = time.time() - conn['start_time']
        return conn['packet_count'] > 1000 and duration > 3600
    
    def _detect_high_volume_connection(self, conn: Dict) -> bool:
        """Detect high-volume data transfers"""
        return conn['byte_count'] > 100 * 1024 * 1024  # 100MB
    
    def _cleanup_old_connections(self):
        """Remove old connections to prevent memory leaks"""
        current_time = time.time()
        old_flows = [
            flow_id for flow_id, conn in self.connections.items()
            if current_time - conn['last_seen'] > 3600  # 1 hour
        ]
        for flow_id in old_flows:
            del self.connections[flow_id]


class DNSAnalyzer:
    """Advanced DNS analysis and threat detection"""
    
    def __init__(self):
        self.dns_cache = {}
        self.suspicious_domains = set()
        self.entropy_threshold = 4.5
    
    def analyze_dns_query(self, domain: str) -> Dict[str, Any]:
        """Analyze DNS query for threats"""
        result = {
            'domain': domain,
            'threats': [],
            'entropy': self._calculate_entropy(domain),
            'is_dga': False,
            'is_tunneling': False
        }
        
        # DNS tunneling detection
        if self._detect_dns_tunneling(domain):
            result['threats'].append('dns_tunneling')
            result['is_tunneling'] = True
        
        # DGA detection
        if self._detect_dga(domain):
            result['threats'].append('dga_domain')
            result['is_dga'] = True
        
        # Suspicious TLD check
        if self._check_suspicious_tld(domain):
            result['threats'].append('suspicious_tld')
        
        return result
    
    def _calculate_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of domain name"""
        if not domain:
            return 0.0
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in domain:
            char_counts[char] += 1
        
        # Calculate entropy
        domain_len = len(domain)
        entropy = 0.0
        for count in char_counts.values():
            probability = count / domain_len
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _detect_dns_tunneling(self, domain: str) -> bool:
        """Detect DNS tunneling patterns"""
        parts = domain.split('.')
        
        # Check for high entropy in subdomains
        for part in parts:
            if len(part) > 20 and self._calculate_entropy(part) > self.entropy_threshold:
                return True
        
        # Check for base64-like patterns
        if re.search(r'[a-zA-Z0-9+/]{20,}={0,2}', domain):
            return True
        
        # Check for hex patterns
        if re.search(r'[a-f0-9]{32,}', domain):
            return True
        
        return False
    
    def _detect_dga(self, domain: str) -> bool:
        """Detect Domain Generation Algorithm patterns"""
        # Remove TLD for analysis
        domain_parts = domain.split('.')
        if len(domain_parts) < 2:
            return False
        
        domain_name = domain_parts[0]
        
        # Check length and entropy
        if len(domain_name) > 12 and self._calculate_entropy(domain_name) > 3.5:
            # Check for consonant/vowel patterns
            consonants = sum(1 for c in domain_name if c in 'bcdfghjklmnpqrstvwxyz')
            vowels = sum(1 for c in domain_name if c in 'aeiou')
            
            if consonants > vowels * 3:  # Too many consonants
                return True
        
        return False
    
    def _check_suspicious_tld(self, domain: str) -> bool:
        """Check for suspicious top-level domains"""
        suspicious_tlds = {'.tk', '.ml', '.ga', '.cf', '.bit', '.onion'}
        return any(domain.endswith(tld) for tld in suspicious_tlds)


class TLSAnalyzer:
    """TLS/SSL certificate analysis"""
    
    def analyze_tls_handshake(self, tls_data: bytes) -> Optional[Dict[str, Any]]:
        """Analyze TLS handshake and extract certificate info"""
        try:
            # Look for certificate in TLS handshake
            if not self._is_tls_handshake(tls_data):
                return None
            
            cert_data = self._extract_certificate(tls_data)
            if not cert_data:
                return None
            
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
            
            return {
                'subject': cert.subject.rfc4514_string(),
                'issuer': cert.issuer.rfc4514_string(),
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'fingerprint': hashlib.sha256(cert_data).hexdigest(),
                'self_signed': cert.subject == cert.issuer,
                'expired': datetime.now(timezone.utc) > cert.not_valid_after.replace(tzinfo=timezone.utc),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'public_key_algorithm': cert.public_key().__class__.__name__
            }
        except Exception as e:
            logging.debug(f"TLS analysis failed: {e}")
            return None
    
    def _is_tls_handshake(self, data: bytes) -> bool:
        """Check if data contains TLS handshake"""
        return len(data) > 5 and data[0] == 0x16 and data[1:3] == b'\x03'
    
    def _extract_certificate(self, tls_data: bytes) -> Optional[bytes]:
        """Extract certificate from TLS handshake"""
        # Simplified certificate extraction
        # In practice, you'd need more robust TLS parsing
        try:
            # Look for certificate message (type 11)
            cert_start = tls_data.find(b'\x0b\x00')
            if cert_start == -1:
                return None
            
            # Extract certificate length and data
            # This is a simplified implementation
            if len(tls_data) > cert_start + 7:
                cert_len = struct.unpack('>I', b'\x00' + tls_data[cert_start+4:cert_start+7])[0]
                cert_data_start = cert_start + 10  # Skip headers
                if len(tls_data) >= cert_data_start + cert_len:
                    return tls_data[cert_data_start:cert_data_start + cert_len]
            
            return None
        except Exception:
            return None


class OptimusAnalyzer:
    """Main packet analyzer class"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.hostname = socket.gethostname()
        self.packet_count = 0
        self.packets = {}
        self.oui_data = {}
        
        # Initialize components
        self.threat_detector = ThreatDetector(config.get('rules_file'))
        self.connection_tracker = ConnectionTracker()
        self.dns_analyzer = DNSAnalyzer()
        self.tls_analyzer = TLSAnalyzer()
        
        # Initialize optional components
        self.geoip_reader = None
        self.es_client = None
        
        if config.get('geoip_enabled'):
            self._init_geoip()
        
        if config.get('elasticsearch', {}).get('enabled'):
            self._init_elasticsearch()
        
        self._load_oui_data()
    
    def _init_geoip(self):
        """Initialize GeoIP database"""
        try:
            self.geoip_reader = maxminddb.open_database(GEOIP_DB)
        except Exception as e:
            logging.error(f"Failed to load GeoIP database: {e}")
    
    def _init_elasticsearch(self):
        """Initialize Elasticsearch connection"""
        try:
            es_config = self.config['elasticsearch']
            self.es_client = Elasticsearch([es_config['host']])
        except Exception as e:
            logging.error(f"Failed to connect to Elasticsearch: {e}")
    
    def _load_oui_data(self):
        """Load OUI (Organizationally Unique Identifier) data"""
        try:
            # Download OUI file if needed
            if not Path(OUI_FILE).exists() or self._is_oui_file_old():
                self._download_oui_file()
            
            # Parse OUI file
            with open(OUI_FILE, 'r') as f:
                for line in f:
                    if not line.startswith('#') and '\t' in line:
                        parts = line.strip().split('\t')
                        if len(parts) >= 2:
                            address = parts[0].replace(':', '').upper()
                            vendor = parts[1] if len(parts) == 2 else parts[2]
                            self.oui_data[address] = vendor
            
            self.oui_data['FFFFFF'] = 'broadcast'
            logging.info(f"Loaded {len(self.oui_data)} OUI entries")
            
        except Exception as e:
            logging.error(f"Failed to load OUI data: {e}")
    
    def _is_oui_file_old(self) -> bool:
        """Check if OUI file needs updating"""
        try:
            file_age = time.time() - Path(OUI_FILE).stat().st_mtime
            return file_age > 86400  # 24 hours
        except:
            return True
    
    def _download_oui_file(self):
        """Download latest OUI file"""
        try:
            response = requests.get(OUI_URL, timeout=30)
            response.raise_for_status()
            with open(OUI_FILE, 'w') as f:
                f.write(response.text)
            logging.info("Downloaded latest OUI file")
        except Exception as e:
            logging.error(f"Failed to download OUI file: {e}")
    
    def capture_packets(self, interface: str, count: int = -1, pcap_file: str = None):
        """Capture and analyze packets"""
        try:
            if pcap_file:
                self._process_pcap_file(pcap_file, count)
            else:
                self._capture_live(interface, count)
                
        except KeyboardInterrupt:
            logging.info("Capture interrupted by user")
        except Exception as e:
            logging.error(f"Capture failed: {e}")
        finally:
            self._output_results()
    
    def _process_pcap_file(self, pcap_file: str, count: int):
        """Process packets from pcap file"""
        with open(pcap_file, 'rb') as f:
            pcap_reader = dpkt.pcap.Reader(f)
            
            for i, (timestamp, packet_data) in enumerate(pcap_reader):
                if count > 0 and i >= count:
                    break
                
                self._parse_packet(packet_data, timestamp)
                
                if i % 1000 == 0:
                    logging.info(f"Processed {i} packets")
    
    def _capture_live(self, interface: str, count: int):
        """Capture live packets from interface"""
        try:
            pc = pcap.pcap(name=interface, promisc=True, immediate=True, timeout_ms=100)
            
            for timestamp, packet_data in pc:
                if count > 0 and self.packet_count >= count:
                    break
                
                self._parse_packet(packet_data, timestamp)
                
                if self.packet_count % 1000 == 0:
                    logging.info(f"Captured {self.packet_count} packets")
                    
        except Exception as e:
            logging.error(f"Live capture failed: {e}")
    
    def _parse_packet(self, packet_data: bytes, timestamp: float):
        """Parse individual packet"""
        try:
            packet_id = str(uuid.uuid4())
            packet_time = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
            
            # Initialize packet data structure
            packet = PacketData(
                id=packet_id,
                timestamp=packet_time,
                hostname=self.hostname,
                interface=self.config.get('interface', 'unknown'),
                datasource=self.config.get('datasource', 'live'),
                protos={'l2': 'unknown', 'l3': 'unknown', 'l4': 'unknown', 'l7': 'unknown'},
                threats=[],
                anomalies=[],
                tags=[]
            )
            
            # Parse Ethernet layer
            try:
                eth = dpkt.ethernet.Ethernet(packet_data)
                self._parse_ethernet(packet, eth)
            except Exception as e:
                logging.debug(f"Ethernet parsing failed: {e}")
                return
            
            self.packets[packet_id] = packet
            self.packet_count += 1
            
        except Exception as e:
            logging.debug(f"Packet parsing failed: {e}")
    
    def _parse_ethernet(self, packet: PacketData, eth):
        """Parse Ethernet layer"""
        # Extract MAC addresses
        src_mac = ':'.join(['%02x' % b for b in eth.src]).upper()
        dst_mac = ':'.join(['%02x' % b for b in eth.dst]).upper()
        
        packet.mac = {
            'src': src_mac,
            'dst': dst_mac,
            'src_vendor': self._get_vendor(src_mac),
            'dst_vendor': self._get_vendor(dst_mac)
        }
        
        # Parse based on EtherType
        if isinstance(eth.data, dpkt.ip.IP):
            packet.protos['l2'] = 'ip_route'
            self._parse_ip(packet, eth.data)
        elif isinstance(eth.data, dpkt.ip6.IP6):
            packet.protos['l2'] = 'ip_route'
            packet.protos['l3'] = 'ipv6'
            self._parse_ipv6(packet, eth.data)
        elif isinstance(eth.data, dpkt.arp.ARP):
            packet.protos['l2'] = 'arp'
            self._parse_arp(packet, eth.data)
    
    def _get_vendor(self, mac_address: str) -> str:
        """Get vendor from MAC address using OUI data"""
        oui = mac_address.replace(':', '')[:6]
        return self.oui_data.get(oui, 'unknown')
    
    def _parse_ip(self, packet: PacketData, ip):
        """Parse IPv4 packet"""
        packet.protos['l3'] = 'ip'
        
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        
        packet.ip = {
            'src': src_ip,
            'dst': dst_ip,
            'proto': ip.p,
            'ttl': ip.ttl,
            'len': ip.len,
            'tos': ip.tos,
            'flags': ip.off & dpkt.ip.IP_DF,
            'ver': ip.v,
            'type': self._classify_ip_type(dst_ip)
        }
        
        # Add GeoIP data if enabled
        if self.geoip_reader:
            packet.geoip = self._get_geoip_data(src_ip, dst_ip)
        
        # Parse transport layer
        if isinstance(ip.data, dpkt.tcp.TCP):
            self._parse_tcp(packet, ip.data, src_ip, dst_ip)
        elif isinstance(ip.data, dpkt.udp.UDP):
            self._parse_udp(packet, ip.data, src_ip, dst_ip)
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            self._parse_icmp(packet, ip.data)
    
    def _parse_ipv6(self, packet: PacketData, ip6):
        """Parse IPv6 packet"""
        # Convert IPv6 addresses to string format
        src_ip = socket.inet_ntop(socket.AF_INET6, ip6.src)
        dst_ip = socket.inet_ntop(socket.AF_INET6, ip6.dst)
        
        packet.ip = {
            'src': src_ip,
            'dst': dst_ip,
            'proto': ip6.nxt,
            'hop_limit': ip6.hlim,
            'len': ip6.plen,
            'ver': 6,
            'type': 'multicast' if dst_ip.startswith('ff') else 'unicast'
        }
    
    def _parse_arp(self, packet: PacketData, arp):
        """Parse ARP packet"""
        packet.arp = {
            'htype': arp.hrd,
            'proto': arp.pro,
            'hlen': arp.hln,
            'opcode': arp.op,
            'sha': ':'.join(['%02x' % b for b in arp.sha]).upper(),
            'spa': socket.inet_ntoa(arp.spa),
            'tha': ':'.join(['%02x' % b for b in arp.tha]).upper(),
            'tpa': socket.inet_ntoa(arp.tpa)
        }
    
    def _parse_tcp(self, packet: PacketData, tcp, src_ip: str, dst_ip: str):
        """Parse TCP packet"""
        packet.protos['l4'] = 'tcp'
        
        # Extract TCP flags
        flags = []
        if tcp.flags & dpkt.tcp.TH_FIN: flags.append('FIN')
        if tcp.flags & dpkt.tcp.TH_SYN: flags.append('SYN')
        if tcp.flags & dpkt.tcp.TH_RST: flags.append('RST')
        if tcp.flags & dpkt.tcp.TH_PUSH: flags.append('PSH')
        if tcp.flags & dpkt.tcp.TH_ACK: flags.append('ACK')
        if tcp.flags & dpkt.tcp.TH_URG: flags.append('URG')
        if tcp.flags & dpkt.tcp.TH_ECE: flags.append('ECE')
        if tcp.flags & dpkt.tcp.TH_CWR: flags.append('CWR')
        
        packet.tcp = {
            'srcport': tcp.sport,
            'dstport': tcp.dport,
            'seqnum': tcp.seq,
            'acknum': tcp.ack,
            'flags': ':'.join(flags),
            'winsize': tcp.win,
            'cksum': tcp.sum
        }
        
        # Track connection
        conn_info = self.connection_tracker.track_connection(
            src_ip, dst_ip, tcp.sport, tcp.dport, 'tcp', len(tcp.data)
        )
        
        if conn_info.get('anomalies'):
            packet.anomalies.extend(conn_info['anomalies'])
        
        # Analyze application layer
        if tcp.data:
            self._analyze_application_layer(packet, tcp.data, tcp.sport, tcp.dport)
    
    def _parse_udp(self, packet: PacketData, udp, src_ip: str, dst_ip: str):
        """Parse UDP packet"""
        packet.protos['l4'] = 'udp'
        
        packet.udp = {
            'srcport': udp.sport,
            'dstport': udp.dport,
            'len': udp.ulen
        }
        
        # Track connection
        conn_info = self.connection_tracker.track_connection(
            src_ip, dst_ip, udp.sport, udp.dport, 'udp', len(udp.data)
        )
        
        # Analyze application layer
        if udp.data:
            self._analyze_application_layer(packet, udp.data, udp.sport, udp.dport)
    
    def _parse_icmp(self, packet: PacketData, icmp):
        """Parse ICMP packet"""
        packet.protos['l4'] = 'icmp'
        
        packet.icmp = {
            'type': icmp.type,
            'code': icmp.code
        }
    
    def _analyze_application_layer(self, packet: PacketData, payload: bytes, sport: int, dport: int):
        """Analyze application layer protocols"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore')
        except:
            payload_str = str(payload)
        
        # HTTP detection
        if self._is_http_traffic(payload_str, sport, dport):
            packet.protos['l7'] = 'http'
            self._analyze_http(packet, payload_str)
        
        # DNS detection
        elif sport == 53 or dport == 53:
            packet.protos['l7'] = 'dns'
            self._analyze_dns(packet, payload)
        
        # SSH detection
        elif sport == 22 or dport == 22 or payload_str.startswith('SSH-'):
            packet.protos['l7'] = 'ssh'
        
        # TLS/SSL detection
        elif self._is_tls_traffic(payload):
            packet.protos['l7'] = 'tls'
            tls_info = self.tls_analyzer.analyze_tls_handshake(payload)
            if tls_info:
                packet.tls = tls_info
        
        # Threat detection
        threats = self.threat_detector.detect_threats(payload_str)
        if threats:
            packet.threats.extend(threats)
    
    def _is_http_traffic(self, payload: str, sport: int, dport: int) -> bool:
        """Detect HTTP traffic"""
        http_methods = ['GET', 'POST', 'HEAD', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']
        return (sport in [80, 443, 8080, 8443] or dport in [80, 443, 8080, 8443] or
                any(payload.startswith(method) for method in http_methods) or
                payload.startswith('HTTP/'))
    
    def _is_tls_traffic(self, payload: bytes) -> bool:
        """Detect TLS/SSL traffic"""
        return (len(payload) > 5 and payload[0] == 0x16 and 
                payload[1:3] in [b'\x03\x01', b'\x03\x02', b'\x03\x03'])
    
    def _analyze_http(self, packet: PacketData, payload: str):
        """Analyze HTTP traffic"""
        lines = payload.split('\n')
        if not lines:
            return
        
        first_line = lines[0].strip()
        
        # HTTP request
        if any(first_line.startswith(method) for method in ['GET', 'POST', 'HEAD', 'PUT', 'DELETE']):
            parts = first_line.split(' ')
            if len(parts) >= 3:
                packet.http = {
                    'request': {
                        'method': parts[0],
                        'uri': parts[1],
                        'version': parts[2]
                    }
                }
        
        # HTTP response
        elif first_line.startswith('HTTP/'):
            parts = first_line.split(' ')
            if len(parts) >= 3:
                packet.http = {
                    'response': {
                        'version': parts[0],
                        'code': parts[1],
                        'status': ' '.join(parts[2:])
                    }
                }
    
    def _analyze_dns(self, packet: PacketData, payload: bytes):
        """Analyze DNS traffic"""
        try:
            # Simple DNS query extraction (simplified)
            if len(payload) > 12:  # DNS header is 12 bytes
                # Extract query name (simplified parsing)
                query_start = 12
                domain_parts = []
                pos = query_start
                
                while pos < len(payload) and payload[pos] != 0:
                    length = payload[pos]
                    if length > 63 or pos + length + 1 > len(payload):
                        break
                    
                    pos += 1
                    if length > 0:
                        domain_part = payload[pos:pos + length].decode('utf-8', errors='ignore')
                        domain_parts.append(domain_part)
                        pos += length
                
                if domain_parts:
                    domain = '.'.join(domain_parts)
                    dns_analysis = self.dns_analyzer.analyze_dns_query(domain)
                    
                    packet.dns = {
                        'query': domain,
                        'entropy': dns_analysis['entropy'],
                        'is_dga': dns_analysis['is_dga'],
                        'is_tunneling': dns_analysis['is_tunneling']
                    }
                    
                    if dns_analysis['threats']:
                        packet.threats.extend(dns_analysis['threats'])
                        
        except Exception as e:
            logging.debug(f"DNS analysis failed: {e}")
    
    def _classify_ip_type(self, ip: str) -> str:
        """Classify IP address type"""
        if ip == '255.255.255.255':
            return 'broadcast'
        elif ip.startswith(('224.', '225.', '226.', '227.', '228.', '229.', '230.', '231.', 
                           '232.', '233.', '234.', '235.', '236.', '237.', '238.', '239.')):
            return 'multicast'
        else:
            return 'unicast'
    
    def _get_geoip_data(self, src_ip: str, dst_ip: str) -> Dict[str, Any]:
        """Get GeoIP information for source and destination IPs"""
        geoip_data = {}
        
        try:
            # Source IP GeoIP
            src_record = self.geoip_reader.get(src_ip)
            if src_record:
                geoip_data['src'] = {
                    'country_code': src_record.get('country', {}).get('iso_code'),
                    'country_name': src_record.get('country', {}).get('names', {}).get('en'),
                    'city': src_record.get('city', {}).get('names', {}).get('en'),
                    'postal_code': src_record.get('postal', {}).get('code'),
                    'latitude': src_record.get('location', {}).get('latitude'),
                    'longitude': src_record.get('location', {}).get('longitude'),
                    'time_zone': src_record.get('location', {}).get('time_zone'),
                    'continent': src_record.get('continent', {}).get('names', {}).get('en')
                }
            
            # Destination IP GeoIP
            dst_record = self.geoip_reader.get(dst_ip)
            if dst_record:
                geoip_data['dst'] = {
                    'country_code': dst_record.get('country', {}).get('iso_code'),
                    'country_name': dst_record.get('country', {}).get('names', {}).get('en'),
                    'city': dst_record.get('city', {}).get('names', {}).get('en'),
                    'postal_code': dst_record.get('postal', {}).get('code'),
                    'latitude': dst_record.get('location', {}).get('latitude'),
                    'longitude': dst_record.get('location', {}).get('longitude'),
                    'time_zone': dst_record.get('location', {}).get('time_zone'),
                    'continent': dst_record.get('continent', {}).get('names', {}).get('en')
                }
                
        except Exception as e:
            logging.debug(f"GeoIP lookup failed: {e}")
        
        return geoip_data
    
    def _output_results(self):
        """Output analysis results"""
        if self.config.get('output_json'):
            self._output_json()
        
        if self.es_client:
            self._output_elasticsearch()
        
        logging.info(f"Processed {self.packet_count} packets")
    
    def _output_json(self):
        """Output results as JSON"""
        packet_list = []
        for packet in self.packets.values():
            packet_dict = asdict(packet)
            # Remove None values
            packet_dict = {k: v for k, v in packet_dict.items() if v is not None}
            packet_list.append(packet_dict)
        
        print(json.dumps(packet_list, indent=2, default=str))
    
    def _output_elasticsearch(self):
        """Output results to Elasticsearch"""
        try:
            actions = []
            index_name = f"packets_{datetime.now().strftime('%Y.%m.%d.%H')}"
            
            for packet_id, packet in self.packets.items():
                packet_dict = asdict(packet)
                # Remove None values
                packet_dict = {k: v for k, v in packet_dict.items() if v is not None}
                
                action = {
                    '_index': index_name,
                    '_id': packet_id,
                    '_source': packet_dict
                }
                actions.append(action)
            
            if actions:
                helpers.bulk(self.es_client, actions)
                logging.info(f"Wrote {len(actions)} packets to Elasticsearch")
                
        except Exception as e:
            logging.error(f"Elasticsearch output failed: {e}")


class BehavioralAnalyzer:
    """Behavioral analysis for detecting anomalies over time"""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.host_profiles = defaultdict(lambda: {
            'packet_times': deque(maxlen=window_size),
            'packet_sizes': deque(maxlen=window_size),
            'protocols': defaultdict(int),
            'connections': defaultdict(int)
        })
    
    def update_profile(self, src_ip: str, packet_size: int, protocol: str, timestamp: float):
        """Update host behavioral profile"""
        profile = self.host_profiles[src_ip]
        profile['packet_times'].append(timestamp)
        profile['packet_sizes'].append(packet_size)
        profile['protocols'][protocol] += 1
        
        # Analyze behavior every 100 packets
        if len(profile['packet_times']) % 100 == 0:
            return self._analyze_behavior(src_ip)
        
        return None
    
    def _analyze_behavior(self, ip: str) -> Dict[str, Any]:
        """Analyze behavioral patterns for anomalies"""
        profile = self.host_profiles[ip]
        
        if len(profile['packet_times']) < 10:
            return {}
        
        times = np.array(list(profile['packet_times']))
        sizes = np.array(list(profile['packet_sizes']))
        
        # Calculate inter-arrival times
        inter_arrivals = np.diff(times)
        
        analysis = {
            'packet_rate': len(times) / (times[-1] - times[0]) if len(times) > 1 else 0,
            'avg_packet_size': np.mean(sizes),
            'size_variance': np.var(sizes),
            'timing_regularity': np.std(inter_arrivals) if len(inter_arrivals) > 0 else 0,
            'protocol_diversity': len(profile['protocols']),
            'anomalies': []
        }
        
        # Detect anomalies
        if analysis['timing_regularity'] < 0.001:  # Very regular timing
            analysis['anomalies'].append('beacon_behavior')
        
        if analysis['size_variance'] < 10 and analysis['avg_packet_size'] > 1000:
            analysis['anomalies'].append('uniform_large_packets')
        
        if analysis['packet_rate'] > 100:  # Very high packet rate
            analysis['anomalies'].append('high_frequency_communication')
        
        return analysis


def load_config(config_file: str) -> Dict[str, Any]:
    """Load configuration from YAML file"""
    default_config = {
        'interface': 'eth0',
        'datasource': 'live',
        'packet_count': 1000,
        'output_json': False,
        'debug': False,
        'geoip_enabled': False,
        'l7_enabled': True,
        'payload_bytes': 1024,
        'elasticsearch': {
            'enabled': False,
            'host': 'localhost:9200'
        }
    }
    
    if Path(config_file).exists():
        try:
            with open(config_file, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
    
    return default_config


def setup_logging(debug: bool = False):
    """Setup logging configuration"""
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('optimus.log')
        ]
    )


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully"""
    logging.info("Received interrupt signal, shutting down...")
    sys.exit(0)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Optimus Network Packet Analyzer')
    parser.add_argument('-i', '--interface', help='Network interface to capture from')
    parser.add_argument('-c', '--count', type=int, help='Number of packets to capture')
    parser.add_argument('-p', '--pcap', help='PCAP file to read from')
    parser.add_argument('--json', action='store_true', help='Output JSON to stdout')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--config', default=CONFIG_FILE, help='Configuration file')
    parser.add_argument('--geoip', action='store_true', help='Enable GeoIP lookups')
    parser.add_argument('--elasticsearch', help='Elasticsearch host:port')
    parser.add_argument('--l7', action='store_true', help='Enable Layer 7 analysis')
    parser.add_argument('--bytes', type=int, help='Payload bytes to capture')
    parser.add_argument('--tag', help='Data source tag')
    parser.add_argument('--dummy', action='store_true', help='Run in dummy mode for testing')
    
    args = parser.parse_args()
    
    # Handle dummy mode
    if args.dummy:
        print("Running in dummy mode...")
        while True:
            time.sleep(120)
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command line arguments
    if args.interface:
        config['interface'] = args.interface
    if args.count:
        config['packet_count'] = args.count
    if args.json:
        config['output_json'] = True
    if args.debug:
        config['debug'] = True
    if args.geoip:
        config['geoip_enabled'] = True
    if args.elasticsearch:
        config['elasticsearch']['enabled'] = True
        config['elasticsearch']['host'] = args.elasticsearch
    if args.l7:
        config['l7_enabled'] = True
    if args.bytes:
        config['payload_bytes'] = args.bytes
    if args.tag:
        config['datasource'] = args.tag
    
    # Setup logging
    setup_logging(config['debug'])
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Validate required parameters
    if not args.pcap and not config.get('interface'):
        parser.error("Either --interface or --pcap must be specified")
    
    if config.get('interface') and not config.get('packet_count'):
        parser.error("Packet count (-c/--count) must be specified for live capture")
    
    # Initialize and run analyzer
    try:
        analyzer = OptimusAnalyzer(config)
        analyzer.capture_packets(
            interface=config.get('interface'),
            count=config.get('packet_count', -1),
            pcap_file=args.pcap
        )
    except Exception as e:
        logging.error(f"Analysis failed: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
