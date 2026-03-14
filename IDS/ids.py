from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress
import re
import os

# try optional yara integration (best-effort)
try:
    import yara
except Exception:
    yara = None

class IntrusionDetectionSystem:
    """Basic Intrusion Detection System"""
    
    def __init__(self, threshold_port_scan=10, threshold_ddos=50, time_window=60, brute_force_threshold=5, brute_force_window=300):
        self.threshold_port_scan = threshold_port_scan
        self.threshold_ddos = threshold_ddos
        self.time_window = time_window
        
        # Data structures for anomaly detection
        self.connection_counts = defaultdict(lambda: deque(maxlen=1000))
        self.port_scan_attempts = defaultdict(lambda: defaultdict(int))
        self.ddos_traffic = defaultdict(lambda: deque(maxlen=1000))
        
        # Brute force tracking: map key -> deque(timestamps)
        # key format: (src_ip, username, service)
        self.auth_failures = defaultdict(lambda: deque())
        self.brute_force_threshold = brute_force_threshold
        self.brute_force_window = brute_force_window  # seconds window for counting failures
        
        # Known malicious patterns & lists
        self.malicious_ips = set()
        self.suspicious_ports = {4444, 31337, 12345}  # Common backdoor ports
        
        # Malware signatures (simple heuristics) + optional compiled yara rules
        self.malware_signatures = []  # list of regex patterns (strings)
        self.yara_rules = None
        self._load_default_signatures()
        
        self.alerts = []
    
    def _load_default_signatures(self):
        """Load some conservative default signatures (can be extended at runtime)."""
        # simple regex substrings that commonly indicate drive-by or malware payloads
        defaults = [
            r'evil\-domain', r'cmd\.exe', r'powershell', r'base64_decode\(', r'var _0x', r'\\\\windows\\\\system32',
            r'CreateRemoteThread', r'LoadLibraryA', r'http[s]?://[^\s]*\.exe\b'
        ]
        self.malware_signatures.extend([re.compile(p, re.IGNORECASE) for p in defaults])
        # try to compile yara rules if a rules.yar file exists
        try:
            rules_path = os.path.join(os.path.dirname(__file__), "yara_rules.yar")
            if yara and os.path.exists(rules_path):
                self.yara_rules = yara.compile(filepath=rules_path)
        except Exception:
            self.yara_rules = None
    
    def load_suspicious_ips_from_file(self, filepath):
        """Load suspicious IPs from a simple text file (one IP per line)."""
        if not os.path.exists(filepath):
            return
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    ip = line.strip()
                    if not ip:
                        continue
                    try:
                        # validate ip
                        _ = ipaddress.ip_address(ip)
                        self.malicious_ips.add(ip)
                    except Exception:
                        # allow CIDR ranges too
                        self.malicious_ips.add(ip)
        except Exception:
            pass
    
    def add_suspicious_ip(self, ip):
        """Add an IP (or CIDR) to the suspicious list at runtime."""
        self.malicious_ips.add(ip)
    
    def add_malware_signature(self, pattern):
        """Add a malware signature (regex string) at runtime."""
        try:
            self.malware_signatures.append(re.compile(pattern, re.IGNORECASE))
        except Exception:
            # fallback to simple substring check if regex fails
            self.malware_signatures.append(pattern)
    
    def analyze_traffic(self, traffic_log):
        """Analyze traffic log for intrusions"""
        alerts = []
        
        src_ip = traffic_log.get('src_ip')
        dst_ip = traffic_log.get('dst_ip')
        
        # 1) Suspicious / known malicious IP check
        if src_ip in self.malicious_ips or dst_ip in self.malicious_ips:
            alerts.append(self._create_alert("Suspicious IP Reputation", traffic_log,
                                            f"Matched suspicious IP list: {src_ip} -> {dst_ip}"))
        
        # 2) Suspicious ports
        if self._is_suspicious_port(traffic_log.get('port', 0)):
            alerts.append(self._create_alert("Suspicious Port", traffic_log))
        
        # 3) Brute-force detection (if auth metadata present)
        bf_alert = self._detect_brute_force(traffic_log)
        if bf_alert:
            alerts.append(bf_alert)
        
        # 4) Port scan / DDoS / brute force (existing detectors)
        port_scan_alert = self._detect_port_scan(traffic_log)
        if port_scan_alert:
            alerts.append(port_scan_alert)
        
        ddos_alert = self._detect_ddos(traffic_log)
        if ddos_alert:
            alerts.append(ddos_alert)
        
        brute_force_alert = self._detect_brute_force_from_counters(traffic_log)
        if brute_force_alert:
            alerts.append(brute_force_alert)
        
        # 5) Malware signature scanning (payloads / URLs)
        malware_alert = self._detect_malware_signature(traffic_log)
        if malware_alert:
            alerts.append(malware_alert)
        
        # 6) legacy anomaly checks
        anomaly_alert = self._detect_anomalies(traffic_log)
        if anomaly_alert:
            alerts.append(anomaly_alert)
        
        # 7) web attacks
        web_attack_alert = self._detect_web_attacks(traffic_log)
        if web_attack_alert:
            alerts.append(web_attack_alert)
        
        # accumulate alerts
        for a in alerts:
            if a and a not in self.alerts:
                self.alerts.append(a)
        return alerts
    
    # --- Brute force helpers ---
    def _detect_brute_force(self, traffic):
        """
        Immediate detection when traffic contains authentication fields.
        Expect traffic to include 'auth_result' and optionally 'username'.
        If auth_result == 'failure' -> record timestamp; on threshold raise.
        """
        try:
            auth_result = traffic.get('auth_result')
            if auth_result is None:
                return None
            src_ip = traffic.get('src_ip')
            service = traffic.get('service', 'UNKNOWN')
            username = traffic.get('username', '') or '__no_user__'
            key = (src_ip, username, service)
            now = datetime.now()
            dq = self.auth_failures[key]
            # append current failure timestamp if failure
            if str(auth_result).lower() in ("fail","failure","failed","false"):
                dq.append(now)
                # prune old timestamps outside window
                while dq and (now - dq[0]).total_seconds() > self.brute_force_window:
                    dq.popleft()
                if len(dq) >= self.brute_force_threshold:
                    # mark attacker ip suspicious
                    self.malicious_ips.add(src_ip)
                    return self._create_alert("Brute Force Attempt", traffic,
                                              f"Detected {len(dq)} failed auths for {username} from {src_ip} on {service}")
            else:
                # on success, clear historical failures for this key to avoid false positives
                if key in self.auth_failures:
                    self.auth_failures.pop(key, None)
        except Exception:
            pass
        return None
    
    def _detect_brute_force_from_counters(self, traffic):
        """
        Backwards-compatible detection if 'is_malicious' or counters exist in traffic.
        Kept lightweight — prefer _detect_brute_force above when auth metadata available.
        """
        if traffic.get('service') == 'SSH' and traffic.get('is_malicious'):
            # some simulators mark repeated SSH attempts as malicious, escalate
            return self._create_alert("SSH Brute Force Attempt", traffic,
                                     "Multiple SSH connection attempts observed (simulator flag).")
        return None
    
    # --- Malware signature detection ---
    def _detect_malware_signature(self, traffic):
        """Scan payload/url/raw_traffic against signature list and optional yara rules."""
        candidates = []
        if 'url' in traffic and traffic['url']:
            candidates.append(traffic['url'])
        if 'payload' in traffic and traffic['payload']:
            candidates.append(traffic['payload'])
        # raw_traffic may contain more text
        if 'raw_traffic' in traffic and traffic['raw_traffic']:
            candidates.append(str(traffic['raw_traffic']))
        
        text_blob = " ".join(candidates)
        if not text_blob:
            return None
        
        # 1) try yara if available and rules compiled
        if yara and self.yara_rules:
            try:
                matches = self.yara_rules.match(data=text_blob)
                if matches:
                    return self._create_alert("Malware Signature Detected", traffic,
                                              f"YARA matched: {[m.rule for m in matches]}")
            except Exception:
                pass
        
        # 2) simple regex / substring checks
        for sig in self.malware_signatures:
            try:
                if isinstance(sig, re.Pattern):
                    if sig.search(text_blob):
                        return self._create_alert("Malware Signature Detected", traffic,
                                                  f"Regex signature matched: {sig.pattern}")
                else:
                    # substring fallback
                    if str(sig).lower() in text_blob.lower():
                        return self._create_alert("Malware Signature Detected", traffic,
                                                  f"Substring signature matched: {sig}")
            except Exception:
                continue
        return None
    
    # --- existing detection methods remain unchanged (kept below) ---
    def _is_malicious_ip(self, ip):
        """Check if IP is in known malicious list"""
        return ip in self.malicious_ips
    
    def _is_suspicious_port(self, port):
        """Check if port is commonly used for malicious activities"""
        return port in self.suspicious_ports
    
    def _detect_port_scan(self, traffic):
        """Detect port scanning activity"""
        current_time = datetime.now()
        src_ip = traffic['src_ip']
        dst_ip = traffic['dst_ip']
        
        # Update connection count
        key = f"{src_ip}_{dst_ip}"
        self.connection_counts[key].append(current_time)
        
        # Remove old entries
        while (self.connection_counts[key] and 
               (current_time - self.connection_counts[key][0]).seconds > self.time_window):
            self.connection_counts[key].popleft()
        
        # Check if threshold exceeded
        if len(self.connection_counts[key]) > self.threshold_port_scan:
            self.malicious_ips.add(src_ip)
            return self._create_alert("Port Scan Detected", traffic, 
                                    f"Multiple connection attempts from {src_ip} to {dst_ip}")
        return None
    
    def _detect_ddos(self, traffic):
        """Detect DDoS attacks"""
        current_time = datetime.now()
        dst_ip = traffic['dst_ip']
        
        # Track traffic to destination
        self.ddos_traffic[dst_ip].append(current_time)
        
        # Remove old entries
        while (self.ddos_traffic[dst_ip] and 
               (current_time - self.ddos_traffic[dst_ip][0]).seconds > self.time_window):
            self.ddos_traffic[dst_ip].popleft()
        
        # Check if threshold exceeded
        if len(self.ddos_traffic[dst_ip]) > self.threshold_ddos:
            return self._create_alert("DDoS Attack Detected", traffic,
                                    f"High traffic volume to {dst_ip}")
        return None
    
    def _detect_anomalies(self, traffic):
        """Detect various anomalies in network traffic"""
        # Check for unusual packet size
        if traffic.get('packet_size', 0) < 64 or traffic.get('packet_size', 0) > 1500:
            return self._create_alert("Suspicious Packet Size", traffic,
                                    f"Unusual packet size: {traffic.get('packet_size', 'N/A')}")
        
        # Check for private IP communicating with external (simplified)
        try:
            src_private = ipaddress.ip_address(traffic['src_ip']).is_private
            dst_private = ipaddress.ip_address(traffic['dst_ip']).is_private
            
            if not src_private and dst_private:
                return self._create_alert("External to Internal Communication", traffic,
                                        f"External IP {traffic['src_ip']} accessing internal resource")
        except ValueError:
            pass
        
        return None
    
    def _detect_web_attacks(self, traffic):
        """Detect web application attacks"""
        if traffic.get('service') in ['HTTP', 'HTTPS']:
            # Check for SQL injection patterns in URL or data
            url = traffic.get('url', '') if 'url' in traffic else ''
            
            sql_patterns = [r"union.*select", r"select.*from", r"insert.*into", 
                           r"drop.*table", r"or.*1=1", r"--"]
            
            for pattern in sql_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    return self._create_alert("Potential SQL Injection", traffic,
                                            f"SQL injection pattern detected: {pattern}")
            
            # Check for XSS patterns
            xss_patterns = [r"<script>", r"javascript:", r"onload=", r"onerror="]
            for pattern in xss_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    return self._create_alert("Potential XSS Attack", traffic,
                                            f"XSS pattern detected: {pattern}")
            
            # Check for path traversal
            if re.search(r"\.\./", url):
                return self._create_alert("Path Traversal Attempt", traffic,
                                        "Directory traversal pattern detected")
        
        return None
    
    def _create_alert(self, alert_type, traffic, description=""):
        """Create an alert message"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "alert_type": alert_type,
            "severity": self._determine_severity(alert_type),
            "src_ip": traffic['src_ip'],
            "dst_ip": traffic['dst_ip'],
            "service": traffic.get('service', 'Unknown'),
            "port": traffic.get('port', 'Unknown'),
            "description": description,
            "raw_traffic": traffic
        }
        self.alerts.append(alert)
        return alert
    
    def _determine_severity(self, alert_type):
        """Determine severity level based on alert type"""
        high_severity = ["DDoS Attack Detected", "Port Scan Detected", "Known Malicious IP"]
        medium_severity = ["SSH Brute Force Attempt", "Suspicious Port", 
                          "Potential SQL Injection", "Potential XSS Attack", "Path Traversal Attempt"]
        low_severity = ["Suspicious Packet Size", "External to Internal Communication"]
        
        if alert_type in high_severity:
            return "HIGH"
        elif alert_type in medium_severity:
            return "MEDIUM"
        else:
            return "LOW"
    
    def print_alerts(self):
        """Print all generated alerts"""
        print("\n" + "="*80)
        print("INTRUSION DETECTION SYSTEM ALERTS")
        print("="*80)
        
        if not self.alerts:
            print("No alerts generated.")
            return
        
        for alert in self.alerts[-10:]:  # Show last 10 alerts
            print(f"\n[{alert['severity']}] {alert['timestamp']}")
            print(f"Type: {alert['alert_type']}")
            print(f"Source: {alert['src_ip']} -> Destination: {alert['dst_ip']}")
            print(f"Service: {alert['service']} Port: {alert['port']}")
            print(f"Description: {alert['description']}")
            print("-" * 50)
    
    def get_statistics(self):
        """Get IDS statistics"""
        stats = {
            "total_alerts": len(self.alerts),
            "high_severity": len([a for a in self.alerts if a['severity'] == 'HIGH']),
            "medium_severity": len([a for a in self.alerts if a['severity'] == 'MEDIUM']),
            "low_severity": len([a for a in self.alerts if a['severity'] == 'LOW']),
            "malicious_ips_count": len(self.malicious_ips)
        }
        return stats
    
    def save_alerts_to_file(self, filename="ids_alerts.log"):
        """Save alerts to a log file"""
        with open(filename, 'w') as f:
            for alert in self.alerts:
                f.write(f"{alert['timestamp']} | {alert['severity']} | {alert['alert_type']} | "
                       f"{alert['src_ip']} -> {alert['dst_ip']} | {alert['description']}\n")
        print(f"Alerts saved to {filename}")