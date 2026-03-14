import random
import time
import json
import pyshark
import threading
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import ipaddress
import logging
import os

class NetworkTrafficSimulator:
    """Enhanced Network Traffic Simulator with Real-time and PCAP Analysis"""
    
    def __init__(self):
        self.ips = [f"192.168.1.{i}" for i in range(1, 101)]
        self.services = ["HTTP", "HTTPS", "SSH", "FTP", "DNS", "SMTP"]
        self.ports = [80, 443, 22, 21, 53, 25]
        
        # Detection engines
        self.brute_force_tracker = defaultdict(list)
        self.suspicious_ips = set(["10.0.0.5", "203.0.113.15", "198.51.100.20"])
        self.malware_signatures = [
            {"pattern": "malware.com", "type": "C&C Domain", "severity": "HIGH"},
            {"pattern": "exploit", "type": "Exploit Kit", "severity": "HIGH"},
            {"pattern": ".exe?", "type": "Executable Download", "severity": "MEDIUM"},
            {"pattern": "powershell -encoded", "type": "Obfuscated PowerShell", "severity": "HIGH"},
            {"pattern": "union select", "type": "SQL Injection", "severity": "HIGH"},
            {"pattern": "<script>", "type": "XSS Attempt", "severity": "MEDIUM"},
            {"pattern": "../../", "type": "Path Traversal", "severity": "HIGH"}
        ]
        
        # Alert storage
        self.alerts = []
        self.setup_logging()
        
        # Real-time monitoring control
        self.is_monitoring = False
        self.monitoring_thread = None
        
    def setup_logging(self):
        """Setup logging for alerts"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('ids_alerts.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('NetworkIDS')
    
    def generate_normal_traffic(self):
        """Generate normal network traffic"""
        src_ip = random.choice(self.ips)
        dst_ip = random.choice(self.ips)
        service = random.choice(self.services)
        port = self.ports[self.services.index(service)]
        
        traffic = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service": service,
            "port": port,
            "packet_size": random.randint(64, 1500),
            "flags": "ACK" if service in ["HTTP", "HTTPS"] else "SYN",
            "protocol": "TCP",
            "type": "normal"
        }
        
        # Analyze the generated traffic
        self.analyze_traffic(traffic)
        return traffic
    
    def generate_malicious_traffic(self):
        """Generate malicious traffic patterns"""
        attack_type = random.choice(["port_scan", "ddos", "brute_force", "malware"])
        
        if attack_type == "port_scan":
            traffic = self._generate_port_scan()
        elif attack_type == "ddos":
            traffic = self._generate_ddos()
        elif attack_type == "brute_force":
            traffic = self._generate_brute_force()
        else:
            traffic = self._generate_malware_traffic()
        
        # Analyze the malicious traffic
        self.analyze_traffic(traffic)
        return traffic
    
    def _generate_port_scan(self):
        src_ip = "10.0.0." + str(random.randint(1, 10))  # Attacker IP
        dst_ip = random.choice(self.ips)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service": "SCAN",
            "port": random.randint(1, 65535),
            "packet_size": 64,
            "flags": "SYN",
            "protocol": "TCP",
            "type": "port_scan",
            "is_malicious": True
        }
    
    def _generate_ddos(self):
        src_ip = "172.16.0." + str(random.randint(1, 50))  # Botnet IP
        dst_ip = "192.168.1.10"  # Target server
        
        return {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service": "HTTP",
            "port": 80,
            "packet_size": random.randint(500, 1500),
            "flags": "ACK",
            "protocol": "TCP",
            "type": "ddos",
            "is_malicious": True
        }
    
    def _generate_brute_force(self):
        src_ip = "10.0.1." + str(random.randint(1, 5))
        dst_ip = random.choice(self.ips)
        
        return {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service": "SSH",
            "port": 22,
            "packet_size": 128,
            "flags": "SYN",
            "protocol": "TCP",
            "type": "brute_force",
            "is_malicious": True
        }
    
    def _generate_malware_traffic(self):
        src_ip = random.choice(self.ips)
        dst_ip = "malware.com"  # Malicious domain
        
        return {
            "timestamp": datetime.now().isoformat(),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "service": "HTTP",
            "port": 80,
            "packet_size": random.randint(200, 2000),
            "flags": "ACK",
            "protocol": "TCP",
            "type": "malware",
            "is_malicious": True,
            "payload": random.choice([
                "download malware.exe",
                "exploit kit payload",
                "powershell -encoded command"
            ])
        }

    # ===== DETECTION ENGINE METHODS =====
    
    def analyze_traffic(self, traffic):
        """Analyze traffic for suspicious patterns"""
        alerts = []
        
        # Check for brute force attempts
        alerts.extend(self.detect_brute_force(traffic))
        
        # Check for suspicious IPs
        alerts.extend(self.detect_suspicious_ips(traffic))
        
        # Check for malware signatures
        alerts.extend(self.detect_malware_signatures(traffic))
        
        # Log alerts
        for alert in alerts:
            self.log_alert(alert)
    
    def detect_brute_force(self, traffic):
        """Detect brute force attempts"""
        alerts = []
        
        # Focus on SSH, FTP, and other authentication services
        if traffic.get('service') in ['SSH', 'FTP'] and traffic.get('flags') == 'SYN':
            src_ip = traffic['src_ip']
            current_time = datetime.now()
            
            # Track connection attempts
            self.brute_force_tracker[src_ip].append(current_time)
            
            # Clean old entries (last 2 minutes)
            self.brute_force_tracker[src_ip] = [
                t for t in self.brute_force_tracker[src_ip]
                if (current_time - t).seconds < 120
            ]
            
            # Alert if more than 5 attempts in 2 minutes
            if len(self.brute_force_tracker[src_ip]) >= 5:
                alert = {
                    'type': 'brute_force',
                    'severity': 'HIGH',
                    'src_ip': src_ip,
                    'dst_ip': traffic['dst_ip'],
                    'service': traffic['service'],
                    'evidence': f"{len(self.brute_force_tracker[src_ip])} authentication attempts in 2 minutes",
                    'timestamp': current_time.isoformat()
                }
                alerts.append(alert)
                
                # Reset counter after alert
                self.brute_force_tracker[src_ip] = []
        
        return alerts
    
    def detect_suspicious_ips(self, traffic):
        """Detect traffic from known suspicious IPs"""
        alerts = []
        
        src_ip = traffic.get('src_ip', '')
        
        # Check if IP is in suspicious list
        if src_ip in self.suspicious_ips:
            alert = {
                'type': 'suspicious_ip',
                'severity': 'MEDIUM',
                'src_ip': src_ip,
                'dst_ip': traffic.get('dst_ip', ''),
                'evidence': f"Traffic from known suspicious IP: {src_ip}",
                'timestamp': datetime.now().isoformat()
            }
            alerts.append(alert)
        
        # Detect internal IPs communicating with external suspicious IPs
        if (traffic['src_ip'].startswith('192.168.') and 
            any(traffic['dst_ip'].startswith(prefix) for prefix in ['10.0.', '172.16.', '203.0.113.'])):
            alert = {
                'type': 'suspicious_communication',
                'severity': 'LOW',
                'src_ip': src_ip,
                'dst_ip': traffic['dst_ip'],
                'evidence': f"Internal IP communicating with external suspicious IP",
                'timestamp': datetime.now().isoformat()
            }
            alerts.append(alert)
        
        return alerts
    
    def detect_malware_signatures(self, traffic):
        """Detect malware signatures in traffic"""
        alerts = []
        
        # Check destination domains
        dst_ip = traffic.get('dst_ip', '')
        payload = traffic.get('payload', '')
        
        for signature in self.malware_signatures:
            pattern = signature['pattern']
            
            # Check if pattern appears in destination or payload
            if pattern.lower() in dst_ip.lower() or pattern.lower() in str(payload).lower():
                alert = {
                    'type': 'malware_signature',
                    'severity': signature['severity'],
                    'src_ip': traffic.get('src_ip', ''),
                    'dst_ip': dst_ip,
                    'evidence': f"Malware signature detected: {signature['type']} - {pattern}",
                    'timestamp': datetime.now().isoformat(),
                    'signature_type': signature['type']
                }
                alerts.append(alert)
                break  # Only alert once per packet
        
        return alerts
    
    def log_alert(self, alert):
        """Log security alert"""
        self.alerts.append(alert)
        alert_msg = f"[{alert['severity']}] {alert['type']} - {alert['evidence']}"
        self.logger.warning(alert_msg)
        print(f"🚨 {alert_msg}")

    # ===== REAL-TIME MONITORING =====
    
    def start_real_time_monitoring(self, interface=None, duration=300):
        """Start real-time network traffic monitoring"""
        print(f"Starting real-time monitoring for {duration} seconds...")
        self.is_monitoring = True
        
        def monitor():
            start_time = time.time()
            packet_count = 0
            
            try:
                # Use pyshark for live capture
                if interface:
                    capture = pyshark.LiveCapture(interface=interface)
                else:
                    capture = pyshark.LiveCapture()
                
                for packet in capture.sniff_continuously():
                    if not self.is_monitoring or (time.time() - start_time) > duration:
                        break
                    
                    packet_count += 1
                    traffic = self.packet_to_traffic(packet)
                    if traffic:
                        self.analyze_traffic(traffic)
                    
                    # Generate some simulated traffic alongside real traffic
                    if random.random() < 0.3:  # 30% chance to generate simulated traffic
                        if random.random() < 0.2:  # 20% of simulated traffic is malicious
                            self.generate_malicious_traffic()
                        else:
                            self.generate_normal_traffic()
                
            except Exception as e:
                self.logger.error(f"Real-time monitoring error: {e}")
            
            print(f"Real-time monitoring stopped. Processed {packet_count} packets.")
        
        self.monitoring_thread = threading.Thread(target=monitor)
        self.monitoring_thread.start()
    
    def stop_real_time_monitoring(self):
        """Stop real-time monitoring"""
        self.is_monitoring = False
        if self.monitoring_thread:
            self.monitoring_thread.join()
        print("Real-time monitoring stopped.")
    
    def packet_to_traffic(self, packet):
        """Convert pyshark packet to traffic dictionary"""
        try:
            traffic = {
                "timestamp": getattr(packet, 'sniff_time', datetime.now()).isoformat(),
                "protocol": "Unknown",
                "src_ip": "Unknown",
                "dst_ip": "Unknown",
                "src_port": "Unknown",
                "dst_port": "Unknown",
                "packet_size": int(getattr(packet, 'length', 0)),
                "type": "real_time"
            }
            
            # Extract IP information
            if hasattr(packet, 'ip'):
                traffic.update({
                    "src_ip": packet.ip.src,
                    "dst_ip": packet.ip.dst,
                    "protocol": "IP"
                })
            
            # Extract TCP information
            if hasattr(packet, 'tcp'):
                traffic.update({
                    "src_port": packet.tcp.srcport,
                    "dst_port": packet.tcp.dstport,
                    "protocol": "TCP",
                    "flags": getattr(packet.tcp, 'flags', ''),
                    "service": self.port_to_service(int(packet.tcp.dstport))
                })
            
            # Extract UDP information
            if hasattr(packet, 'udp'):
                traffic.update({
                    "src_port": packet.udp.srcport,
                    "dst_port": packet.udp.dstport,
                    "protocol": "UDP",
                    "service": self.port_to_service(int(packet.udp.dstport))
                })
            
            return traffic
            
        except Exception as e:
            self.logger.warning(f"Error converting packet: {e}")
            return None
    
    def port_to_service(self, port):
        """Convert port number to service name"""
        port_service_map = {
            80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
            53: "DNS", 25: "SMTP", 110: "POP3", 143: "IMAP"
        }
        return port_service_map.get(port, "Unknown")

    # ===== PCAP FILE ANALYSIS =====
    
    def analyze_pcap_file(self, pcap_file):
        """Analyze a PCAP file for security threats"""
        print(f"Analyzing PCAP file: {pcap_file}")
        
        if not os.path.exists(pcap_file):
            print(f"Error: PCAP file {pcap_file} not found")
            return
        
        try:
            # Use pyshark to read the PCAP file
            capture = pyshark.FileCapture(pcap_file)
            
            packet_count = 0
            for packet in capture:
                packet_count += 1
                traffic = self.packet_to_traffic(packet)
                if traffic:
                    self.analyze_traffic(traffic)
                
                # Progress indicator
                if packet_count % 100 == 0:
                    print(f"Processed {packet_count} packets...")
            
            capture.close()
            print(f"PCAP analysis complete. Processed {packet_count} packets.")
            
        except Exception as e:
            self.logger.error(f"PCAP analysis error: {e}")
            print(f"Error analyzing PCAP file: {e}")
    
    def generate_pcap_report(self):
        """Generate a security report from detected alerts"""
        if not self.alerts:
            print("No security alerts detected!")
            return
        
        print("\n" + "="*60)
        print("SECURITY ANALYSIS REPORT")
        print("="*60)
        
        # Group alerts by type
        alert_types = Counter([alert['type'] for alert in self.alerts])
        severity_counts = Counter([alert['severity'] for alert in self.alerts])
        
        print(f"Total Alerts: {len(self.alerts)}")
        print(f"High Severity: {severity_counts['HIGH']}")
        print(f"Medium Severity: {severity_counts['MEDIUM']}")
        print(f"Low Severity: {severity_counts['LOW']}")
        
        print("\nAlert Breakdown:")
        for alert_type, count in alert_types.items():
            print(f"  {alert_type}: {count}")
        
        print("\nRecent Alerts:")
        for alert in self.alerts[-10:]:  # Show last 10 alerts
            print(f"  [{alert['severity']}] {alert['type']} - {alert['src_ip']} -> {alert['dst_ip']}")
        
        print("="*60)

    # ===== SIMULATION MODE =====
    
    def run_simulation(self, duration=60, malicious_ratio=0.2):
        """Run a simulation with mixed normal and malicious traffic"""
        print(f"Starting simulation for {duration} seconds...")
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            packet_count += 1
            
            # Determine if this packet is malicious
            if random.random() < malicious_ratio:
                traffic = self.generate_malicious_traffic()
            else:
                traffic = self.generate_normal_traffic()
            
            # Print progress
            if packet_count % 10 == 0:
                elapsed = time.time() - start_time
                print(f"Generated {packet_count} packets ({elapsed:.1f}s elapsed)")
            
            time.sleep(0.1)  # Slow down the simulation
        
        print(f"Simulation complete. Generated {packet_count} packets.")
        self.generate_pcap_report()

# ===== USAGE EXAMPLES =====

def main():
    simulator = NetworkTrafficSimulator()
    
    while True:
        print("\n🌐 Network Traffic IDS Simulator")
        print("="*50)
        print("1. Run Simulation (Generate & Analyze Traffic)")
        print("2. Real-time Network Monitoring")
        print("3. Analyze PCAP File")
        print("4. View Security Report")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            duration = int(input("Simulation duration (seconds, default 60): ") or 60)
            malicious_ratio = float(input("Malicious traffic ratio (0.0-1.0, default 0.2): ") or 0.2)
            simulator.run_simulation(duration, malicious_ratio)
            
        elif choice == '2':
            interface = input("Network interface (default: auto-detect): ").strip() or None
            duration = int(input("Monitoring duration (seconds, default 300): ") or 300)
            simulator.start_real_time_monitoring(interface, duration)
            
            # Wait for monithertoring to complete
            time.sleep(duration + 2)
            simulator.stop_real_time_monitoring()
            
        elif choice == '3':
            pcap_file = input("Enter PCAP file path: ").strip()
            simulator.analyze_pcap_file(pcap_file)
            
        elif choice == '4':
            simulator.generate_pcap_report()
            
        elif choice == '5':
            print("Goodbye!")
            break
            
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    # Install required packages first:
    # pip install pyshark
    
    main()