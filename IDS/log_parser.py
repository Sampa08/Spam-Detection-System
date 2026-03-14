import re
from datetime import datetime

class LogParser:
    """Parse various network log formats"""
    
    @staticmethod
    def parse_apache_log(log_line):
        """Parse Apache access log format"""
        pattern = r'(\S+) (\S+) (\S+) \[([^]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
        match = re.match(pattern, log_line)
        
        if match:
            return {
                "src_ip": match.group(1),
                "timestamp": match.group(4),
                "method": match.group(5),
                "url": match.group(6),
                "protocol": match.group(7),
                "status_code": int(match.group(8)),
                "response_size": int(match.group(9)),
                "service": "HTTP"
            }
        return None
    
    @staticmethod
    def parse_iptables_log(log_line):
        """Parse iptables log format"""
        # Simplified iptables log parser
        if "SRC=" in log_line and "DST=" in log_line:
            src_ip = re.search(r'SRC=(\S+)', log_line)
            dst_ip = re.search(r'DST=(\S+)', log_line)
            protocol = re.search(r'PROTO=(\S+)', log_line)
            
            if src_ip and dst_ip:
                return {
                    "src_ip": src_ip.group(1),
                    "dst_ip": dst_ip.group(1),
                    "protocol": protocol.group(1) if protocol else "UNKNOWN",
                    "timestamp": datetime.now().isoformat()
                }
        return None
    
    @staticmethod
    def parse_custom_log(log_line):
        """Parse custom log format - extend as needed"""
        # Add your custom log format parsing here
        if "|" in log_line:  # Example: pipe-separated format
            parts = log_line.split("|")
            if len(parts) >= 4:
                return {
                    "timestamp": parts[0].strip(),
                    "src_ip": parts[1].strip(),
                    "dst_ip": parts[2].strip(),
                    "service": parts[3].strip()
                }
        return None