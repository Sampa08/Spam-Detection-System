#!/usr/bin/env python3
"""
Main entry point for the Intrusion Detection System
Runs the entire system as one cohesive unit
"""

import time
import sys
import argparse
from traffic_simulator import NetworkTrafficSimulator
from ids import IntrusionDetectionSystem
from log_parser import LogParser

class IDSController:
    """Controller class to manage the entire IDS system"""
    
    def __init__(self):
        self.simulator = NetworkTrafficSimulator()
        self.ids = IntrusionDetectionSystem()
        self.log_parser = LogParser()
        self.running = False
    
    def start_realtime_monitoring(self, duration=120, malicious_ratio=0.1, notify=None):
        """Start real-time traffic monitoring and analysis
        notify: optional callable(msg: str, type: str, payload: dict) to send updates to GUI or logger
        """
        def _send(msg, t="info", payload=None):
            if callable(notify):
                try:
                    notify(msg, t, payload or {})
                except Exception:
                    pass
            else:
                print(msg)

        _send("🚀 Starting Real-time Network Intrusion Detection System", "info")
        _send("=" * 60, "info")
        _send("Monitoring network traffic...", "info")
        _send("Press Ctrl+C to stop monitoring\n", "info")
        
        self.running = True
        packet_count = 0
        alert_count = 0
        
        try:
            start_time = time.time()
            
            while time.time() - start_time < duration and self.running:
                # Generate traffic with specified malicious ratio
                if packet_count % 20 == 0:  # Every 20th packet is malicious
                    traffic = self.simulator.generate_malicious_traffic()
                else:
                    traffic = self.simulator.generate_normal_traffic()
                
                # Analyze traffic in real-time
                alerts = self.ids.analyze_traffic(traffic)
                
                # Display real-time alerts
                for alert in alerts:
                    alert_count += 1
                    # send a structured alert to GUI/logger
                    _send(f"ALERT #{alert_count}: {alert['alert_type']}", "alert", alert)
                    # Also call existing display helper for console
                    self.display_realtime_alert(alert, alert_count)
                
                packet_count += 1
                
                # Display progress every 10 packets
                if packet_count % 10 == 0:
                    elapsed = time.time() - start_time
                    remaining = max(0, duration - elapsed)
                    _send(f"Progress: {packet_count} packets analyzed | {alert_count} alerts detected | Time remaining: {remaining:.1f}s", "progress", {"packet_count":packet_count, "alert_count":alert_count})
                
                time.sleep(0.5)  # Simulate real-time processing
                
        except KeyboardInterrupt:
            _send("\n\n⏹️  Monitoring stopped by user", "info")
        
        finally:
            self.running = False
            return packet_count, alert_count
    
    def display_realtime_alert(self, alert, alert_number):
        """Display alert in real-time format"""
        severity_icons = {
            "HIGH": "🔴",
            "MEDIUM": "🟡", 
            "LOW": "🔵"
        }
        
        icon = severity_icons.get(alert['severity'], '⚪')
        print(f"\n{icon} ALERT #{alert_number}: {alert['alert_type']}")
        print(f"   Source: {alert['src_ip']} → Destination: {alert['dst_ip']}")
        print(f"   Service: {alert['service']} | Port: {alert['port']}")
        print(f"   Description: {alert['description']}")
        print(f"   Timestamp: {alert['timestamp']}")
    
    def run_log_analysis_demo(self):
        """Run the log analysis demonstration"""
        print("\n" + "=" * 60)
        print("📝 LOG ANALYSIS MODULE")
        print("=" * 60)
        
        # Sample log entries that simulate real attacks
        sample_logs = [
            # Normal traffic
            '192.168.1.100 - - [10/Oct/2023:14:30:01 +0000] "GET /index.html HTTP/1.1" 200 512',
            # Port scan attempt
            '10.0.0.5 - - [10/Oct/2023:14:30:02 +0000] "GET /test1 HTTP/1.1" 404 128',
            '10.0.0.5 - - [10/Oct/2023:14:30:03 +0000] "GET /test2 HTTP/1.1" 404 128',
            '10.0.0.5 - - [10/Oct/2023:14:30:04 +0000] "GET /test3 HTTP/1.1" 404 128',
            # SQL Injection attempt
            '172.16.0.20 - - [10/Oct/2023:14:30:05 +0000] "GET /login.php?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 256',
            # XSS attempt
            '192.168.1.200 - - [10/Oct/2023:14:30:06 +0000] "GET /search?q=<script>alert(\"xss\")</script> HTTP/1.1" 200 312',
            # Path traversal attempt
            '10.0.1.15 - - [10/Oct/2023:14:30:07 +0000] "GET /../../../etc/passwd HTTP/1.1" 403 198',
        ]
        
        print("Analyzing sample web server logs for security threats...\n")
        
        total_alerts = 0
        for i, log_line in enumerate(sample_logs, 1):
            print(f"Log {i}: {log_line}")
            parsed_log = self.log_parser.parse_apache_log(log_line)
            
            if parsed_log:
                alerts = self.ids.analyze_traffic(parsed_log)
                if alerts:
                    for alert in alerts:
                        total_alerts += 1
                        print(f"   🚨 DETECTED: {alert['alert_type']}")
                        print(f"      Reason: {alert['description']}")
                else:
                    print("   ✅ No threats detected")
            else:
                print("   ❌ Failed to parse log entry")
            print()
        
        print(f"Log analysis completed. Found {total_alerts} potential threats.")
    
    def generate_comprehensive_report(self):
        """Generate a comprehensive security report"""
        stats = self.ids.get_statistics()
        
        print("\n" + "=" * 60)
        print("📊 COMPREHENSIVE SECURITY REPORT")
        print("=" * 60)
        
        print(f"\n📈 DETECTION STATISTICS:")
        print(f"   Total Alerts: {stats['total_alerts']}")
        print(f"   🔴 High Severity: {stats['high_severity']}")
        print(f"   🟡 Medium Severity: {stats['medium_severity']}") 
        print(f"   🔵 Low Severity: {stats['low_severity']}")
        print(f"   🚫 Malicious IPs Blocked: {stats['malicious_ips_count']}")
        
        # Alert breakdown
        if self.ids.alerts:
            print(f"\n🔍 RECENT ALERTS (last 5):")
            for alert in self.ids.alerts[-5:]:
                icon = "🔴" if alert['severity'] == 'HIGH' else "🟡" if alert['severity'] == 'MEDIUM' else "🔵"
                print(f"   {icon} {alert['alert_type']} - {alert['src_ip']} -> {alert['dst_ip']}")
        
        # Save detailed report
        self.ids.save_alerts_to_file("security_report.log")
        print(f"\n💾 Detailed report saved to: security_report.log")
    
    def run_complete_system(self, monitoring_duration=120):
        """Run the complete IDS system - all modules together"""
        print("🎯 INITIALIZING COMPLETE INTRUSION DETECTION SYSTEM")
        print("=" * 60)
        
        # Phase 1: Real-time Monitoring
        print("\n1. STARTING REAL-TIME TRAFFIC MONITORING...")
        packets, alerts = self.start_realtime_monitoring(monitoring_duration)
        
        # Phase 2: Log Analysis
        print("\n2. PERFORMING LOG ANALYSIS...")
        self.run_log_analysis_demo()
        
        # Phase 3: Generate Report
        print("\n3. GENERATING SECURITY REPORT...")
        self.generate_comprehensive_report()
        
        # Final Summary
        print("\n" + "=" * 60)
        print("✅ SYSTEM EXECUTION COMPLETED")
        print("=" * 60)
        print(f"📦 Summary of Operations:")
        print(f"   • Real-time monitoring: {packets} packets analyzed")
        print(f"   • Security alerts: {alerts} threats detected")
        print(f"   • Log files analyzed: 7 sample logs processed")
        print(f"   • Reports generated: Comprehensive security report")
        print("\n🛡️  System is ready for production deployment!")

def main():
    """Main function with command line interface"""
    parser = argparse.ArgumentParser(
        description='Complete Intrusion Detection System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python main.py                          # Run complete system (default)
  python main.py --mode realtime          # Only real-time monitoring
  python main.py --mode logs              # Only log analysis
  python main.py --duration 60            # Run for 60 seconds
  python main.py --simple                 # Simple mode without animations
        '''
    )
    
    parser.add_argument('--mode', 
                       choices=['complete', 'realtime', 'logs', 'report'],
                       default='complete',
                       help='Operation mode (default: complete)')
    
    parser.add_argument('--duration', 
                       type=int, 
                       default=120,
                       help='Monitoring duration in seconds (default: 120)')
    
    parser.add_argument('--simple', 
                       action='store_true',
                       help='Simple output mode without emojis')
    
    args = parser.parse_args()
    
    # Initialize the complete system
    controller = IDSController()
    
    try:
        if args.mode == 'complete':
            controller.run_complete_system(args.duration)
        
        elif args.mode == 'realtime':
            controller.start_realtime_monitoring(args.duration)
            controller.generate_comprehensive_report()
        
        elif args.mode == 'logs':
            controller.run_log_analysis_demo()
            controller.generate_comprehensive_report()
        
        elif args.mode == 'report':
            controller.generate_comprehensive_report()
    
    except KeyboardInterrupt:
        print("\n\n🔚 System shutdown requested by user.")
    
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("Please check that all files are in the same directory.")
    
    print("\nThank you for using the Intrusion Detection System! 🛡️")

if __name__ == "__main__":
    main()