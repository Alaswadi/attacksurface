"""
Masscan Scanner - High-speed port scanner
"""

import json
import logging
import re
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner, BaseScannerError

logger = logging.getLogger(__name__)

class MasscanScanner(BaseScanner):
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__('masscan', tool_path)
        self.timeout = 300  # 5 minutes for port scanning
    
    def scan(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """
        Run masscan to scan for open ports
        
        Args:
            targets: List of hosts/IPs to scan
            **kwargs: Additional options
                - ports: Port specification (e.g., "80,443,8080" or "1-1000")
                - top_ports: Number of top ports to scan
                - rate: Packets per second rate
                - timeout: Connection timeout
                - exclude_ports: Ports to exclude
                - interface: Network interface to use
                - source_ip: Source IP address
        
        Returns:
            Dict containing scan results
        """
        if not targets:
            raise BaseScannerError("No targets provided for port scanning")
        
        # Create temporary file with targets
        targets_content = '\n'.join(targets)
        targets_file = self._create_temp_file(targets_content)
        
        try:
            # Build command
            cmd = [self.tool_path]
            
            # Add targets file
            cmd.extend(['-iL', targets_file])
            
            # Add output format
            cmd.extend(['-oJ', '-'])  # JSON output to stdout
            
            # Add port specification
            ports = kwargs.get('ports')
            top_ports = kwargs.get('top_ports')
            
            if ports:
                cmd.extend(['-p', str(ports)])
            elif top_ports:
                # Use predefined port lists based on top_ports count
                if top_ports <= 50:
                    # Top 50 most common ports
                    common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080,8443,9000,9090,3000,5000,8000,8888,9999"
                    cmd.extend(['-p', common_ports])
                elif top_ports <= 100:
                    # Top 100 ports
                    cmd.extend(['-p', '1-1000'])
                elif top_ports <= 1000:
                    # Top 1000 ports
                    cmd.extend(['-p', '1-1000'])
                else:
                    # Large port range
                    cmd.extend(['-p', f'1-{min(top_ports, 65535)}'])
            else:
                # Default to common ports
                cmd.extend(['-p', '21,22,23,25,53,80,110,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080'])
            
            # Add rate limiting
            rate = kwargs.get('rate', 1000)
            cmd.extend(['--rate', str(rate)])
            
            # Add timeout
            timeout = kwargs.get('timeout', 3)
            cmd.extend(['--wait', str(timeout)])
            
            # Add retries
            retries = kwargs.get('retries', 3)
            cmd.extend(['--retries', str(retries)])
            
            # Add interface if specified
            interface = kwargs.get('interface')
            if interface:
                cmd.extend(['-e', interface])
            
            # Add source IP if specified
            source_ip = kwargs.get('source_ip')
            if source_ip:
                cmd.extend(['--source-ip', source_ip])
            
            # Exclude ports if specified
            exclude_ports = kwargs.get('exclude_ports')
            if exclude_ports:
                cmd.extend(['--exclude-ports', str(exclude_ports)])
            
            # Add other useful options
            cmd.extend(['--open-only'])  # Only show open ports
            cmd.extend(['--banners'])    # Grab banners when possible
            
            # Run the scan
            result = self._run_command(cmd)
            
            if not result['success']:
                raise BaseScannerError(f"Masscan scan failed: {result['stderr']}")
            
            # Parse results
            open_ports = self.parse_output(result['stdout'])
            
            return {
                'tool': 'masscan',
                'targets': targets,
                'open_ports': open_ports,
                'scan_config': {
                    'ports': ports or top_ports or 'common',
                    'rate': rate,
                    'timeout': timeout,
                    'retries': retries
                },
                'raw_output': result['stdout']
            }
            
        finally:
            self._cleanup_temp_file(targets_file)
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse masscan JSON output"""
        open_ports = []
        
        if not output.strip():
            return open_ports
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                data = json.loads(line)
                
                # Extract port information
                if 'ports' in data and data['ports']:
                    ip = data.get('ip', '')
                    timestamp = data.get('timestamp', '')
                    
                    for port_info in data['ports']:
                        port_data = {
                            'host': ip,
                            'ip': ip,
                            'port': port_info.get('port', 0),
                            'protocol': port_info.get('proto', 'tcp'),
                            'status': port_info.get('status', 'open'),
                            'service': port_info.get('service', {}).get('name', ''),
                            'banner': port_info.get('service', {}).get('banner', ''),
                            'timestamp': timestamp,
                            'reason': port_info.get('reason', ''),
                            'ttl': port_info.get('ttl', 0)
                        }
                        
                        open_ports.append(port_data)
                
            except json.JSONDecodeError:
                # Skip malformed JSON lines
                continue
        
        return open_ports
    
    def scan_single_host(self, host: str, **kwargs) -> Dict[str, Any]:
        """Scan a single host"""
        return self.scan([host], **kwargs)
    
    def scan_ports_only(self, targets: List[str], ports: str) -> Dict[str, Any]:
        """Scan specific ports only"""
        return self.scan(targets, ports=ports)
    
    def quick_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Quick scan with common ports and fast settings"""
        return self.scan(targets, 
                        top_ports=50, 
                        rate=2000, 
                        timeout=2,
                        retries=1)
    
    def comprehensive_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Comprehensive scan with many ports"""
        return self.scan(targets, 
                        ports='1-65535', 
                        rate=1000, 
                        timeout=5,
                        retries=3)
    
    def get_open_ports_summary(self, targets: List[str]) -> Dict[str, List[int]]:
        """Get summary of open ports per host"""
        result = self.scan(targets)
        summary = {}
        
        for port_info in result['open_ports']:
            host = port_info['host']
            port = port_info['port']
            
            if host not in summary:
                summary[host] = []
            
            if port not in summary[host]:
                summary[host].append(port)
        
        # Sort ports for each host
        for host in summary:
            summary[host].sort()
        
        return summary
