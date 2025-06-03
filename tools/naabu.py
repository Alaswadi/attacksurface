"""
Naabu integration for port scanning
"""

import json
import re
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner, BaseScannerError

class NaabuScanner(BaseScanner):
    """Naabu port scanner"""

    def __init__(self, tool_path: Optional[str] = None):
        super().__init__('naabu', tool_path)
        self.timeout = 120  # Reduced to 2 minutes to prevent 504 timeouts
    
    def scan(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """
        Run Naabu to scan for open ports
        
        Args:
            targets: List of hosts/IPs to scan
            **kwargs: Additional options
                - ports: Port range (e.g., "1-1000", "80,443,8080")
                - top_ports: Scan top N ports
                - rate: Packets per second
                - timeout: Connection timeout
                - retries: Number of retries
        
        Returns:
            Dict containing scan results
        """
        if not targets:
            raise BaseScannerError("No targets provided for port scan")
        
        # Create temporary file with targets
        targets_content = '\n'.join(targets)
        targets_file = self._create_temp_file(targets_content)
        
        try:
            # Build command
            cmd = [self.tool_path, '-list', targets_file]
            
            # Add JSON output
            cmd.extend(['-json'])
            
            # Add port specification
            ports = kwargs.get('ports')
            top_ports = kwargs.get('top_ports')

            if ports:
                cmd.extend(['-p', str(ports)])
            elif top_ports:
                # Use explicit port list for most critical ports to avoid timeouts
                if top_ports <= 20:
                    # Top 20 most critical ports (fastest scan)
                    critical_ports = "22,80,443,21,23,25,53,110,143,993,995,3389,3306,5432,8080,8443,135,139,111,993"
                    cmd.extend(['-p', critical_ports])
                elif top_ports <= 50:
                    # Top 50 most important ports (balanced speed/coverage)
                    important_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080,8443,8000,9000,3000,5000,8888,9090,1433,27017,6379,5984,587,465,636,389,88,445,1521,5060,161,162,69,123,514,515,631,873,902,1080"
                    cmd.extend(['-p', important_ports])
                elif top_ports <= 100:
                    # Top 100 ports - focus on common services only
                    common_services = "21-25,53,80,110-111,135,139,143,443,993,995,1433,1521,1723,3306,3389,5432,5900,8000,8080,8443,8888,9000,9090"
                    cmd.extend(['-p', common_services])
                else:
                    # For larger port counts, use very limited range to avoid timeouts
                    cmd.extend(['-p', '21-25,53,80,110,135,139,143,443,993,995,3306,3389,5432,8080,8443'])
            else:
                # Default to top 20 critical ports for speed
                cmd.extend(['-p', '22,80,443,21,23,25,53,110,143,993,995,3389,3306,5432,8080,8443,135,139,111,993'])
            
            # Add optional parameters - using only supported Naabu parameters
            rate = kwargs.get('rate', 1000)  # Packets per second
            cmd.extend(['-rate', str(rate)])

            # Add concurrency limit
            cmd.extend(['-c', '25'])  # Concurrent goroutines (reduced for stability)

            # Add timeout (connection timeout)
            timeout = kwargs.get('timeout', 3)
            cmd.extend(['-timeout', f'{timeout}s'])

            # Add retries
            retries = kwargs.get('retries', 1)
            cmd.extend(['-retries', str(retries)])
            
            # Add silent mode
            if kwargs.get('silent', True):
                cmd.append('-silent')
            
            # Run the scan
            result = self._run_command(cmd)
            
            if not result['success']:
                raise BaseScannerError(f"Naabu scan failed: {result['stderr']}")
            
            # Parse results
            open_ports = self.parse_output(result['stdout'])
            
            return {
                'tool': 'naabu',
                'targets': targets,
                'open_ports': open_ports,
                'total_ports': len(open_ports),
                'scan_config': {
                    'ports': ports or f'top-{top_ports or 1000}',
                    'rate': rate,
                    'timeout': timeout,
                    'retries': retries
                },
                'raw_output': result['stdout']
            }
            
        finally:
            self._cleanup_temp_file(targets_file)
    
    def scan_single_host(self, host: str, **kwargs) -> Dict[str, Any]:
        """Scan a single host for open ports"""
        return self.scan([host], **kwargs)
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Naabu JSON output"""
        open_ports = []
        
        if not output.strip():
            return open_ports
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                # Try to parse as JSON
                data = json.loads(line)
                port_info = {
                    'host': data.get('host', ''),
                    'ip': data.get('ip', ''),
                    'port': data.get('port', 0),
                    'protocol': data.get('protocol', 'tcp'),
                    'timestamp': data.get('timestamp', '')
                }
                open_ports.append(port_info)
            except json.JSONDecodeError:
                # Fallback to plain text parsing (host:port format)
                if ':' in line:
                    try:
                        host, port = line.strip().split(':')
                        port_info = {
                            'host': host,
                            'ip': '',
                            'port': int(port),
                            'protocol': 'tcp',
                            'timestamp': ''
                        }
                        open_ports.append(port_info)
                    except ValueError:
                        continue
        
        return open_ports
    
    def scan_with_service_detection(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """Run Naabu with service detection"""
        # Add service detection flag
        kwargs['service_detection'] = True
        
        # Create temporary file with targets
        targets_content = '\n'.join(targets)
        targets_file = self._create_temp_file(targets_content)
        
        try:
            cmd = [self.tool_path, '-list', targets_file, '-json', '-sV']
            
            # Add port specification
            ports = kwargs.get('ports', 'top-1000')
            if ports.startswith('top-'):
                # Convert top-X to explicit port range
                port_count = int(ports.split('-')[1])
                if port_count <= 50:
                    common_ports = "21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5432,5900,8080"
                    cmd.extend(['-p', common_ports])
                else:
                    cmd.extend(['-p', f'1-{min(port_count * 10, 65535)}'])
            else:
                cmd.extend(['-p', str(ports)])
            
            result = self._run_command(cmd)
            
            if not result['success']:
                raise BaseScannerError(f"Naabu service detection failed: {result['stderr']}")
            
            open_ports = self.parse_output(result['stdout'])
            
            return {
                'tool': 'naabu',
                'targets': targets,
                'open_ports': open_ports,
                'total_ports': len(open_ports),
                'service_detection': True,
                'raw_output': result['stdout']
            }
            
        finally:
            self._cleanup_temp_file(targets_file)
    
    def get_common_ports(self) -> Dict[str, List[int]]:
        """Get common port lists optimized for speed"""
        return {
            'critical_20': [22, 80, 443, 21, 23, 25, 53, 110, 143, 993, 995, 3389, 3306, 5432, 8080, 8443, 135, 139, 111, 993],
            'important_50': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8000, 9000, 3000, 5000, 8888, 9090, 1433, 27017, 6379, 5984, 587, 465, 636, 389, 88, 445, 1521, 5060, 161, 162, 69, 123, 514, 515, 631, 873, 902, 1080],
            'web_ports': [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000, 9090],
            'database_ports': [3306, 5432, 1433, 27017, 6379, 5984, 1521],
            'mail_ports': [25, 110, 143, 993, 995, 587, 465],
            'ftp_ports': [21, 22, 990],
            'remote_access': [22, 23, 3389, 5900, 5901],
            'network_services': [53, 88, 135, 139, 389, 445, 636]
        }
    
    def scan_common_ports(self, targets: List[str], port_category: str = 'critical_20') -> Dict[str, Any]:
        """Scan common ports by category - defaults to critical_20 for speed"""
        common_ports = self.get_common_ports()

        if port_category not in common_ports:
            raise BaseScannerError(f"Unknown port category: {port_category}")

        ports = ','.join(map(str, common_ports[port_category]))
        return self.scan(targets, ports=ports)

    def quick_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Perform a quick scan of only the most critical ports to avoid timeouts"""
        return self.scan(targets,
                        top_ports=20,
                        rate=3000,
                        timeout=1,
                        retries=1)
