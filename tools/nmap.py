"""
Nmap integration for port scanning
"""

import json
import re
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner, BaseScannerError

class NmapScanner(BaseScanner):
    """Nmap port scanner"""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__('nmap', tool_path)
        self.timeout = 120  # 2 minutes for port scanning to prevent 504 timeouts
    
    def scan(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """
        Run Nmap to scan for open ports
        
        Args:
            targets: List of hosts/IPs to scan
            **kwargs: Additional options
                - ports: Port range (e.g., "80,443,22")
                - top_ports: Scan top N ports
                - scan_type: SYN scan (-sS) by default
                - timing: Timing template (T1-T5)
        
        Returns:
            Dict containing scan results
        """
        if not targets:
            raise BaseScannerError("No targets provided for port scan")
        
        # Create temporary file with targets
        targets_content = '\n'.join(targets)
        targets_file = self._create_temp_file(targets_content)
        
        try:
            # Build command - use SYN scan for speed and stealth
            cmd = [self.tool_path, '-sS', '-iL', targets_file]
            
            # Add output format - XML for structured parsing
            cmd.extend(['-oX', '-'])  # Output XML to stdout
            
            # Add port specification - focus on critical ports only
            ports = kwargs.get('ports')
            top_ports = kwargs.get('top_ports')

            if ports:
                cmd.extend(['-p', str(ports)])
            elif top_ports:
                # Use only the most critical ports for speed
                if top_ports <= 10:
                    # Top 10 most critical ports
                    critical_ports = "22,80,443,21,25,53,3389,3306,8080,8443"
                    cmd.extend(['-p', critical_ports])
                elif top_ports <= 20:
                    # Top 20 critical ports
                    critical_ports = "22,80,443,21,23,25,53,110,143,993,995,3389,3306,5432,8080,8443,135,139,111,1433"
                    cmd.extend(['-p', critical_ports])
                elif top_ports <= 50:
                    # Top 50 important ports
                    important_ports = "21-25,53,80,110-111,135,139,143,443,993,995,1433,1521,3306,3389,5432,5900,8000,8080,8443,8888,9000"
                    cmd.extend(['-p', important_ports])
                else:
                    # Use nmap's top ports feature for larger counts
                    cmd.extend(['--top-ports', str(min(top_ports, 1000))])
            else:
                # Default to top 10 critical ports for maximum speed
                cmd.extend(['-p', '22,80,443,21,25,53,3389,3306,8080,8443'])
            
            # Add timing template for speed vs accuracy balance
            timing = kwargs.get('timing', 'T4')  # Aggressive timing by default
            cmd.extend([f'-{timing}'])
            
            # Add additional speed optimizations
            cmd.extend([
                '--min-rate', '1000',  # Minimum packet rate
                '--max-retries', '1',  # Reduce retries
                '--host-timeout', '30s',  # Host timeout
                '--scan-delay', '0',  # No delay between probes
                '-n',  # No DNS resolution (we already resolved)
                '--disable-arp-ping'  # Skip ARP ping for speed
            ])
            
            # Add version detection only if requested
            if kwargs.get('version_detection', False):
                cmd.append('-sV')
            
            # Run the scan
            result = self._run_command(cmd)
            
            if not result['success']:
                raise BaseScannerError(f"Nmap scan failed: {result['stderr']}")
            
            # Parse results
            open_ports = self.parse_xml_output(result['stdout'])
            
            return {
                'tool': 'nmap',
                'targets': targets,
                'open_ports': open_ports,
                'total_ports': len(open_ports),
                'scan_config': {
                    'ports': ports or f'top-{top_ports or 10}',
                    'timing': timing,
                    'scan_type': 'SYN'
                },
                'raw_output': result['stdout']
            }
            
        finally:
            self._cleanup_temp_file(targets_file)

    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse Nmap output (required by BaseScanner)"""
        open_ports = self.parse_xml_output(output)
        return {
            'tool': 'nmap',
            'open_ports': open_ports,
            'total_ports': len(open_ports)
        }

    def parse_xml_output(self, xml_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output"""
        open_ports = []
        
        if not xml_output.strip():
            return open_ports
        
        # Simple regex parsing for XML (basic implementation)
        # Look for host entries
        host_pattern = r'<host[^>]*>.*?</host>'
        hosts = re.findall(host_pattern, xml_output, re.DOTALL)
        
        for host_xml in hosts:
            # Extract IP address
            ip_match = re.search(r'<address addr="([^"]+)"', host_xml)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            
            # Extract open ports
            port_pattern = r'<port protocol="([^"]+)" portid="([^"]+)">.*?<state state="open"'
            ports = re.findall(port_pattern, host_xml, re.DOTALL)
            
            for protocol, port in ports:
                # Extract service info if available
                service_match = re.search(
                    rf'<port protocol="{protocol}" portid="{port}">.*?<service name="([^"]*)"',
                    host_xml, re.DOTALL
                )
                service = service_match.group(1) if service_match else ''
                
                port_info = {
                    'host': ip,
                    'ip': ip,
                    'port': int(port),
                    'protocol': protocol,
                    'service': service,
                    'state': 'open'
                }
                open_ports.append(port_info)
        
        return open_ports
    
    def scan_single_host(self, host: str, **kwargs) -> Dict[str, Any]:
        """Scan a single host for open ports"""
        return self.scan([host], **kwargs)
    
    def get_critical_ports(self) -> Dict[str, List[int]]:
        """Get critical port lists optimized for speed"""
        return {
            'top_10': [22, 80, 443, 21, 25, 53, 3389, 3306, 8080, 8443],
            'top_20': [22, 80, 443, 21, 23, 25, 53, 110, 143, 993, 995, 3389, 3306, 5432, 8080, 8443, 135, 139, 111, 1433],
            'web_ports': [80, 443, 8080, 8443, 8000, 8888, 3000, 5000],
            'database_ports': [3306, 5432, 1433, 27017, 1521],
            'mail_ports': [25, 110, 143, 993, 995, 587],
            'remote_access': [22, 23, 3389, 5900],
            'network_services': [21, 25, 53, 135, 139, 445]
        }
    
    def quick_scan(self, targets: List[str]) -> Dict[str, Any]:
        """Perform a very fast scan of only the most critical ports"""
        return self.scan(targets, 
                        top_ports=10, 
                        timing='T5',  # Insane timing for maximum speed
                        version_detection=False)
    
    def scan_critical_ports(self, targets: List[str], port_category: str = 'top_10') -> Dict[str, Any]:
        """Scan critical ports by category"""
        critical_ports = self.get_critical_ports()
        
        if port_category not in critical_ports:
            raise BaseScannerError(f"Unknown port category: {port_category}")
        
        ports = ','.join(map(str, critical_ports[port_category]))
        return self.scan(targets, ports=ports, timing='T4')
