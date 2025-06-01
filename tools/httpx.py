"""
HTTPX Scanner - Check if hosts are alive and get HTTP information
"""

import json
import logging
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner, BaseScannerError

logger = logging.getLogger(__name__)

class HttpxScanner(BaseScanner):
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__('httpx', tool_path)
        self.timeout = 180  # 3 minutes for HTTP probing
    
    def scan(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """
        Run httpx to probe HTTP services and check if hosts are alive
        
        Args:
            targets: List of hosts/domains to probe
            **kwargs: Additional options
                - ports: Specific ports to probe
                - follow_redirects: Follow HTTP redirects
                - timeout: Request timeout
                - threads: Number of threads
                - status_code: Include status codes
                - tech_detect: Enable technology detection
                - title: Extract page titles
        
        Returns:
            Dict containing probe results
        """
        if not targets:
            raise BaseScannerError("No targets provided for HTTP probing")
        
        # Create temporary file with targets
        targets_content = '\n'.join(targets)
        targets_file = self._create_temp_file(targets_content)
        
        try:
            # Build command
            cmd = [self.tool_path, '-list', targets_file]
            
            # Add JSON output
            cmd.extend(['-json'])
            
            # Add basic probing options
            cmd.extend(['-status-code'])  # Include status codes
            cmd.extend(['-title'])        # Extract page titles
            cmd.extend(['-tech-detect'])  # Technology detection
            cmd.extend(['-follow-redirects'])  # Follow redirects
            
            # Add ports if specified
            ports = kwargs.get('ports')
            if ports:
                if isinstance(ports, list):
                    cmd.extend(['-ports', ','.join(map(str, ports))])
                else:
                    cmd.extend(['-ports', str(ports)])
            else:
                # Default to common HTTP ports
                cmd.extend(['-ports', '80,443,8080,8443,8000,3000'])
            
            # Add performance options
            timeout = kwargs.get('timeout', 10)
            cmd.extend(['-timeout', str(timeout)])
            
            threads = kwargs.get('threads', 50)
            cmd.extend(['-threads', str(threads)])
            
            # Add silent mode
            if kwargs.get('silent', True):
                cmd.append('-silent')
            
            # Disable update check
            cmd.append('-disable-update-check')
            
            # Run the scan
            result = self._run_command(cmd)
            
            if not result['success']:
                raise BaseScannerError(f"Httpx scan failed: {result['stderr']}")
            
            # Parse results
            alive_hosts = self.parse_output(result['stdout'])
            
            return {
                'tool': 'httpx',
                'targets': targets,
                'alive_hosts': alive_hosts,
                'total_alive': len(alive_hosts),
                'scan_config': {
                    'ports': ports or '80,443,8080,8443,8000,3000',
                    'timeout': timeout,
                    'threads': threads,
                    'follow_redirects': kwargs.get('follow_redirects', True),
                    'tech_detect': kwargs.get('tech_detect', True)
                },
                'raw_output': result['stdout']
            }
            
        finally:
            self._cleanup_temp_file(targets_file)
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse httpx JSON output"""
        alive_hosts = []
        
        if not output.strip():
            return alive_hosts
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                data = json.loads(line)
                
                # Extract host information
                host_info = {
                    'url': data.get('url', ''),
                    'host': data.get('host', ''),
                    'port': data.get('port', 80),
                    'scheme': data.get('scheme', 'http'),
                    'status_code': data.get('status_code', 0),
                    'content_length': data.get('content_length', 0),
                    'title': data.get('title', ''),
                    'webserver': data.get('webserver', ''),
                    'tech': data.get('tech', []),
                    'method': data.get('method', 'GET'),
                    'location': data.get('location', ''),
                    'content_type': data.get('content_type', ''),
                    'response_time': data.get('response_time', ''),
                    'failed': data.get('failed', False),
                    'cdn_name': data.get('cdn_name', ''),
                    'cdn_type': data.get('cdn_type', '')
                }
                
                # Only include hosts that responded successfully
                if not host_info['failed'] and host_info['status_code'] > 0:
                    alive_hosts.append(host_info)
                
            except json.JSONDecodeError:
                # Skip malformed JSON lines
                continue
        
        return alive_hosts
    
    def probe_single_host(self, host: str, **kwargs) -> Dict[str, Any]:
        """Probe a single host"""
        return self.scan([host], **kwargs)
    
    def probe_with_custom_ports(self, targets: List[str], ports: List[int]) -> Dict[str, Any]:
        """Probe targets with custom ports"""
        return self.scan(targets, ports=ports)
    
    def quick_probe(self, targets: List[str]) -> Dict[str, Any]:
        """Quick probe with minimal options for speed"""
        return self.scan(targets, 
                        ports=[80, 443], 
                        timeout=5, 
                        threads=100,
                        tech_detect=False,
                        follow_redirects=False)
    
    def get_alive_urls(self, targets: List[str]) -> List[str]:
        """Get list of alive URLs from targets"""
        result = self.scan(targets)
        return [host['url'] for host in result['alive_hosts']]
    
    def get_alive_hosts(self, targets: List[str]) -> List[str]:
        """Get list of alive hostnames from targets"""
        result = self.scan(targets)
        return [host['host'] for host in result['alive_hosts']]
