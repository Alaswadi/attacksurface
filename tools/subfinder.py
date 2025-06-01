"""
Subfinder integration for subdomain discovery
"""

import json
import re
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner, BaseScannerError

class SubfinderScanner(BaseScanner):
    """Subfinder subdomain discovery scanner"""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__('subfinder', tool_path)
        self.timeout = 180  # 3 minutes for subdomain discovery
    
    def scan(self, domain: str, **kwargs) -> Dict[str, Any]:
        """
        Run Subfinder to discover subdomains
        
        Args:
            domain: Target domain to scan
            **kwargs: Additional options
                - sources: List of sources to use
                - silent: Run in silent mode
                - recursive: Enable recursive subdomain discovery
                - max_time: Maximum time for scan
        
        Returns:
            Dict containing scan results
        """
        if not self._is_valid_domain(domain):
            raise BaseScannerError(f"Invalid domain format: {domain}")
        
        # Build command
        cmd = [self.tool_path, '-d', domain]
        
        # Add JSON output
        cmd.extend(['-json'])
        
        # Add optional parameters
        if kwargs.get('silent', True):
            cmd.append('-silent')
        
        if kwargs.get('recursive', False):
            cmd.append('-recursive')
        
        sources = kwargs.get('sources')
        if sources:
            cmd.extend(['-sources', ','.join(sources)])
        
        max_time = kwargs.get('max_time', self.timeout)
        if max_time:
            cmd.extend(['-timeout', str(max_time)])
        
        # Run the scan
        result = self._run_command(cmd)
        
        if not result['success']:
            raise BaseScannerError(f"Subfinder scan failed: {result['stderr']}")
        
        # Parse results
        subdomains = self.parse_output(result['stdout'])
        
        return {
            'tool': 'subfinder',
            'target': domain,
            'subdomains': subdomains,
            'total_found': len(subdomains),
            'scan_time': max_time,
            'raw_output': result['stdout']
        }
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Subfinder JSON output"""
        subdomains = []
        
        if not output.strip():
            return subdomains
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                # Try to parse as JSON first (newer versions)
                data = json.loads(line)
                subdomain = {
                    'host': data.get('host', ''),
                    'source': data.get('source', 'unknown'),
                    'ip': data.get('ip', ''),
                    'timestamp': data.get('timestamp', '')
                }
                subdomains.append(subdomain)
            except json.JSONDecodeError:
                # Fallback to plain text parsing
                if self._is_valid_domain(line.strip()):
                    subdomain = {
                        'host': line.strip(),
                        'source': 'unknown',
                        'ip': '',
                        'timestamp': ''
                    }
                    subdomains.append(subdomain)
        
        return subdomains
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(domain))
    
    def scan_with_wordlist(self, domain: str, wordlist_path: str) -> Dict[str, Any]:
        """Run Subfinder with custom wordlist"""
        cmd = [
            self.tool_path, '-d', domain,
            '-w', wordlist_path,
            '-o', '/dev/stdout',
            '-json', '-silent'
        ]
        
        result = self._run_command(cmd)
        
        if not result['success']:
            raise BaseScannerError(f"Subfinder wordlist scan failed: {result['stderr']}")
        
        subdomains = self.parse_output(result['stdout'])
        
        return {
            'tool': 'subfinder',
            'target': domain,
            'method': 'wordlist',
            'wordlist': wordlist_path,
            'subdomains': subdomains,
            'total_found': len(subdomains),
            'raw_output': result['stdout']
        }
    
    def get_available_sources(self) -> List[str]:
        """Get list of available sources"""
        cmd = [self.tool_path, '-ls']
        result = self._run_command(cmd)
        
        if result['success']:
            sources = []
            for line in result['stdout'].split('\n'):
                line = line.strip()
                if line and not line.startswith('[') and not line.startswith('Current'):
                    sources.append(line)
            return sources
        
        return []
