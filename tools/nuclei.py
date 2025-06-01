"""
Nuclei integration for vulnerability scanning
"""

import json
import yaml
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner, BaseScannerError

class NucleiScanner(BaseScanner):
    """Nuclei vulnerability scanner"""
    
    def __init__(self, tool_path: Optional[str] = None):
        super().__init__('nuclei', tool_path)
        self.timeout = 600  # 10 minutes for vulnerability scanning
    
    def scan(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """
        Run Nuclei to scan for vulnerabilities
        
        Args:
            targets: List of URLs/hosts to scan
            **kwargs: Additional options
                - templates: Template tags or paths
                - severity: Severity levels to include
                - exclude_tags: Tags to exclude
                - rate_limit: Requests per second
                - concurrency: Number of concurrent requests
                - timeout: Request timeout
        
        Returns:
            Dict containing scan results
        """
        if not targets:
            raise BaseScannerError("No targets provided for vulnerability scan")
        
        # Create temporary file with targets
        targets_content = '\n'.join(targets)
        targets_file = self._create_temp_file(targets_content)
        
        try:
            # Build command
            cmd = [self.tool_path, '-list', targets_file]
            
            # Add JSON output
            cmd.extend(['-json'])
            
            # Add template specification
            templates = kwargs.get('templates')
            if templates:
                if isinstance(templates, list):
                    for template in templates:
                        cmd.extend(['-t', template])
                else:
                    cmd.extend(['-t', templates])
            else:
                # Use default templates
                cmd.extend(['-t', 'cves/', '-t', 'vulnerabilities/', '-t', 'exposures/'])
            
            # Add severity filter
            severity = kwargs.get('severity')
            if severity:
                if isinstance(severity, list):
                    cmd.extend(['-severity', ','.join(severity)])
                else:
                    cmd.extend(['-severity', severity])
            
            # Add exclude tags
            exclude_tags = kwargs.get('exclude_tags')
            if exclude_tags:
                if isinstance(exclude_tags, list):
                    cmd.extend(['-exclude-tags', ','.join(exclude_tags)])
                else:
                    cmd.extend(['-exclude-tags', exclude_tags])
            
            # Add performance options
            rate_limit = kwargs.get('rate_limit', 150)
            cmd.extend(['-rate-limit', str(rate_limit)])
            
            concurrency = kwargs.get('concurrency', 25)
            cmd.extend(['-c', str(concurrency)])
            
            timeout = kwargs.get('timeout', 5)
            cmd.extend(['-timeout', str(timeout)])
            
            # Add silent mode
            if kwargs.get('silent', True):
                cmd.append('-silent')
            
            # Disable update check
            cmd.append('-disable-update-check')
            
            # Run the scan
            result = self._run_command(cmd)
            
            # Nuclei might return non-zero even on successful scans
            if result['returncode'] not in [0, 1]:
                raise BaseScannerError(f"Nuclei scan failed: {result['stderr']}")
            
            # Parse results
            vulnerabilities = self.parse_output(result['stdout'])
            
            return {
                'tool': 'nuclei',
                'targets': targets,
                'vulnerabilities': vulnerabilities,
                'total_found': len(vulnerabilities),
                'scan_config': {
                    'templates': templates,
                    'severity': severity,
                    'rate_limit': rate_limit,
                    'concurrency': concurrency,
                    'timeout': timeout
                },
                'raw_output': result['stdout']
            }
            
        finally:
            self._cleanup_temp_file(targets_file)
    
    def parse_output(self, output: str) -> List[Dict[str, Any]]:
        """Parse Nuclei JSON output"""
        vulnerabilities = []
        
        if not output.strip():
            return vulnerabilities
        
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
                
            try:
                data = json.loads(line)
                
                # Extract vulnerability information
                vuln = {
                    'template_id': data.get('template-id', ''),
                    'template_name': data.get('info', {}).get('name', ''),
                    'severity': data.get('info', {}).get('severity', 'unknown'),
                    'description': data.get('info', {}).get('description', ''),
                    'reference': data.get('info', {}).get('reference', []),
                    'classification': data.get('info', {}).get('classification', {}),
                    'host': data.get('host', ''),
                    'matched_at': data.get('matched-at', ''),
                    'extracted_results': data.get('extracted-results', []),
                    'curl_command': data.get('curl-command', ''),
                    'timestamp': data.get('timestamp', ''),
                    'matcher_status': data.get('matcher-status', False)
                }
                
                # Add CVE information if available
                cve_info = data.get('info', {}).get('classification', {})
                if 'cve-id' in cve_info:
                    vuln['cve_id'] = cve_info['cve-id']
                
                # Add CVSS score if available
                if 'cvss-score' in cve_info:
                    vuln['cvss_score'] = cve_info['cvss-score']
                
                vulnerabilities.append(vuln)
                
            except json.JSONDecodeError:
                # Skip malformed JSON lines
                continue
        
        return vulnerabilities
    
    def scan_with_custom_templates(self, targets: List[str], template_paths: List[str]) -> Dict[str, Any]:
        """Scan with custom template paths"""
        return self.scan(targets, templates=template_paths)
    
    def scan_by_severity(self, targets: List[str], severity_levels: List[str]) -> Dict[str, Any]:
        """Scan for specific severity levels"""
        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        
        for severity in severity_levels:
            if severity not in valid_severities:
                raise BaseScannerError(f"Invalid severity level: {severity}")
        
        return self.scan(targets, severity=severity_levels)
    
    def scan_cves_only(self, targets: List[str]) -> Dict[str, Any]:
        """Scan for CVEs only"""
        return self.scan(targets, templates=['cves/'])
    
    def scan_exposures_only(self, targets: List[str]) -> Dict[str, Any]:
        """Scan for exposures only"""
        return self.scan(targets, templates=['exposures/'])
    
    def get_template_stats(self) -> Dict[str, Any]:
        """Get statistics about available templates"""
        cmd = [self.tool_path, '-tl']
        result = self._run_command(cmd)
        
        if result['success']:
            # Parse template list output
            lines = result['stdout'].split('\n')
            stats = {
                'total_templates': 0,
                'categories': {},
                'severities': {}
            }
            
            for line in lines:
                if line.strip() and not line.startswith('['):
                    stats['total_templates'] += 1
                    # Basic parsing - could be enhanced
                    if 'critical' in line.lower():
                        stats['severities']['critical'] = stats['severities'].get('critical', 0) + 1
                    elif 'high' in line.lower():
                        stats['severities']['high'] = stats['severities'].get('high', 0) + 1
                    elif 'medium' in line.lower():
                        stats['severities']['medium'] = stats['severities'].get('medium', 0) + 1
                    elif 'low' in line.lower():
                        stats['severities']['low'] = stats['severities'].get('low', 0) + 1
            
            return stats
        
        return {'error': 'Failed to get template statistics'}
    
    def update_templates(self) -> bool:
        """Update Nuclei templates"""
        cmd = [self.tool_path, '-update-templates']
        result = self._run_command(cmd)
        return result['success']
