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
        self.timeout = None  # No timeout for comprehensive vulnerability scanning
    
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

        # Debug: Log target information
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"🔍 NUCLEI: Scanning {len(targets)} targets")
        logger.info(f"🔍 NUCLEI: Target list: {targets}")
        logger.info(f"🔍 NUCLEI: Target file content:")
        logger.info(f"📄 {targets_content}")

        try:
            # Build command
            cmd = [self.tool_path, '-list', targets_file]
            
            # Add JSON Lines output
            cmd.extend(['-jsonl'])
            
            # Add template specification
            templates = kwargs.get('templates')
            if templates:
                if isinstance(templates, list):
                    for template in templates:
                        cmd.extend(['-t', template])
                else:
                    cmd.extend(['-t', templates])
            else:
                # Use default templates - just scan without specific template paths
                # This will use all available templates
                pass  # Don't add any template specification to use all available
            
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
            
            # Add optimized performance options
            rate_limit = kwargs.get('rate_limit', 200)
            cmd.extend(['-rl', str(rate_limit)])  # Use -rl instead of -rate-limit

            concurrency = kwargs.get('concurrency', 30)
            cmd.extend(['-c', str(concurrency)])

            # Add bulk size for better performance
            bulk_size = kwargs.get('bulk_size', 25)
            cmd.extend(['-bs', str(bulk_size)])

            # Add scan strategy for multiple hosts
            scan_strategy = kwargs.get('scan_strategy', 'host-spray')
            cmd.extend(['-ss', scan_strategy])

            timeout = kwargs.get('timeout', 8)
            cmd.extend(['-timeout', str(timeout)])

            # Add retry logic for reliability
            retries = kwargs.get('retries', 1)
            if retries > 0:
                cmd.extend(['-retries', str(retries)])

            # Add max host error threshold
            max_host_error = kwargs.get('max_host_error', 30)
            cmd.extend(['-mhe', str(max_host_error)])

            # Add include/exclude tags if specified
            include_tags = kwargs.get('include_tags', [])
            if include_tags:
                for tag in include_tags:
                    cmd.extend(['-include-tags', tag])

            exclude_tags = kwargs.get('exclude_tags', [])
            if exclude_tags:
                for tag in exclude_tags:
                    cmd.extend(['-exclude-tags', tag])
            
            # Add silent mode
            if kwargs.get('silent', True):
                cmd.append('-silent')
            
            # Disable update check
            cmd.append('-disable-update-check')

            # Debug: Log the complete command
            logger.info(f"🔍 NUCLEI: Executing command: {' '.join(cmd)}")

            # Run the scan
            result = self._run_command(cmd)

            # Log Nuclei result details
            logger.info(f"🔍 NUCLEI: Return code: {result['returncode']}")
            if result['stderr']:
                logger.info(f"🔍 NUCLEI: STDERR: {result['stderr'].strip()}")

            # Debug: Log raw output
            logger.info(f"🔍 NUCLEI: Raw stdout length: {len(result['stdout'])}")
            if result['stdout'].strip():
                logger.info(f"🔍 NUCLEI: Raw stdout (first 500 chars): {result['stdout'][:500]}")
            else:
                logger.info(f"🔍 NUCLEI: No stdout output received")

            # Nuclei return codes:
            # 0 = success with findings
            # 1 = success with no findings
            # 2 = success but some templates failed (acceptable)
            if result['returncode'] not in [0, 1, 2]:
                raise BaseScannerError(f"Nuclei scan failed: {result['stderr']}")

            # Parse results
            vulnerabilities = self.parse_output(result['stdout'])
            logger.info(f"🔍 NUCLEI: Parsed {len(vulnerabilities)} vulnerabilities")
            
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
        """Update Nuclei templates with multiple fallback methods"""
        import logging
        logger = logging.getLogger(__name__)

        # Try multiple update methods
        update_methods = [
            [self.tool_path, '-update-templates', '-ut'],  # Latest method
            [self.tool_path, '-update-templates'],          # Standard method
            [self.tool_path, '-update']                     # Fallback method
        ]

        for i, cmd in enumerate(update_methods, 1):
            try:
                logger.info(f"🔄 Attempting Nuclei template update method {i}: {' '.join(cmd)}")
                result = self._run_command(cmd)
                if result['success']:
                    logger.info(f"✅ Nuclei templates updated successfully with method {i}")
                    return True
                else:
                    logger.warning(f"⚠️ Template update method {i} failed: {result.get('stderr', 'Unknown error')}")
            except Exception as e:
                logger.warning(f"⚠️ Template update method {i} exception: {str(e)}")
                continue

        logger.error("❌ All Nuclei template update methods failed")
        return False

    def verify_templates(self) -> Dict[str, Any]:
        """Verify that templates are available and get basic stats"""
        import logging
        logger = logging.getLogger(__name__)

        try:
            # Try to list templates
            cmd = [self.tool_path, '-tl']
            result = self._run_command(cmd)

            if result['success']:
                lines = result['stdout'].split('\n')
                template_count = len([line for line in lines if line.strip() and not line.startswith('[')])
                logger.info(f"✅ Nuclei templates verified: {template_count} templates available")
                return {
                    'success': True,
                    'template_count': template_count,
                    'sample_templates': lines[:10]
                }
            else:
                logger.error(f"❌ Template verification failed: {result.get('stderr', 'Unknown error')}")
                return {'success': False, 'error': result.get('stderr', 'Unknown error')}

        except Exception as e:
            logger.error(f"❌ Template verification exception: {str(e)}")
            return {'success': False, 'error': str(e)}

    def ensure_templates(self) -> bool:
        """Ensure templates are available, update if necessary"""
        import logging
        logger = logging.getLogger(__name__)

        # First verify if templates exist
        verification = self.verify_templates()
        if verification['success'] and verification.get('template_count', 0) > 0:
            logger.info(f"✅ Templates already available: {verification['template_count']} templates")
            return True

        # Templates not available, try to update
        logger.info("📥 Templates not found, attempting to download...")
        if self.update_templates():
            # Verify again after update
            verification = self.verify_templates()
            return verification['success'] and verification.get('template_count', 0) > 0

        return False
