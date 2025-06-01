"""
Scanner Manager - Orchestrates Subfinder, Naabu, and Nuclei scans
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from .subfinder import SubfinderScanner
from .naabu import NaabuScanner
from .nuclei import NucleiScanner
from .base_scanner import BaseScannerError, ToolNotFoundError

logger = logging.getLogger(__name__)

class ScannerManager:
    """Manages and orchestrates security scanning tools"""
    
    def __init__(self):
        self.subfinder = None
        self.naabu = None
        self.nuclei = None
        self._initialize_scanners()
    
    def _initialize_scanners(self):
        """Initialize available scanners"""
        try:
            self.subfinder = SubfinderScanner()
            logger.info("Subfinder initialized successfully")
        except ToolNotFoundError:
            logger.warning("Subfinder not found - subdomain discovery will be unavailable")
        
        try:
            self.naabu = NaabuScanner()
            logger.info("Naabu initialized successfully")
        except ToolNotFoundError:
            logger.warning("Naabu not found - port scanning will be unavailable")
        
        try:
            self.nuclei = NucleiScanner()
            logger.info("Nuclei initialized successfully")
        except ToolNotFoundError:
            logger.warning("Nuclei not found - vulnerability scanning will be unavailable")
    
    def get_available_tools(self) -> Dict[str, bool]:
        """Get status of available tools"""
        return {
            'subfinder': self.subfinder is not None and self.subfinder.is_available(),
            'naabu': self.naabu is not None and self.naabu.is_available(),
            'nuclei': self.nuclei is not None and self.nuclei.is_available()
        }
    
    def get_tool_versions(self) -> Dict[str, str]:
        """Get versions of available tools"""
        versions = {}
        
        if self.subfinder:
            versions['subfinder'] = self.subfinder.get_version()
        
        if self.naabu:
            versions['naabu'] = self.naabu.get_version()
        
        if self.nuclei:
            versions['nuclei'] = self.nuclei.get_version()
        
        return versions
    
    def full_scan(self, domain: str, **kwargs) -> Dict[str, Any]:
        """
        Perform a complete scan: subdomain discovery -> port scanning -> vulnerability scanning
        
        Args:
            domain: Target domain to scan
            **kwargs: Configuration options for each tool
        
        Returns:
            Complete scan results
        """
        scan_results = {
            'domain': domain,
            'start_time': datetime.utcnow().isoformat(),
            'subdomains': [],
            'open_ports': [],
            'vulnerabilities': [],
            'scan_summary': {
                'subdomains_found': 0,
                'ports_found': 0,
                'vulnerabilities_found': 0
            },
            'errors': []
        }
        
        try:
            # Step 1: Subdomain Discovery
            logger.info(f"Starting subdomain discovery for {domain}")
            if self.subfinder:
                try:
                    subfinder_config = kwargs.get('subfinder', {})
                    subdomain_results = self.subfinder.scan(domain, **subfinder_config)
                    scan_results['subdomains'] = subdomain_results['subdomains']
                    scan_results['scan_summary']['subdomains_found'] = len(subdomain_results['subdomains'])
                    logger.info(f"Found {len(subdomain_results['subdomains'])} subdomains")
                except Exception as e:
                    error_msg = f"Subfinder scan failed: {str(e)}"
                    logger.error(error_msg)
                    scan_results['errors'].append(error_msg)
            else:
                scan_results['errors'].append("Subfinder not available")
            
            # Step 2: Port Scanning
            logger.info("Starting port scanning")
            if self.naabu and scan_results['subdomains']:
                try:
                    # Extract hosts from subdomains
                    hosts = [sub['host'] for sub in scan_results['subdomains']]
                    # Add the main domain
                    if domain not in hosts:
                        hosts.append(domain)
                    
                    naabu_config = kwargs.get('naabu', {})
                    port_results = self.naabu.scan(hosts, **naabu_config)
                    scan_results['open_ports'] = port_results['open_ports']
                    scan_results['scan_summary']['ports_found'] = len(port_results['open_ports'])
                    logger.info(f"Found {len(port_results['open_ports'])} open ports")
                except Exception as e:
                    error_msg = f"Naabu scan failed: {str(e)}"
                    logger.error(error_msg)
                    scan_results['errors'].append(error_msg)
            else:
                if not self.naabu:
                    scan_results['errors'].append("Naabu not available")
                else:
                    scan_results['errors'].append("No subdomains found for port scanning")
            
            # Step 3: Vulnerability Scanning
            logger.info("Starting vulnerability scanning")
            if self.nuclei and scan_results['open_ports']:
                try:
                    # Build target URLs from open ports
                    targets = self._build_target_urls(scan_results['open_ports'])
                    
                    nuclei_config = kwargs.get('nuclei', {})
                    vuln_results = self.nuclei.scan(targets, **nuclei_config)
                    scan_results['vulnerabilities'] = vuln_results['vulnerabilities']
                    scan_results['scan_summary']['vulnerabilities_found'] = len(vuln_results['vulnerabilities'])
                    logger.info(f"Found {len(vuln_results['vulnerabilities'])} vulnerabilities")
                except Exception as e:
                    error_msg = f"Nuclei scan failed: {str(e)}"
                    logger.error(error_msg)
                    scan_results['errors'].append(error_msg)
            else:
                if not self.nuclei:
                    scan_results['errors'].append("Nuclei not available")
                else:
                    scan_results['errors'].append("No open ports found for vulnerability scanning")
        
        except Exception as e:
            error_msg = f"Full scan failed: {str(e)}"
            logger.error(error_msg)
            scan_results['errors'].append(error_msg)
        
        scan_results['end_time'] = datetime.utcnow().isoformat()
        return scan_results
    
    def subdomain_scan_only(self, domain: str, **kwargs) -> Dict[str, Any]:
        """Perform subdomain discovery only"""
        logger.info(f"🔍 SUBFINDER: Starting subdomain discovery for {domain}")
        logger.info(f"🔍 SUBFINDER: Parameters: {kwargs}")

        if not self.subfinder:
            logger.error("🔍 SUBFINDER: Tool not available")
            raise BaseScannerError("Subfinder not available")

        try:
            logger.info("🔍 SUBFINDER: Executing scan...")
            result = self.subfinder.scan(domain, **kwargs)
            logger.info(f"🔍 SUBFINDER: Scan completed, found {len(result.get('subdomains', []))} subdomains")
            return result
        except Exception as e:
            logger.error(f"🔍 SUBFINDER: Scan failed: {str(e)}")
            raise
    
    def port_scan_only(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """Perform port scanning only"""
        logger.info(f"🔌 NAABU: Starting port scan on {len(targets)} targets")
        logger.info(f"🔌 NAABU: Targets: {', '.join(targets[:3])}{'...' if len(targets) > 3 else ''}")
        logger.info(f"🔌 NAABU: Parameters: {kwargs}")

        if not self.naabu:
            logger.error("🔌 NAABU: Tool not available")
            raise BaseScannerError("Naabu not available")

        try:
            logger.info("🔌 NAABU: Executing port scan...")
            result = self.naabu.scan(targets, **kwargs)
            logger.info(f"🔌 NAABU: Port scan completed, found {len(result.get('open_ports', []))} open ports")
            return result
        except Exception as e:
            logger.error(f"🔌 NAABU: Port scan failed: {str(e)}")
            raise
    
    def vulnerability_scan_only(self, targets: List[str], **kwargs) -> Dict[str, Any]:
        """Perform vulnerability scanning only"""
        if not self.nuclei:
            raise BaseScannerError("Nuclei not available")
        
        return self.nuclei.scan(targets, **kwargs)
    
    def _build_target_urls(self, open_ports: List[Dict[str, Any]]) -> List[str]:
        """Build target URLs from open ports"""
        targets = []
        
        for port_info in open_ports:
            host = port_info['host']
            port = port_info['port']
            
            # Determine protocol
            if port in [80, 8080, 8000, 3000]:
                protocol = 'http'
            elif port in [443, 8443]:
                protocol = 'https'
            else:
                # Try both protocols for unknown ports
                targets.append(f"http://{host}:{port}")
                targets.append(f"https://{host}:{port}")
                continue
            
            if port in [80, 443]:
                # Standard ports - no need to specify port
                targets.append(f"{protocol}://{host}")
            else:
                targets.append(f"{protocol}://{host}:{port}")
        
        return list(set(targets))  # Remove duplicates
    
    def quick_scan(self, domain: str) -> Dict[str, Any]:
        """Perform a quick scan with optimized settings"""
        config = {
            'subfinder': {
                'silent': True,
                'max_time': 60  # 1 minute
            },
            'naabu': {
                'top_ports': 100,  # Top 100 ports only
                'rate': 2000,
                'timeout': 3
            },
            'nuclei': {
                'severity': ['critical', 'high'],  # Only critical and high severity
                'rate_limit': 300,  # Faster rate
                'concurrency': 50,
                'timeout': 120,  # 2 minutes for nuclei
                'max_time': 120  # Overall nuclei timeout
            }
        }

        return self.full_scan(domain, **config)
    
    def deep_scan(self, domain: str) -> Dict[str, Any]:
        """Perform a comprehensive deep scan"""
        config = {
            'subfinder': {
                'silent': True,
                'recursive': True,
                'max_time': 300  # 5 minutes
            },
            'naabu': {
                'top_ports': 10000,  # Top 10k ports
                'rate': 1000,
                'timeout': 5,
                'retries': 3
            },
            'nuclei': {
                'templates': ['http/', 'network/'],  # Use simpler, more reliable templates
                'rate_limit': 100,
                'concurrency': 25,
                'timeout': 10
            }
        }
        
        return self.full_scan(domain, **config)
