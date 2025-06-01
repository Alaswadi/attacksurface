"""
Real Security Scanning Service using Subfinder, Naabu, and Nuclei
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from models import db, Asset, Vulnerability, Alert, AssetType, SeverityLevel, AlertType
from tools.scanner_manager import ScannerManager
from tools.base_scanner import BaseScannerError

logger = logging.getLogger(__name__)

class RealScanningService:
    """Real security scanning service using actual tools"""
    
    def __init__(self):
        self.scanner_manager = ScannerManager()
        self.available_tools = self.scanner_manager.get_available_tools()
        logger.info(f"Initialized scanning service with tools: {self.available_tools}")
    
    def scan_domain(self, domain: str, organization_id: int, scan_type: str = 'quick') -> Dict[str, Any]:
        """
        Perform a complete domain scan

        Args:
            domain: Target domain to scan
            organization_id: Organization ID for storing results
            scan_type: Type of scan ('quick', 'deep', 'custom')

        Returns:
            Scan results summary
        """
        logger.info(f"Starting {scan_type} scan for domain: {domain}")

        try:
            # Use the new httpx-enabled scan flow for all scan types
            if scan_type == 'quick':
                scan_results = self.scanner_manager.quick_scan(domain)
            elif scan_type == 'deep':
                scan_results = self.scanner_manager.deep_scan(domain)
            else:
                scan_results = self.scanner_manager.full_scan(domain)

            # Process and store results
            summary = self._process_scan_results(scan_results, organization_id)

            logger.info(f"Scan completed for {domain}: {summary}")
            return summary

        except Exception as e:
            logger.error(f"Scan failed for {domain}: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'domain': domain,
                'scan_type': scan_type
            }

    def _quick_scan_without_nuclei(self, domain: str) -> Dict[str, Any]:
        """Perform a quick scan without nuclei for faster response"""
        from datetime import datetime

        logger.info(f"🚀 QUICK SCAN STARTED for domain: {domain}")

        scan_results = {
            'domain': domain,
            'start_time': datetime.utcnow().isoformat(),
            'subdomains': [],
            'open_ports': [],
            'vulnerabilities': [],
            'errors': [],
            'scan_summary': {}
        }

        try:
            # Subdomain discovery
            logger.info(f"🔍 STEP 1: Starting subdomain discovery for {domain}")
            logger.info(f"📋 Subfinder parameters: silent=True, max_time=60 seconds")

            subdomains = self.scanner_manager.subdomain_scan_only(domain, silent=True, max_time=60)
            scan_results['subdomains'] = subdomains.get('subdomains', [])

            logger.info(f"✅ STEP 1 COMPLETE: Found {len(scan_results['subdomains'])} subdomains")
            for i, sub in enumerate(scan_results['subdomains'][:5]):  # Log first 5
                logger.info(f"   📍 Subdomain {i+1}: {sub.get('host', 'unknown')}")
            if len(scan_results['subdomains']) > 5:
                logger.info(f"   📍 ... and {len(scan_results['subdomains']) - 5} more subdomains")

            # Port scanning on discovered subdomains
            if scan_results['subdomains']:
                hosts = [sub['host'] for sub in scan_results['subdomains']]
                logger.info(f"🔌 STEP 2: Starting port scanning on {len(hosts)} hosts")
                logger.info(f"📋 Naabu parameters: top_ports=100, rate=2000, timeout=3")
                logger.info(f"🎯 Scanning hosts: {', '.join(hosts[:3])}{'...' if len(hosts) > 3 else ''}")

                ports = self.scanner_manager.port_scan_only(hosts, top_ports=100, rate=2000, timeout=3)
                scan_results['open_ports'] = ports.get('open_ports', [])

                logger.info(f"✅ STEP 2 COMPLETE: Found {len(scan_results['open_ports'])} open ports")
                for i, port in enumerate(scan_results['open_ports'][:5]):  # Log first 5
                    logger.info(f"   🔓 Port {i+1}: {port.get('host', 'unknown')}:{port.get('port', 'unknown')}")
                if len(scan_results['open_ports']) > 5:
                    logger.info(f"   🔓 ... and {len(scan_results['open_ports']) - 5} more open ports")
            else:
                logger.info("⚠️  STEP 2 SKIPPED: No subdomains found to scan")

            # Skip nuclei for quick response
            logger.info("⚡ STEP 3: Skipping vulnerability scan for quick response")

            # Create summary
            scan_results['scan_summary'] = {
                'subdomains_found': len(scan_results['subdomains']),
                'ports_found': len(scan_results['open_ports']),
                'vulnerabilities_found': 0  # No nuclei scan
            }

            logger.info(f"📊 SCAN SUMMARY: {scan_results['scan_summary']['subdomains_found']} subdomains, {scan_results['scan_summary']['ports_found']} open ports")

        except Exception as e:
            error_msg = f"Quick scan error: {str(e)}"
            logger.error(f"❌ SCAN ERROR: {error_msg}")
            scan_results['errors'].append(error_msg)

        scan_results['end_time'] = datetime.utcnow().isoformat()
        logger.info(f"🏁 QUICK SCAN COMPLETED for {domain}")
        return scan_results
    
    def _process_scan_results(self, scan_results: Dict[str, Any], organization_id: int) -> Dict[str, Any]:
        """Process and store scan results in database"""
        domain = scan_results['domain']
        
        # Store discovered assets
        assets_created = self._store_assets(scan_results, organization_id)
        
        # Store vulnerabilities
        vulnerabilities_created = self._store_vulnerabilities(scan_results, organization_id)
        
        # Create alerts for critical findings
        alerts_created = self._create_alerts(scan_results, organization_id)
        
        # Commit all changes
        db.session.commit()
        
        return {
            'success': True,
            'domain': domain,
            'scan_summary': scan_results.get('scan_summary', {}),
            'assets_created': assets_created,
            'vulnerabilities_created': vulnerabilities_created,
            'alerts_created': alerts_created,
            'errors': scan_results.get('errors', []),
            'scan_time': scan_results.get('end_time', '')
        }
    
    def _store_assets(self, scan_results: Dict[str, Any], organization_id: int) -> int:
        """Store discovered assets in database"""
        assets_created = 0
        
        # Store main domain
        domain = scan_results['domain']
        if not Asset.query.filter_by(name=domain, organization_id=organization_id).first():
            main_asset = Asset(
                name=domain,
                asset_type=AssetType.DOMAIN,
                description=f"Main domain discovered during scan",
                organization_id=organization_id,
                last_scanned=datetime.utcnow()
            )
            db.session.add(main_asset)
            assets_created += 1
        
        # Store subdomains
        for subdomain_info in scan_results.get('subdomains', []):
            subdomain = subdomain_info['host']
            
            # Check if asset already exists
            existing_asset = Asset.query.filter_by(
                name=subdomain, 
                organization_id=organization_id
            ).first()
            
            if not existing_asset:
                asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    description=f"Subdomain discovered via {subdomain_info.get('source', 'unknown')}",
                    organization_id=organization_id,
                    last_scanned=datetime.utcnow()
                )
                db.session.add(asset)
                assets_created += 1
            else:
                # Update last scanned time
                existing_asset.last_scanned = datetime.utcnow()
        
        # Store IP addresses from port scan results
        for port_info in scan_results.get('open_ports', []):
            ip_address = port_info.get('ip')
            if ip_address and ip_address != port_info.get('host'):
                existing_ip = Asset.query.filter_by(
                    name=ip_address,
                    organization_id=organization_id
                ).first()
                
                if not existing_ip:
                    ip_asset = Asset(
                        name=ip_address,
                        asset_type=AssetType.IP_ADDRESS,
                        description=f"IP address discovered during port scan",
                        organization_id=organization_id,
                        last_scanned=datetime.utcnow()
                    )
                    db.session.add(ip_asset)
                    assets_created += 1
        
        return assets_created
    
    def _store_vulnerabilities(self, scan_results: Dict[str, Any], organization_id: int) -> int:
        """Store discovered vulnerabilities in database"""
        vulnerabilities_created = 0
        
        for vuln_info in scan_results.get('vulnerabilities', []):
            # Find the associated asset
            host = vuln_info.get('host', '').replace('http://', '').replace('https://', '').split(':')[0]
            asset = Asset.query.filter_by(name=host, organization_id=organization_id).first()
            
            if not asset:
                # Create asset if it doesn't exist
                asset = Asset(
                    name=host,
                    asset_type=AssetType.SUBDOMAIN,
                    description="Asset discovered during vulnerability scan",
                    organization_id=organization_id,
                    last_scanned=datetime.utcnow()
                )
                db.session.add(asset)
                db.session.flush()  # Get the asset ID
            
            # Map Nuclei severity to our severity levels
            nuclei_severity = vuln_info.get('severity', 'unknown').lower()
            severity_mapping = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW,
                'info': SeverityLevel.INFO
            }
            severity = severity_mapping.get(nuclei_severity, SeverityLevel.MEDIUM)
            
            # Check if vulnerability already exists
            existing_vuln = Vulnerability.query.filter_by(
                title=vuln_info.get('template_name', 'Unknown Vulnerability'),
                asset_id=asset.id
            ).first()
            
            if not existing_vuln:
                vulnerability = Vulnerability(
                    title=vuln_info.get('template_name', 'Unknown Vulnerability'),
                    description=self._format_vulnerability_description(vuln_info),
                    severity=severity,
                    asset_id=asset.id,
                    organization_id=organization_id,
                    discovered_at=datetime.utcnow(),
                    cve_id=vuln_info.get('cve_id'),
                    cvss_score=vuln_info.get('cvss_score')
                )
                db.session.add(vulnerability)
                vulnerabilities_created += 1
        
        return vulnerabilities_created
    
    def _create_alerts(self, scan_results: Dict[str, Any], organization_id: int) -> int:
        """Create alerts for critical findings"""
        alerts_created = 0
        
        # Alert for critical vulnerabilities
        critical_vulns = [v for v in scan_results.get('vulnerabilities', []) 
                         if v.get('severity', '').lower() == 'critical']
        
        for vuln in critical_vulns:
            host = vuln.get('host', '').replace('http://', '').replace('https://', '').split(':')[0]
            asset = Asset.query.filter_by(name=host, organization_id=organization_id).first()
            
            if asset:
                alert = Alert(
                    title=f"Critical Vulnerability: {vuln.get('template_name', 'Unknown')}",
                    description=f"Critical vulnerability found on {host}: {vuln.get('description', '')}",
                    alert_type=AlertType.VULNERABILITY,
                    severity=SeverityLevel.CRITICAL,
                    organization_id=organization_id,
                    asset_id=asset.id,
                    created_at=datetime.utcnow()
                )
                db.session.add(alert)
                alerts_created += 1
        
        # Alert for high number of open ports
        open_ports_count = len(scan_results.get('open_ports', []))
        if open_ports_count > 10:
            alert = Alert(
                title=f"High Number of Open Ports Detected",
                description=f"Found {open_ports_count} open ports across discovered assets. This may indicate excessive attack surface.",
                alert_type=AlertType.VULNERABILITY,
                severity=SeverityLevel.MEDIUM,
                organization_id=organization_id,
                created_at=datetime.utcnow()
            )
            db.session.add(alert)
            alerts_created += 1
        
        # Alert for new subdomains
        subdomains_count = len(scan_results.get('subdomains', []))
        if subdomains_count > 0:
            alert = Alert(
                title=f"New Subdomains Discovered",
                description=f"Discovered {subdomains_count} subdomains for {scan_results['domain']}. Review for unauthorized or forgotten assets.",
                alert_type=AlertType.NEW_ASSET,
                severity=SeverityLevel.INFO,
                organization_id=organization_id,
                created_at=datetime.utcnow()
            )
            db.session.add(alert)
            alerts_created += 1
        
        return alerts_created
    
    def _format_vulnerability_description(self, vuln_info: Dict[str, Any]) -> str:
        """Format vulnerability description with additional details"""
        description = vuln_info.get('description', '')
        template_id = vuln_info.get('template_id', '')
        matched_at = vuln_info.get('matched_at', '')
        
        formatted_desc = f"{description}\n\n"
        formatted_desc += f"Template ID: {template_id}\n"
        formatted_desc += f"Matched at: {matched_at}\n"
        
        if vuln_info.get('reference'):
            formatted_desc += f"References: {', '.join(vuln_info['reference'])}\n"
        
        if vuln_info.get('cve_id'):
            formatted_desc += f"CVE ID: {vuln_info['cve_id']}\n"
        
        if vuln_info.get('cvss_score'):
            formatted_desc += f"CVSS Score: {vuln_info['cvss_score']}\n"
        
        return formatted_desc.strip()
    
    def get_tool_status(self) -> Dict[str, Any]:
        """Get status of security tools"""
        return {
            'available_tools': self.available_tools,
            'tool_versions': self.scanner_manager.get_tool_versions(),
            'scanner_ready': any(self.available_tools.values())
        }
    
    def test_tools(self) -> Dict[str, Any]:
        """Test all security tools"""
        results = {}
        
        if self.available_tools.get('subfinder'):
            try:
                test_result = self.scanner_manager.subfinder.scan('example.com', silent=True, max_time=30)
                results['subfinder'] = {'status': 'working', 'test_result': 'success'}
            except Exception as e:
                results['subfinder'] = {'status': 'error', 'error': str(e)}
        else:
            results['subfinder'] = {'status': 'not_available'}
        
        if self.available_tools.get('masscan'):
            try:
                test_result = self.scanner_manager.masscan.scan(['8.8.8.8'], top_ports=10, timeout=10)
                results['masscan'] = {'status': 'working', 'test_result': 'success'}
            except Exception as e:
                results['masscan'] = {'status': 'error', 'error': str(e)}
        else:
            results['masscan'] = {'status': 'not_available'}
        
        if self.available_tools.get('nuclei'):
            try:
                # Test with a simple template
                test_result = self.scanner_manager.nuclei.scan(['http://httpbin.org'], templates=['http/miscellaneous/robots-txt.yaml'], timeout=30)
                results['nuclei'] = {'status': 'working', 'test_result': 'success'}
            except Exception as e:
                results['nuclei'] = {'status': 'error', 'error': str(e)}
        else:
            results['nuclei'] = {'status': 'not_available'}

        if self.available_tools.get('httpx'):
            try:
                # Test with a simple HTTP probe
                test_result = self.scanner_manager.httpx.scan(['httpbin.org'], timeout=10)
                results['httpx'] = {'status': 'working', 'test_result': 'success'}
            except Exception as e:
                results['httpx'] = {'status': 'error', 'error': str(e)}
        else:
            results['httpx'] = {'status': 'not_available'}

        return results
