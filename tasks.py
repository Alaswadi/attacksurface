#!/usr/bin/env python3
"""
Celery tasks for Attack Surface Discovery SaaS
Background tasks for scanning, processing, and notifications
Optimized for large-scale domain scanning with hundreds/thousands of subdomains
"""

import logging
import json
import re
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional
from app import create_app
from models import db, Asset, Vulnerability, Alert, Organization, AssetType, SeverityLevel, AlertType

# Create Flask app and get Celery instance
flask_app = create_app()
celery = flask_app.celery

logger = logging.getLogger(__name__)

# Celery configuration is now handled in config.py and app.py
# This avoids configuration conflicts with newer Celery versions

# Vulnerability validation functions
def calculate_vulnerability_confidence(vuln_data):
    """Calculate confidence score for vulnerability finding"""
    score = 60  # Higher base score (was 50)

    # Template-based confidence
    template_name = vuln_data.get('template_name', '').lower()
    if 'cve-' in template_name:
        score += 25  # CVE templates are highly reliable
    elif 'default-login' in template_name:
        score += 20  # Default logins are usually accurate
    elif 'exposure' in template_name:
        score += 20  # Exposures are generally reliable (increased from 15)
    elif 'takeover' in template_name:
        score += 20  # Subdomain takeovers are critical
    elif 'misconfiguration' in template_name:
        score += 15  # Misconfigurations are valuable (increased from 10)

    # Severity-based confidence
    severity = vuln_data.get('severity', '').lower()
    if severity == 'critical':
        score += 15
    elif severity == 'high':
        score += 10
    elif severity == 'medium':
        score += 8  # Increased from 5
    elif severity == 'low':
        score += 5  # Added low severity bonus
    elif severity == 'info':
        score += 3  # Added info severity bonus

    # Response-based validation (more generous)
    response_code = vuln_data.get('response_code', 0)
    if response_code in [200, 401, 403, 500]:
        score += 10  # Valid HTTP responses indicate real findings
    elif response_code in [404, 502, 503]:
        score -= 5  # Reduced penalty (was -10)

    # Template category confidence (more generous)
    template_path = vuln_data.get('template_path', '').lower()
    if any(category in template_path for category in ['cves/', 'exposures/', 'default-logins/', 'misconfiguration/']):
        score += 10
    elif any(category in template_path for category in ['technologies/', 'workflows/']):
        score += 5  # Added bonus for these categories
    elif any(category in template_path for category in ['fuzzing/', 'helpers/']):
        score -= 10  # Reduced penalty (was -15)

    return min(max(score, 30), 100)  # Clamp between 30-100 (raised minimum)

def validate_vulnerability_finding(vuln_data, confidence_threshold=60):
    """Validate vulnerability finding to reduce false positives"""

    # 1. Minimum confidence threshold (lowered from 70 to 60)
    confidence = vuln_data.get('confidence_score', 0)
    if confidence < confidence_threshold:
        logger.debug(f"🔍 VALIDATION: Rejected - confidence {confidence} < {confidence_threshold}")
        return False

    # 2. Check for common false positive patterns in description (more lenient)
    description = vuln_data.get('description', '').lower()
    false_positive_patterns = [
        'test page', 'example', 'placeholder', 'dummy'
    ]
    if any(pattern in description for pattern in false_positive_patterns):
        logger.debug(f"🔍 VALIDATION: Rejected - false positive pattern in description")
        return False

    # 3. Validate response content length (more lenient)
    response = vuln_data.get('response', '')
    if len(response) < 10:  # Reduced from 30 to 10
        logger.debug(f"🔍 VALIDATION: Rejected - response too short ({len(response)} chars)")
        return False

    # 4. Check for template reliability (more lenient)
    template_name = vuln_data.get('template_name', '').lower()
    unreliable_templates = ['test-template', 'sample-template']
    if any(pattern in template_name for pattern in unreliable_templates):
        logger.debug(f"🔍 VALIDATION: Rejected - unreliable template")
        return False

    # 5. Accept all severities (removed strict info filtering)
    logger.debug(f"🔍 VALIDATION: Accepted - {vuln_data.get('template_name', 'unknown')} with confidence {confidence}")
    return True

@celery.task(bind=True)
def comprehensive_nuclei_scan_task(self, main_domain, organization_id, scan_type='deep'):
    """
    Asynchronous comprehensive Nuclei vulnerability scan for main domain only
    Runs without timeout constraints for thorough coverage
    """
    logger.info(f"🔍 NUCLEI ASYNC: Starting comprehensive vulnerability scan for main domain: {main_domain}")

    try:
        with flask_app.app_context():
            # Import Nuclei scanner
            from tools.nuclei import NucleiScanner
            nuclei_scanner = NucleiScanner()

            # Ensure templates are available
            if not nuclei_scanner.ensure_templates():
                logger.warning("⚠️ NUCLEI ASYNC: Templates not available, aborting scan")
                return {'success': False, 'error': 'Templates not available'}

            # Configure Nuclei for comprehensive main domain scanning (more conservative)
            nuclei_config = {
                'quick': {
                    'templates': ['cves/', 'exposures/', 'default-logins/', 'takeovers/'],
                    'rate_limit': 50,           # Much more conservative to avoid being killed
                    'concurrency': 10,          # Lower concurrency for stability
                    'bulk_size': 5,             # Smaller bulk size
                    'scan_strategy': 'host-spray',
                    'timeout': 10,              # Shorter per-request timeout
                    'severity': ['critical', 'high', 'medium', 'low', 'info'],
                    'retries': 1,               # Fewer retries
                    'max_host_error': 10        # Lower error threshold
                },
                'deep': {
                    'templates': ['cves/', 'exposures/', 'vulnerabilities/', 'misconfiguration/', 'default-logins/', 'takeovers/', 'technologies/'],
                    'rate_limit': 100,          # Thorough scanning
                    'concurrency': 20,          # Conservative for reliability
                    'bulk_size': 15,
                    'scan_strategy': 'host-spray',
                    'timeout': 20,              # Extended per-request timeout
                    'severity': ['critical', 'high', 'medium'],
                    'retries': 3,
                    'max_host_error': 50
                },
                'comprehensive': {
                    'templates': ['cves/', 'exposures/', 'vulnerabilities/', 'misconfiguration/', 'default-logins/', 'takeovers/', 'technologies/', 'workflows/'],
                    'rate_limit': 75,           # Very thorough
                    'concurrency': 15,          # Maximum stability
                    'bulk_size': 10,
                    'scan_strategy': 'host-spray',
                    'timeout': 30,              # Extended timeout for complex checks
                    'severity': ['critical', 'high', 'medium', 'low', 'info'],
                    'retries': 3,
                    'max_host_error': 100,
                    'include_tags': ['oast'],
                    'exclude_tags': ['dos', 'intrusive']
                }
            }

            config = nuclei_config.get(scan_type, nuclei_config['deep'])

            # Prepare main domain target (strip any protocol, let Nuclei handle protocol detection)
            clean_domain = main_domain.replace('http://', '').replace('https://', '').split('/')[0]
            main_domain_targets = [clean_domain]

            logger.info(f"🔍 NUCLEI ASYNC: Scanning main domain with config: {config}")
            logger.info(f"🔍 NUCLEI ASYNC: Clean domain target: {main_domain_targets}")

            # Update task state
            self.update_state(
                state='PROGRESS',
                meta={
                    'stage': 'nuclei_main_domain_scanning',
                    'domain': main_domain,
                    'message': f'Performing comprehensive vulnerability scan on {main_domain}...',
                    'targets': main_domain_targets,
                    'config': config
                }
            )

            # Perform comprehensive vulnerability scanning (no timeout limit)
            vuln_results = nuclei_scanner.scan(main_domain_targets, **config)
            raw_vulnerabilities = vuln_results.get('vulnerabilities', [])

            logger.info(f"🔍 NUCLEI ASYNC: Found {len(raw_vulnerabilities)} potential vulnerabilities")

            # Process and validate vulnerabilities (simplified - no confidence scoring)
            vulnerability_results = []
            validated_count = 0

            for vuln_data in raw_vulnerabilities:
                logger.info(f"🔍 PROCESSING: Template: {vuln_data.get('template_name', 'unknown')}")
                logger.info(f"🔍 PROCESSING: Severity: {vuln_data.get('severity', 'unknown')}")

                # Simple validation based on severity (no confidence scoring)
                severity = vuln_data.get('severity', 'unknown').lower()
                is_validated = severity in ['critical', 'high', 'medium']  # Auto-validate critical/high/medium
                vuln_data['is_validated'] = is_validated

                # Store ALL vulnerabilities, regardless of validation status
                vulnerability_results.append(vuln_data)

                if is_validated:
                    validated_count += 1
                    logger.info(f"✅ VALIDATION: Auto-validated vulnerability: {vuln_data.get('template_name', 'unknown')} (severity: {severity})")
                else:
                    logger.info(f"⚠️ VALIDATION: Stored for manual review: {vuln_data.get('template_name', 'unknown')} (severity: {severity})")

            logger.info(f"🔍 NUCLEI ASYNC: Stored {len(vulnerability_results)} total vulnerabilities ({validated_count} validated, {len(raw_vulnerabilities) - validated_count} unvalidated)")

            # Store vulnerabilities in database
            from models import Vulnerability, SeverityLevel, Asset

            severity_mapping = {
                'critical': SeverityLevel.CRITICAL,
                'high': SeverityLevel.HIGH,
                'medium': SeverityLevel.MEDIUM,
                'low': SeverityLevel.LOW,
                'info': SeverityLevel.INFO
            }

            vulnerabilities_stored = 0

            # Find the main domain asset (use clean domain)
            main_domain_asset = Asset.query.filter_by(
                name=clean_domain,
                organization_id=organization_id
            ).first()

            if main_domain_asset:
                for vuln_data in vulnerability_results:
                    try:
                        # Map severity
                        severity_str = vuln_data.get('severity', 'medium').lower()
                        severity = severity_mapping.get(severity_str, SeverityLevel.MEDIUM)

                        # Create vulnerability record with validation fields (no confidence scoring)
                        vulnerability = Vulnerability(
                            title=vuln_data.get('template_name', 'Unknown Vulnerability'),
                            description=vuln_data.get('description', ''),
                            severity=severity,
                            asset_id=main_domain_asset.id,
                            organization_id=organization_id,
                            discovered_at=datetime.now(),
                            cve_id=vuln_data.get('cve_id'),
                            is_resolved=False,
                            # Validation fields (simplified)
                            is_validated=vuln_data.get('is_validated', True),
                            template_name=vuln_data.get('template_name', ''),
                            cvss_score=vuln_data.get('cvss_score'),
                            asset_metadata=vuln_data  # Store raw scan data
                        )
                        db.session.add(vulnerability)

                        # Update asset metadata
                        if main_domain_asset.asset_metadata:
                            existing_metadata = main_domain_asset.asset_metadata.copy()
                            if 'vulnerabilities' not in existing_metadata:
                                existing_metadata['vulnerabilities'] = []

                            vuln_metadata = {
                                'template_name': vuln_data.get('template_name', ''),
                                'severity': severity_str,
                                'description': vuln_data.get('description', ''),
                                'is_validated': vuln_data.get('is_validated', True),
                                'discovered_at': datetime.now().isoformat()
                            }
                            if vuln_data.get('cve_id'):
                                vuln_metadata['cve_id'] = vuln_data.get('cve_id')

                            existing_metadata['vulnerabilities'].append(vuln_metadata)
                            existing_metadata['nuclei_scan_status'] = 'completed'
                            existing_metadata['nuclei_scan_completed_at'] = datetime.now().isoformat()
                            main_domain_asset.asset_metadata = existing_metadata
                            vulnerabilities_stored += 1

                            # Log with validation status
                            validation_status = "✅ VALIDATED" if vuln_data.get('is_validated') else "⚠️ UNVALIDATED"
                            logger.info(f"{validation_status}: {vuln_data.get('template_name', 'Unknown')} (severity: {severity_str})")

                    except Exception as e:
                        logger.error(f"❌ NUCLEI ASYNC: Vulnerability storage failed: {str(e)}")
                        continue

                # Commit all vulnerability updates
                try:
                    db.session.commit()
                    logger.info(f"📊 NUCLEI ASYNC: Stored {vulnerabilities_stored} vulnerabilities for {main_domain}")
                except Exception as e:
                    logger.error(f"❌ NUCLEI ASYNC: Database commit failed: {str(e)}")
                    db.session.rollback()
            else:
                logger.warning(f"⚠️ NUCLEI ASYNC: Main domain asset not found: {main_domain}")

            # Final success state
            self.update_state(
                state='SUCCESS',
                meta={
                    'stage': 'nuclei_completed',
                    'domain': main_domain,
                    'vulnerabilities_found': len(vulnerability_results),
                    'vulnerabilities_stored': vulnerabilities_stored,
                    'message': f'Comprehensive vulnerability scan completed for {main_domain}'
                }
            )

            return {
                'success': True,
                'domain': main_domain,
                'vulnerabilities_found': len(vulnerability_results),
                'vulnerabilities_stored': vulnerabilities_stored,
                'scan_type': scan_type,
                'message': 'Comprehensive Nuclei scan completed successfully'
            }

    except Exception as e:
        error_msg = str(e)
        logger.error(f"❌ NUCLEI ASYNC: Comprehensive scan failed for {main_domain}: {error_msg}")

        # Update state with proper error handling
        try:
            self.update_state(
                state='FAILURE',
                meta={
                    'domain': main_domain,
                    'error': error_msg,
                    'stage': 'nuclei_failed',
                    'message': f'Nuclei scan failed: {error_msg}'
                }
            )
        except Exception as state_error:
            logger.error(f"❌ Failed to update task state: {str(state_error)}")

        # Return failure result
        return {
            'success': False,
            'domain': main_domain,
            'error': error_msg,
            'message': f'Comprehensive Nuclei scan failed: {error_msg}'
        }

@celery.task(bind=True)
def test_task(self):
    """Test task to verify Celery is working"""
    logger.info("Test task executed successfully")
    return "Test task completed"

# ============================================================================
# LARGE-SCALE SCANNING ORCHESTRATOR
# ============================================================================

@celery.task(bind=True, name='tasks.large_domain_scan_orchestrator')
def large_domain_scan_orchestrator(self, domain: str, organization_id: int, scan_type: str = 'deep'):
    """
    Orchestrator task for large-scale domain scanning
    Manages the complete workflow: Subfinder → httpx → nmap + Nuclei

    This task coordinates the entire scanning pipeline for domains that may have
    hundreds or thousands of subdomains, ensuring efficient resource utilization
    and progress tracking.

    Args:
        domain (str): Target domain to scan
        organization_id (int): Organization ID
        scan_type (str): Type of scan (quick, deep, full)

    Returns:
        dict: Complete scan orchestration results
    """
    try:
        # Update task state
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'initializing',
                'domain': domain,
                'progress': 0,
                'message': f'Initializing large-scale scan for {domain}',
                'start_time': datetime.now().isoformat()
            }
        )

        logger.info(f"🚀 Starting large-scale {scan_type} scan orchestration for domain: {domain}")

        # PROGRESSIVE STAGE 1: Subdomain Discovery with Immediate Storage
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'subdomain_discovery',
                'domain': domain,
                'progress': 10,
                'message': f'Discovering subdomains for {domain}...',
                'current_phase': 'Subfinder scanning'
            }
        )

        # Execute the complete scanning workflow synchronously within this task
        # This avoids the Celery .get() restriction by doing everything in one task

        # Stage 1: Subdomain Discovery
        logger.info(f"🔍 Starting subdomain discovery for {domain}")

        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'subfinder_scanning',
                'domain': domain,
                'progress': 15,
                'message': f'Running Subfinder scan for {domain}...',
                'current_phase': 'Subfinder subdomain discovery'
            }
        )

        # Import scanning service
        from services.real_scanning_service import RealScanningService
        scanning_service = RealScanningService()

        # Configure Subfinder based on scan type
        subfinder_config = {
            'quick': {'silent': True, 'max_time': 60, 'recursive': False},
            'deep': {'silent': True, 'max_time': 300, 'recursive': True},
            'full': {'silent': True, 'max_time': 600, 'recursive': True, 'all_sources': True}
        }

        config = subfinder_config.get(scan_type, subfinder_config['deep'])

        # Perform subdomain discovery
        scan_results = scanning_service.scanner_manager.subdomain_scan_only(domain, **config)
        subdomains = scan_results.get('subdomains', [])

        logger.info(f"📊 Discovered {len(subdomains)} subdomains for {domain}")

        # Stage 2: HTTP Probing (BEFORE storing subdomains)
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'http_probing',
                'domain': domain,
                'progress': 40,
                'message': f'Probing {len(subdomains)} subdomains for live hosts...',
                'current_phase': 'HTTP probing with httpx',
                'subdomains_found': len(subdomains)
            }
        )

        logger.info(f"🌐 Starting HTTP probing for {len(subdomains)} subdomains")

        # Extract hostnames for HTTP probing
        hostnames = []
        for subdomain in subdomains:
            if isinstance(subdomain, dict):
                hostname = subdomain.get('host', '')
            else:
                hostname = str(subdomain)
            if hostname:
                hostnames.append(hostname)

        # Execute HTTP probing
        alive_hosts = []
        http_data = {}

        if hostnames:
            try:
                # Import httpx scanner
                from tools.httpx import HttpxScanner
                httpx_scanner = HttpxScanner()

                # Configure httpx based on scan type
                httpx_config = {
                    'quick': {
                        'ports': [80, 443],
                        'timeout': 5,
                        'threads': 100,
                        'tech_detect': False,
                        'follow_redirects': False
                    },
                    'deep': {
                        'ports': [80, 443, 8080, 8443, 8000, 3000],
                        'timeout': 10,
                        'threads': 50,
                        'tech_detect': True,
                        'follow_redirects': True
                    },
                    'full': {
                        'ports': [80, 443, 8080, 8443, 8000, 3000, 9000, 9090],
                        'timeout': 15,
                        'threads': 30,
                        'tech_detect': True,
                        'follow_redirects': True
                    }
                }

                http_config = httpx_config.get(scan_type, httpx_config['deep'])

                # Perform HTTP probing
                probe_results = httpx_scanner.scan(hostnames, **http_config)
                alive_hosts_data = probe_results.get('alive_hosts', [])

                # Extract alive hostnames and build HTTP data
                for host in alive_hosts_data:
                    # httpx returns the original hostname in 'input' field and resolved IP in 'host'
                    original_hostname = host.get('input', host.get('url', ''))
                    resolved_ip = host.get('host', '')

                    # Clean the hostname from URL format if needed
                    if '://' in original_hostname:
                        original_hostname = original_hostname.split('://', 1)[1].split('/', 1)[0].split(':', 1)[0]

                    # Use the original hostname as the key for consistency with asset storage
                    if original_hostname:
                        alive_hosts.append(resolved_ip)  # Keep IPs for port scanning

                        # Store HTTP data using hostname as key (matches asset storage)
                        http_data[original_hostname] = {
                            'url': host.get('url', ''),
                            'status_code': host.get('status_code', 0),
                            'title': host.get('title', ''),
                            'tech': host.get('tech', []),
                            'webserver': host.get('webserver', ''),
                            'content_length': host.get('content_length', 0),
                            'response_time': host.get('response_time', ''),
                            'scheme': host.get('scheme', 'http'),
                            'port': host.get('port', 80),
                            'resolved_ip': resolved_ip  # Store the resolved IP for reference
                        }

                        logger.debug(f"✅ HTTP probe data stored for {original_hostname}: status {host.get('status_code', 'N/A')}")

            except Exception as e:
                logger.error(f"❌ HTTP probing failed: {str(e)}")

        logger.info(f"🌐 HTTP probing completed: {len(alive_hosts)} alive hosts found")

        # Stage 3: Port Scanning (BEFORE storing subdomains)
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'port_scanning',
                'domain': domain,
                'progress': 70,
                'message': f'Port scanning {len(alive_hosts)} alive hosts...',
                'current_phase': 'Nmap port scanning',
                'subdomains_found': len(subdomains),
                'alive_hosts_found': len(alive_hosts)
            }
        )

        port_results = {}
        if alive_hosts:
            logger.info(f"🔍 Starting port scanning for {len(alive_hosts)} alive hosts")

            try:
                # Import nmap scanner
                from tools.nmap import NmapScanner
                nmap_scanner = NmapScanner()

                # Configure nmap based on scan type
                nmap_config = {
                    'quick': {
                        'ports': '80,443,22,21,25,53,110,143,993,995',
                        'timing': 'T4'
                    },
                    'deep': {
                        'ports': '1-1000',
                        'timing': 'T3',
                        'version_detection': True
                    },
                    'full': {
                        'ports': '1-65535',
                        'timing': 'T3',
                        'version_detection': True
                    }
                }

                port_config = nmap_config.get(scan_type, nmap_config['deep'])

                # Filter and validate hostnames before scanning
                valid_hosts = []
                for host in alive_hosts:
                    # Clean and validate hostname
                    clean_host = str(host).strip()
                    if clean_host and '.' in clean_host and not clean_host.startswith('.') and not clean_host.endswith('.'):
                        # Basic hostname validation
                        if len(clean_host) > 3 and not clean_host.isspace():
                            valid_hosts.append(clean_host)
                        else:
                            logger.warning(f"⚠️ Skipping invalid hostname: '{clean_host}'")
                    else:
                        logger.warning(f"⚠️ Skipping malformed hostname: '{clean_host}'")

                logger.info(f"🔍 Validated {len(valid_hosts)} hosts for port scanning (filtered from {len(alive_hosts)})")

                if valid_hosts:
                    # Create IP to hostname mapping for port results
                    ip_to_hostname = {}
                    for hostname, http_info in http_data.items():
                        resolved_ip = http_info.get('resolved_ip', '')
                        if resolved_ip:
                            ip_to_hostname[resolved_ip] = hostname

                    # Perform batch port scanning for efficiency
                    try:
                        batch_results = nmap_scanner.scan(valid_hosts, **port_config)
                        if batch_results.get('open_ports'):
                            # Group results by hostname (not IP)
                            for port_info in batch_results['open_ports']:
                                host_ip = port_info.get('host', '')
                                if host_ip:
                                    # Map IP back to hostname for consistent storage
                                    hostname = ip_to_hostname.get(host_ip, host_ip)

                                    if hostname not in port_results:
                                        port_results[hostname] = []
                                    port_results[hostname].append(port_info)

                                    logger.debug(f"✅ Port scan result for {hostname} ({host_ip}): port {port_info.get('port', 'N/A')}")

                        logger.info(f"✅ Batch port scan completed: {len(port_results)} hosts with open ports")

                    except Exception as batch_error:
                        logger.warning(f"⚠️ Batch scanning failed, falling back to individual scans: {str(batch_error)}")

                        # Fallback to individual host scanning
                        for host_ip in valid_hosts:
                            try:
                                host_results = nmap_scanner.scan([host_ip], **port_config)
                                if host_results.get('open_ports'):
                                    # Map IP back to hostname for consistent storage
                                    hostname = ip_to_hostname.get(host_ip, host_ip)
                                    port_results[hostname] = host_results['open_ports']
                                    logger.debug(f"✅ Individual scan completed for {hostname} ({host_ip})")
                            except Exception as e:
                                logger.warning(f"Port scan failed for {host_ip}: {str(e)}")
                                continue
                else:
                    logger.warning("⚠️ No valid hosts found for port scanning")

            except Exception as e:
                logger.error(f"❌ Port scanning failed: {str(e)}")

            logger.info(f"🔍 Port scanning completed: {len(port_results)} hosts with open ports")

        logger.info(f"🎯 Scan workflow completed: {len(subdomains)} subdomains, {len(alive_hosts)} alive hosts")

        # Stage 4: Final Database Storage (WITH complete HTTP and port data)
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'database_storage',
                'domain': domain,
                'progress': 90,
                'message': f'Storing {len(subdomains)} subdomains with complete metadata in database...',
                'current_phase': 'Database storage with HTTP and port data',
                'subdomains_found': len(subdomains),
                'alive_hosts_found': len(alive_hosts)
            }
        )

        stored_count = 0

        # Import database models
        from models import Asset, AssetType
        from app import db

        for subdomain in subdomains:
            try:
                if isinstance(subdomain, dict):
                    hostname = subdomain.get('host', '')
                    source = subdomain.get('source', 'subfinder')
                    ip = subdomain.get('ip', '')
                    timestamp = subdomain.get('timestamp', '')
                else:
                    hostname = str(subdomain)
                    source = 'subfinder'
                    ip = ''
                    timestamp = ''

                if not hostname:
                    continue

                # Check if subdomain already exists
                existing_asset = Asset.query.filter_by(
                    name=hostname,
                    organization_id=organization_id
                ).first()

                if not existing_asset:
                    # Get HTTP probe data for this hostname
                    http_probe_data = http_data.get(hostname, {})

                    # Get port scan data for this hostname
                    port_scan_data = port_results.get(hostname, [])

                    # Format port data for frontend display
                    ports_formatted = []
                    if isinstance(port_scan_data, list):
                        for port_info in port_scan_data:
                            if isinstance(port_info, dict):
                                ports_formatted.append({
                                    'port': port_info.get('port', ''),
                                    'service': port_info.get('service', ''),
                                    'protocol': port_info.get('protocol', 'tcp'),
                                    'state': port_info.get('state', 'open')
                                })

                    asset_metadata = {
                        'discovery_method': 'subfinder',
                        'parent_domain': domain,
                        'scan_type': scan_type,
                        'source': source,
                        'discovered_ip': ip,
                        'discovery_timestamp': timestamp or datetime.now().isoformat(),
                        'http_probe': http_probe_data,  # ✅ Store HTTP probe data
                        'ports': ports_formatted,       # ✅ Store port scan data
                        'scan_source': 'large_scale_orchestrator'
                    }

                    asset = Asset(
                        name=hostname,
                        asset_type=AssetType.SUBDOMAIN,
                        organization_id=organization_id,
                        discovered_at=datetime.now(),
                        is_active=True,
                        asset_metadata=asset_metadata
                    )
                    db.session.add(asset)
                    stored_count += 1
                    logger.debug(f"✅ Added new subdomain: {hostname} with HTTP status: {http_probe_data.get('status_code', 'N/A')} and {len(ports_formatted)} ports")
                else:
                    # Update existing asset with new HTTP and port data
                    http_probe_data = http_data.get(hostname, {})
                    port_scan_data = port_results.get(hostname, [])

                    # Format port data for frontend display
                    ports_formatted = []
                    if isinstance(port_scan_data, list):
                        for port_info in port_scan_data:
                            if isinstance(port_info, dict):
                                ports_formatted.append({
                                    'port': port_info.get('port', ''),
                                    'service': port_info.get('service', ''),
                                    'protocol': port_info.get('protocol', 'tcp'),
                                    'state': port_info.get('state', 'open')
                                })

                    # Update existing metadata
                    existing_metadata = existing_asset.asset_metadata or {}
                    existing_metadata.update({
                        'http_probe': http_probe_data,  # ✅ Update HTTP probe data
                        'ports': ports_formatted,       # ✅ Update port scan data
                        'last_large_scale_scan': datetime.now().isoformat(),
                        'scan_source': 'large_scale_orchestrator'
                    })
                    existing_asset.asset_metadata = existing_metadata
                    existing_asset.last_scanned = datetime.now()

                    logger.debug(f"✅ Updated existing subdomain: {hostname} with HTTP status: {http_probe_data.get('status_code', 'N/A')} and {len(ports_formatted)} ports")

            except Exception as e:
                logger.warning(f"Failed to store subdomain {subdomain}: {str(e)}")
                continue

        db.session.commit()
        logger.info(f"📊 Stored {stored_count} new subdomains in database")

        # Stage 5: Final Processing and Storage
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'finalizing',
                'domain': domain,
                'progress': 90,
                'message': 'Finalizing scan results and storing data...',
                'current_phase': 'Data storage and cleanup',
                'subdomains_found': len(subdomains),
                'alive_hosts_found': len(alive_hosts)
            }
        )

        # Store main domain asset if it doesn't exist
        try:
            # Import database models (already imported above, but ensuring availability)
            main_domain_asset = Asset.query.filter_by(
                name=domain,
                organization_id=organization_id
            ).first()

            # Get HTTP probe data for the main domain
            domain_http_data = http_data.get(domain, {})

            # Get port scan data for the main domain
            domain_port_data = port_results.get(domain, [])

            # Format port data for frontend display
            domain_ports_formatted = []
            if isinstance(domain_port_data, list):
                for port_info in domain_port_data:
                    if isinstance(port_info, dict):
                        domain_ports_formatted.append({
                            'port': port_info.get('port', ''),
                            'service': port_info.get('service', ''),
                            'protocol': port_info.get('protocol', 'tcp'),
                            'state': port_info.get('state', 'open')
                        })

            if not main_domain_asset:
                main_domain_asset = Asset(
                    name=domain,
                    asset_type=AssetType.DOMAIN,
                    description=f"Main domain discovered during large-scale scan",
                    organization_id=organization_id,
                    discovered_at=datetime.now(),
                    last_scanned=datetime.now(),
                    asset_metadata={
                        'scan_source': 'large_scale_orchestrator',
                        'scan_type': scan_type,
                        'subdomains_found': len(subdomains),
                        'alive_hosts_found': len(alive_hosts),
                        'http_probe': domain_http_data,      # ✅ Store HTTP probe data
                        'ports': domain_ports_formatted      # ✅ Store port scan data
                    }
                )
                db.session.add(main_domain_asset)
                logger.debug(f"✅ Added main domain: {domain} with HTTP status: {domain_http_data.get('status_code', 'N/A')} and {len(domain_ports_formatted)} ports")
            else:
                # Update existing asset
                main_domain_asset.last_scanned = datetime.now()
                existing_metadata = main_domain_asset.asset_metadata or {}
                existing_metadata.update({
                    'scan_source': 'large_scale_orchestrator',
                    'scan_type': scan_type,
                    'subdomains_found': len(subdomains),
                    'alive_hosts_found': len(alive_hosts),
                    'last_large_scale_scan': datetime.now().isoformat(),
                    'http_probe': domain_http_data,      # ✅ Update HTTP probe data
                    'ports': domain_ports_formatted      # ✅ Update port scan data
                })
                main_domain_asset.asset_metadata = existing_metadata
                logger.debug(f"✅ Updated main domain: {domain} with HTTP status: {domain_http_data.get('status_code', 'N/A')} and {len(domain_ports_formatted)} ports")

            db.session.commit()
            logger.info(f"📊 Updated main domain asset for {domain}")

        except Exception as storage_error:
            logger.warning(f"⚠️ Failed to update main domain asset: {str(storage_error)}")
            db.session.rollback()

        # Final completion
        self.update_state(
            state='SUCCESS',
            meta={
                'stage': 'completed',
                'domain': domain,
                'progress': 100,
                'message': f'Large-scale scan completed successfully! Found {len(subdomains)} subdomains, {len(alive_hosts)} alive hosts.',
                'current_phase': 'Completed',
                'subdomains_found': len(subdomains),
                'alive_hosts_found': len(alive_hosts),
                'completed_at': datetime.now().isoformat()
            }
        )

        logger.info(f"🎉 Large-scale scan orchestration completed for {domain}")

        return {
            'success': True,
            'domain': domain,
            'scan_type': scan_type,
            'subdomains_found': len(subdomains),
            'alive_hosts_found': len(alive_hosts),
            'subdomains': subdomains,
            'alive_hosts': alive_hosts,
            'http_data': http_data,
            'port_results': port_results,
            'stage': 'completed',
            'progress': 100,
            'message': f'Large-scale scan completed successfully! Found {len(subdomains)} subdomains, {len(alive_hosts)} alive hosts.',
            'completed_at': datetime.now().isoformat()
        }

    except Exception as e:
        import traceback
        error_message = str(e)
        error_traceback = traceback.format_exc()

        logger.error(f"❌ Large-scale scan orchestration failed for {domain}: {error_message}")
        logger.error(f"❌ Traceback: {error_traceback}")

        # Update state with proper error handling
        try:
            self.update_state(
                state='FAILURE',
                meta={
                    'domain': domain,
                    'error': error_message,
                    'stage': 'failed',
                    'progress': 0,
                    'failed_at': datetime.now().isoformat()
                }
            )
        except Exception as state_error:
            logger.error(f"❌ Failed to update task state: {str(state_error)}")

        # Don't retry on certain types of errors to avoid infinite loops
        if "organization" in error_message.lower() or "database" in error_message.lower():
            logger.warning(f"⚠️ Not retrying task due to configuration/database error")
            return {
                'success': False,
                'error': error_message,
                'domain': domain,
                'scan_type': scan_type,
                'retry': False
            }

        # Retry with exponential backoff for other errors
        try:
            self.retry(countdown=300, max_retries=2)
        except Exception as retry_error:
            logger.error(f"❌ Failed to retry task: {str(retry_error)}")

        return {
            'success': False,
            'error': error_message,
            'domain': domain,
            'scan_type': scan_type,
            'retry': True
        }

# Helper functions removed - all functionality is now inline in the orchestrator task

# ============================================================================
# INDIVIDUAL SCANNING TASKS (Optimized for Large Domains)
# ============================================================================

@celery.task(bind=True, name='tasks.subdomain_discovery_task')
def subdomain_discovery_task(self, domain: str, organization_id: int, scan_type: str = 'deep'):
    """
    Dedicated task for subdomain discovery using Subfinder
    Optimized for large domains that may have hundreds/thousands of subdomains

    Args:
        domain (str): Target domain
        organization_id (int): Organization ID
        scan_type (str): Scan intensity (quick, deep, full)

    Returns:
        dict: Subdomain discovery results
    """
    try:
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'subfinder_scanning',
                'domain': domain,
                'progress': 0,
                'message': f'Starting Subfinder scan for {domain}...'
            }
        )

        logger.info(f"🔍 Starting Subfinder subdomain discovery for: {domain}")

        # Import scanning service
        from services.real_scanning_service import RealScanningService
        scanning_service = RealScanningService()

        # Configure Subfinder based on scan type
        subfinder_config = {
            'quick': {
                'silent': True,
                'max_time': 60,  # 1 minute for quick scans
                'recursive': False
            },
            'deep': {
                'silent': True,
                'max_time': 300,  # 5 minutes for deep scans
                'recursive': True
            },
            'full': {
                'silent': True,
                'max_time': 600,  # 10 minutes for full scans
                'recursive': True,
                'all_sources': True
            }
        }

        config = subfinder_config.get(scan_type, subfinder_config['deep'])

        # Update progress
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'subfinder_scanning',
                'domain': domain,
                'progress': 25,
                'message': f'Running Subfinder with {scan_type} configuration...',
                'config': config
            }
        )

        # Perform subdomain discovery
        scan_results = scanning_service.scanner_manager.subdomain_scan_only(domain, **config)
        subdomains = scan_results.get('subdomains', [])

        logger.info(f"✅ Subfinder completed for {domain}: {len(subdomains)} subdomains discovered")

        # Store subdomains in database
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'storing_subdomains',
                'domain': domain,
                'progress': 75,
                'message': f'Storing {len(subdomains)} subdomains in database...',
                'subdomains_found': len(subdomains)
            }
        )

        # Store discovered subdomains as assets
        stored_count = 0
        for subdomain in subdomains:
            try:
                # Extract hostname from subdomain data
                if isinstance(subdomain, dict):
                    hostname = subdomain.get('host', '')
                    source = subdomain.get('source', 'subfinder')
                    ip = subdomain.get('ip', '')
                    timestamp = subdomain.get('timestamp', '')
                else:
                    # Handle string format (fallback)
                    hostname = str(subdomain)
                    source = 'subfinder'
                    ip = ''
                    timestamp = ''

                if not hostname:
                    logger.warning(f"Skipping subdomain with empty hostname: {subdomain}")
                    continue

                # Check if subdomain already exists
                existing_asset = Asset.query.filter_by(
                    name=hostname,
                    organization_id=organization_id
                ).first()

                if not existing_asset:
                    # Create asset metadata with discovery details
                    asset_metadata = {
                        'discovery_method': 'subfinder',
                        'parent_domain': domain,
                        'scan_type': scan_type,
                        'source': source,
                        'discovered_ip': ip,
                        'discovery_timestamp': timestamp or datetime.now().isoformat()
                    }

                    asset = Asset(
                        name=hostname,
                        asset_type=AssetType.SUBDOMAIN,
                        organization_id=organization_id,
                        discovered_at=datetime.now(),
                        is_active=True,
                        asset_metadata=asset_metadata
                    )
                    db.session.add(asset)
                    stored_count += 1
                    logger.debug(f"✅ Added new subdomain: {hostname}")
                else:
                    logger.debug(f"⚠️ Subdomain already exists: {hostname}")

            except Exception as e:
                logger.warning(f"Failed to store subdomain {subdomain}: {str(e)}")
                continue

        db.session.commit()
        logger.info(f"📊 Stored {stored_count} new subdomains in database")

        return {
            'success': True,
            'domain': domain,
            'subdomains': subdomains,
            'subdomains_count': len(subdomains),
            'stored_count': stored_count,
            'scan_type': scan_type,
            'config_used': config,
            'stage': 'complete'
        }

    except Exception as e:
        import traceback
        error_message = str(e)
        error_traceback = traceback.format_exc()

        logger.error(f"❌ Subdomain discovery failed for {domain}: {error_message}")
        logger.error(f"❌ Traceback: {error_traceback}")

        # Update state with proper error handling
        try:
            self.update_state(
                state='FAILURE',
                meta={
                    'domain': domain,
                    'error': error_message,
                    'stage': 'failed',
                    'failed_at': datetime.now().isoformat()
                }
            )
        except Exception as state_error:
            logger.error(f"❌ Failed to update subdomain discovery task state: {str(state_error)}")

        # Retry with proper error handling
        try:
            self.retry(countdown=120, max_retries=2)
        except Exception as retry_error:
            logger.error(f"❌ Failed to retry subdomain discovery task: {str(retry_error)}")

        return {
            'success': False,
            'error': error_message,
            'domain': domain,
            'scan_type': scan_type
        }

@celery.task(bind=True, name='tasks.http_probe_task')
def http_probe_task(self, subdomains: List[str], scan_type: str = 'deep'):
    """
    Dedicated task for HTTP probing using httpx
    Processes subdomains in batches to handle large lists efficiently

    Args:
        subdomains (List[str]): List of subdomains to probe
        scan_type (str): Scan intensity

    Returns:
        dict: HTTP probe results
    """
    try:
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'http_probing',
                'subdomains_count': len(subdomains),
                'progress': 0,
                'message': f'Starting HTTP probing for {len(subdomains)} subdomains...'
            }
        )

        logger.info(f"🌐 Starting HTTP probing for {len(subdomains)} subdomains")

        # Import httpx scanner
        from tools.httpx import HttpxScanner
        httpx_scanner = HttpxScanner()

        # Configure httpx based on scan type
        httpx_config = {
            'quick': {
                'ports': [80, 443],
                'timeout': 5,
                'threads': 100,
                'tech_detect': False,
                'follow_redirects': False
            },
            'deep': {
                'ports': [80, 443, 8080, 8443, 8000, 3000],
                'timeout': 10,
                'threads': 50,
                'tech_detect': True,
                'follow_redirects': True
            },
            'full': {
                'ports': [80, 443, 8080, 8443, 8000, 3000, 9000, 9090],
                'timeout': 15,
                'threads': 30,
                'tech_detect': True,
                'follow_redirects': True
            }
        }

        config = httpx_config.get(scan_type, httpx_config['deep'])

        # Update progress
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'http_probing',
                'subdomains_count': len(subdomains),
                'progress': 25,
                'message': f'Probing with httpx using {scan_type} configuration...',
                'config': config
            }
        )

        # Perform HTTP probing
        probe_results = httpx_scanner.scan(subdomains, **config)
        alive_hosts = probe_results.get('alive_hosts', [])

        logger.info(f"✅ HTTP probing completed: {len(alive_hosts)} alive hosts found")

        # Process results for storage
        http_data = {}
        for host in alive_hosts:
            hostname = host.get('host', '')
            if hostname:
                http_data[hostname] = {
                    'url': host.get('url', ''),
                    'status_code': host.get('status_code', 0),
                    'title': host.get('title', ''),
                    'tech': host.get('tech', []),
                    'webserver': host.get('webserver', ''),
                    'content_length': host.get('content_length', 0),
                    'response_time': host.get('response_time', ''),
                    'scheme': host.get('scheme', 'http'),
                    'port': host.get('port', 80)
                }

        return {
            'success': True,
            'alive_hosts': [host.get('host', '') for host in alive_hosts],
            'alive_hosts_count': len(alive_hosts),
            'http_data': http_data,
            'scan_type': scan_type,
            'config_used': config,
            'raw_results': probe_results,
            'stage': 'complete'
        }

    except Exception as e:
        import traceback
        error_message = str(e)
        error_traceback = traceback.format_exc()

        logger.error(f"❌ HTTP probing failed: {error_message}")
        logger.error(f"❌ Traceback: {error_traceback}")

        # Update state with proper error handling
        try:
            self.update_state(
                state='FAILURE',
                meta={
                    'error': error_message,
                    'stage': 'failed',
                    'failed_at': datetime.now().isoformat()
                }
            )
        except Exception as state_error:
            logger.error(f"❌ Failed to update HTTP probe task state: {str(state_error)}")

        # Retry with proper error handling
        try:
            self.retry(countdown=60, max_retries=2)
        except Exception as retry_error:
            logger.error(f"❌ Failed to retry HTTP probe task: {str(retry_error)}")

        return {
            'success': False,
            'error': error_message,
            'scan_type': scan_type
        }

@celery.task(bind=True, name='tasks.port_scan_task')
def port_scan_task(self, alive_hosts: List[str], scan_type: str = 'deep'):
    """
    Dedicated task for port scanning using Nmap
    Optimized for scanning multiple alive hosts efficiently

    Args:
        alive_hosts (List[str]): List of alive hosts to scan
        scan_type (str): Scan intensity

    Returns:
        dict: Port scan results
    """
    try:
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'port_scanning',
                'hosts_count': len(alive_hosts),
                'progress': 0,
                'message': f'Starting port scanning for {len(alive_hosts)} hosts...'
            }
        )

        logger.info(f"🔍 Starting port scanning for {len(alive_hosts)} alive hosts")

        # Import nmap scanner
        from tools.nmap import NmapScanner
        nmap_scanner = NmapScanner()

        # Configure nmap based on scan type
        nmap_config = {
            'quick': {
                'top_ports': 10,  # Top 10 most critical ports
                'timing': 'T5',   # Insane timing for speed
                'version_detection': False
            },
            'deep': {
                'top_ports': 20,  # Top 20 critical ports
                'timing': 'T4',   # Aggressive timing
                'version_detection': True
            },
            'full': {
                'top_ports': 100,  # Top 100 ports
                'timing': 'T3',    # Normal timing for accuracy
                'version_detection': True,
                'script_scan': True
            }
        }

        config = nmap_config.get(scan_type, nmap_config['deep'])

        # Update progress
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'port_scanning',
                'hosts_count': len(alive_hosts),
                'progress': 25,
                'message': f'Running Nmap with {scan_type} configuration...',
                'config': config
            }
        )

        # Perform port scanning
        port_results = nmap_scanner.scan(alive_hosts, **config)
        open_ports = port_results.get('open_ports', [])

        logger.info(f"✅ Port scanning completed: {len(open_ports)} open ports found")

        return {
            'success': True,
            'open_ports': open_ports,
            'open_ports_count': len(open_ports),
            'scan_type': scan_type,
            'config_used': config,
            'raw_results': port_results,
            'stage': 'complete'
        }

    except Exception as e:
        logger.error(f"❌ Port scanning failed: {str(e)}")
        self.update_state(
            state='FAILURE',
            meta={
                'error': str(e),
                'stage': 'failed'
            }
        )
        self.retry(countdown=120, max_retries=2)
        return {
            'success': False,
            'error': str(e),
            'scan_type': scan_type
        }

@celery.task(bind=True, name='tasks.vulnerability_scan_task')
def vulnerability_scan_task(self, alive_hosts: List[str], scan_type: str = 'deep'):
    """
    Dedicated task for vulnerability scanning using Nuclei
    Optimized for scanning multiple hosts with appropriate templates

    Args:
        alive_hosts (List[str]): List of alive hosts to scan
        scan_type (str): Scan intensity

    Returns:
        dict: Vulnerability scan results
    """
    try:
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'vulnerability_scanning',
                'hosts_count': len(alive_hosts),
                'progress': 0,
                'message': f'Starting vulnerability scanning for {len(alive_hosts)} hosts...'
            }
        )

        logger.info(f"🔍 Starting vulnerability scanning for {len(alive_hosts)} alive hosts")

        # Import nuclei scanner
        from tools.nuclei import NucleiScanner
        nuclei_scanner = NucleiScanner()

        # Configure nuclei based on scan type
        nuclei_config = {
            'quick': {
                'templates': ['http/miscellaneous/'],
                'rate_limit': 500,
                'concurrency': 100,
                'timeout': 60
            },
            'deep': {
                'templates': ['http/', 'network/'],
                'rate_limit': 100,
                'concurrency': 25,
                'timeout': 300
            },
            'full': {
                'templates': ['http/', 'network/', 'ssl/', 'dns/'],
                'rate_limit': 50,
                'concurrency': 15,
                'timeout': 600
            }
        }

        config = nuclei_config.get(scan_type, nuclei_config['deep'])

        # Update progress
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'vulnerability_scanning',
                'hosts_count': len(alive_hosts),
                'progress': 25,
                'message': f'Running Nuclei with {scan_type} configuration...',
                'config': config
            }
        )

        # Perform vulnerability scanning
        vuln_results = nuclei_scanner.scan(alive_hosts, **config)
        vulnerabilities = vuln_results.get('vulnerabilities', [])

        logger.info(f"✅ Vulnerability scanning completed: {len(vulnerabilities)} vulnerabilities found")

        return {
            'success': True,
            'vulnerabilities': vulnerabilities,
            'vulnerabilities_count': len(vulnerabilities),
            'scan_type': scan_type,
            'config_used': config,
            'raw_results': vuln_results,
            'stage': 'complete'
        }

    except Exception as e:
        logger.error(f"❌ Vulnerability scanning failed: {str(e)}")
        self.update_state(
            state='FAILURE',
            meta={
                'error': str(e),
                'stage': 'failed'
            }
        )
        self.retry(countdown=120, max_retries=2)
        return {
            'success': False,
            'error': str(e),
            'scan_type': scan_type
        }

@celery.task(bind=True)
def process_scan_results_task(self, scan_results, organization_id):
    """
    Background task to process and store scan results
    
    Args:
        scan_results (dict): Raw scan results
        organization_id (int): Organization ID
    
    Returns:
        dict: Processing summary
    """
    try:
        logger.info(f"Processing scan results for organization {organization_id}")
        
        # Process and store results
        summary = {
            'assets_created': 0,
            'vulnerabilities_found': 0,
            'alerts_generated': 0
        }
        
        # Store discovered assets
        if 'subdomains' in scan_results:
            for subdomain in scan_results['subdomains']:
                asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    organization_id=organization_id,
                    discovered_at=datetime.utcnow(),
                    is_active=True
                )
                db.session.add(asset)
                summary['assets_created'] += 1
        
        # Store vulnerabilities
        if 'vulnerabilities' in scan_results:
            for vuln_data in scan_results['vulnerabilities']:
                vulnerability = Vulnerability(
                    title=vuln_data.get('title', 'Unknown Vulnerability'),
                    description=vuln_data.get('description', ''),
                    severity=SeverityLevel.MEDIUM,  # Default severity
                    organization_id=organization_id,
                    discovered_at=datetime.utcnow(),
                    is_resolved=False
                )
                db.session.add(vulnerability)
                summary['vulnerabilities_found'] += 1
        
        # Generate alerts for critical findings
        if summary['vulnerabilities_found'] > 0:
            alert = Alert(
                title=f"Scan completed: {summary['vulnerabilities_found']} vulnerabilities found",
                description=f"Scan discovered {summary['assets_created']} assets and {summary['vulnerabilities_found']} vulnerabilities",
                alert_type=AlertType.VULNERABILITY,
                severity=SeverityLevel.INFO,
                organization_id=organization_id,
                created_at=datetime.utcnow(),
                is_resolved=False
            )
            db.session.add(alert)
            summary['alerts_generated'] += 1
        
        # Commit all changes
        db.session.commit()
        
        logger.info(f"Scan results processed: {summary}")
        return summary
        
    except Exception as e:
        logger.error(f"Failed to process scan results: {str(e)}")
        db.session.rollback()
        self.retry(countdown=60, max_retries=3)
        return {
            'success': False,
            'error': str(e)
        }

@celery.task(bind=True)
def cleanup_old_data_task(self, days_old=30):
    """
    Background task to cleanup old scan data
    
    Args:
        days_old (int): Number of days after which data is considered old
    
    Returns:
        dict: Cleanup summary
    """
    try:
        logger.info(f"Starting cleanup of data older than {days_old} days")
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_old)
        
        # Cleanup old resolved vulnerabilities
        old_vulns = Vulnerability.query.filter(
            Vulnerability.is_resolved == True,
            Vulnerability.resolved_at < cutoff_date
        ).count()
        
        Vulnerability.query.filter(
            Vulnerability.is_resolved == True,
            Vulnerability.resolved_at < cutoff_date
        ).delete()
        
        # Cleanup old resolved alerts
        old_alerts = Alert.query.filter(
            Alert.is_resolved == True,
            Alert.resolved_at < cutoff_date
        ).count()
        
        Alert.query.filter(
            Alert.is_resolved == True,
            Alert.resolved_at < cutoff_date
        ).delete()
        
        db.session.commit()
        
        summary = {
            'vulnerabilities_cleaned': old_vulns,
            'alerts_cleaned': old_alerts
        }
        
        logger.info(f"Cleanup completed: {summary}")
        return summary
        
    except Exception as e:
        logger.error(f"Cleanup failed: {str(e)}")
        db.session.rollback()
        return {
            'success': False,
            'error': str(e)
        }

@celery.task(bind=True)
def send_notification_task(self, user_id, message, notification_type='info'):
    """
    Background task to send notifications
    
    Args:
        user_id (int): User ID to send notification to
        message (str): Notification message
        notification_type (str): Type of notification (info, warning, error)
    
    Returns:
        dict: Notification result
    """
    try:
        logger.info(f"Sending {notification_type} notification to user {user_id}: {message}")
        
        # Here you would implement actual notification sending
        # For now, just log the notification
        
        return {
            'success': True,
            'user_id': user_id,
            'message': message,
            'type': notification_type,
            'sent_at': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to send notification: {str(e)}")
        return {
            'success': False,
            'error': str(e)
        }

# Periodic tasks (if using Celery Beat)
@celery.task(bind=True)
def periodic_health_check(self):
    """Periodic health check task"""
    try:
        logger.info("Running periodic health check")
        
        # Check database connectivity
        db.session.execute('SELECT 1')
        
        # Check Redis connectivity
        celery.backend.get('health_check')
        
        return {
            'success': True,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'healthy'
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'unhealthy'
        }

# ============================================================================
# PROGRESSIVE SCANNING ORCHESTRATOR WITH REAL-TIME UPDATES
# ============================================================================

@celery.task(bind=True, name='tasks.progressive_large_domain_scan_orchestrator')
def progressive_large_domain_scan_orchestrator(self, domain, organization_id, scan_type='quick'):
    """
    Progressive large-scale domain scanning orchestrator with real-time updates
    Stores data immediately after each scanning stage for real-time population

    Progressive Workflow:
    1. Subdomain Discovery → Immediate storage with "scanning" status
    2. HTTP Probing → Update assets with HTTP status codes and technologies
    3. Port Scanning → Update assets with port information
    4. Final completion → Mark all assets as "completed"
    """
    logger = logging.getLogger(__name__)

    try:
        logger.info(f"🚀 Starting PROGRESSIVE large-scale scan for {domain} (scan_type: {scan_type})")

        # Initialize scanning service
        from services.real_scanning_service import RealScanningService
        scanning_service = RealScanningService()
        if not scanning_service.is_available():
            raise Exception("Scanning service not available")

        logger.info(f"Initialized scanning service with tools: {scanning_service.get_available_tools()}")

        # Import database models for progressive storage
        from models import Asset, AssetType
        from app import db

        # PROGRESSIVE STAGE 1: Subdomain Discovery with Immediate Storage
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'subdomain_discovery',
                'domain': domain,
                'progress': 10,
                'message': f'Discovering subdomains for {domain}...',
                'current_phase': 'Subfinder scanning',
                'progressive_update': {
                    'type': 'stage_started',
                    'stage': 'subdomain_discovery',
                    'timestamp': datetime.now().isoformat()
                }
            }
        )

        # Configure Subfinder parameters
        subfinder_config = {
            'silent': True,
            'max_time': 60 if scan_type == 'quick' else 300,
            'recursive': scan_type == 'comprehensive'
        }

        # Run Subfinder
        scan_results = scanning_service.scanner_manager.subdomain_scan_only(domain, **subfinder_config)
        subdomains = scan_results.get('subdomains', [])

        # Add the main domain to the subdomain list if not already present
        main_domain_found = False
        for subdomain in subdomains:
            if isinstance(subdomain, dict):
                hostname = subdomain.get('host', '')
            else:
                hostname = str(subdomain)

            if hostname == domain:
                main_domain_found = True
                break

        if not main_domain_found:
            # Add main domain to the list
            main_domain_entry = {
                'host': domain,
                'source': 'main_domain',
                'ip': '',
                'timestamp': datetime.now().isoformat()
            }
            subdomains.append(main_domain_entry)
            logger.info(f"📋 Added main domain {domain} to subdomain list")

        logger.info(f"🔍 SUBFINDER: Scan completed, found {len(subdomains)} subdomains (including main domain)")

        # IMMEDIATE STORAGE: Store subdomains with "scanning" status
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'progressive_storage_subdomains',
                'domain': domain,
                'progress': 25,
                'message': f'Storing {len(subdomains)} discovered subdomains...',
                'current_phase': 'Progressive storage - Subdomains',
                'subdomains_found': len(subdomains),
                'progressive_update': {
                    'type': 'subdomains_discovered',
                    'subdomains': subdomains,
                    'count': len(subdomains),
                    'timestamp': datetime.now().isoformat()
                }
            }
        )

        # Store subdomains immediately with scanning status
        progressive_stored_count = 0
        for subdomain in subdomains:
            try:
                # Extract hostname and metadata
                if isinstance(subdomain, dict):
                    hostname = subdomain.get('host', '')
                    source = subdomain.get('source', 'subfinder')
                    ip = subdomain.get('ip', '')
                    timestamp = subdomain.get('timestamp', '')
                else:
                    hostname = str(subdomain)
                    source = 'subfinder'
                    ip = ''
                    timestamp = ''

                if not hostname:
                    continue

                # Initial asset metadata (scanning status)
                asset_metadata = {
                    'discovery_method': 'subfinder',
                    'parent_domain': domain,
                    'scan_type': scan_type,
                    'source': source,
                    'discovered_ip': ip,
                    'discovery_timestamp': timestamp or datetime.now().isoformat(),
                    'scan_source': 'progressive_large_scale_orchestrator',
                    'scan_status': 'scanning',  # Progressive status indicator
                    'http_probe': {},  # Will be populated later
                    'ports': []        # Will be populated later
                }

                # Check if asset already exists
                existing_asset = Asset.query.filter_by(
                    name=hostname,
                    organization_id=organization_id
                ).first()

                if not existing_asset:
                    # Determine asset type - main domain vs subdomain
                    asset_type = AssetType.DOMAIN if hostname == domain else AssetType.SUBDOMAIN

                    # Create new asset with scanning status
                    asset = Asset(
                        name=hostname,
                        asset_type=asset_type,
                        organization_id=organization_id,
                        discovered_at=datetime.now(),
                        is_active=True,
                        asset_metadata=asset_metadata
                    )
                    db.session.add(asset)
                    progressive_stored_count += 1
                    logger.debug(f"✅ Progressive storage: Added subdomain {hostname} with scanning status")
                else:
                    # Update existing asset with scanning status
                    existing_asset.last_scanned = datetime.now()
                    existing_asset.is_active = True
                    existing_metadata = existing_asset.asset_metadata or {}
                    existing_metadata.update({
                        'scan_status': 'scanning',
                        'scan_source': 'progressive_large_scale_orchestrator',
                        'last_scan_start': datetime.now().isoformat()
                    })
                    existing_asset.asset_metadata = existing_metadata
                    progressive_stored_count += 1
                    logger.debug(f"✅ Progressive storage: Updated subdomain {hostname} with scanning status")

            except Exception as e:
                logger.error(f"❌ Progressive storage failed for subdomain {subdomain}: {str(e)}")
                continue

        # Commit progressive storage
        try:
            db.session.commit()
            logger.info(f"📊 Progressive storage: Stored {progressive_stored_count} subdomains with scanning status")
        except Exception as e:
            logger.error(f"❌ Progressive storage commit failed: {str(e)}")
            db.session.rollback()

        # Send progressive update for subdomains stored
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'subdomains_stored',
                'domain': domain,
                'progress': 30,
                'message': f'Stored {progressive_stored_count} subdomains, starting HTTP probing...',
                'current_phase': 'Subdomains stored - Starting HTTP probing',
                'subdomains_found': len(subdomains),
                'progressive_update': {
                    'type': 'subdomains_stored',
                    'stored_count': progressive_stored_count,
                    'timestamp': datetime.now().isoformat()
                }
            }
        )

        # PROGRESSIVE STAGE 2: HTTP Probing with Progressive Updates
        http_probe_results = {}
        alive_hosts = []

        logger.info(f"🌐 Starting HTTP probing stage with {len(subdomains)} subdomains")

        if subdomains and len(subdomains) > 0:
            self.update_state(
                state='PROGRESS',
                meta={
                    'stage': 'http_probing',
                    'domain': domain,
                    'progress': 40,
                    'message': f'HTTP probing {len(subdomains)} discovered subdomains...',
                    'current_phase': 'httpx HTTP probing',
                    'subdomains_found': len(subdomains),
                    'progressive_update': {
                        'type': 'http_probing_started',
                        'subdomain_count': len(subdomains),
                        'timestamp': datetime.now().isoformat()
                    }
                }
            )

            # Prepare subdomain list for httpx
            subdomain_list = []
            for subdomain in subdomains:
                if isinstance(subdomain, dict):
                    hostname = subdomain.get('host', '')
                else:
                    hostname = str(subdomain)

                if hostname:
                    subdomain_list.append(hostname)

            logger.info(f"🌐 Prepared {len(subdomain_list)} hosts for HTTP probing: {subdomain_list[:5]}{'...' if len(subdomain_list) > 5 else ''}")

            # Run httpx HTTP probing
            try:
                logger.info(f"🌐 HTTPX: Starting HTTP probing for {len(subdomain_list)} subdomains")
                httpx_config = {
                    'timeout': 30 if scan_type == 'quick' else 60,
                    'follow_redirects': True,
                    'tech_detect': True
                }

                http_results = scanning_service.scanner_manager.http_probe_only(subdomain_list, **httpx_config)
                alive_hosts_data = http_results.get('alive_hosts', [])

                # Extract hostnames from URLs instead of using IP addresses
                alive_hosts = []
                for host_data in alive_hosts_data:
                    if host_data.get('status_code'):
                        url = host_data.get('url', '')
                        if url:
                            # Extract hostname from URL
                            url_match = re.search(r'https?://([^:/]+)', url)
                            if url_match:
                                hostname = url_match.group(1)
                                alive_hosts.append(hostname)
                        else:
                            # Fallback to host field if no URL
                            host = host_data.get('host', '')
                            if host:
                                alive_hosts.append(host)

                # Remove duplicates while preserving order
                alive_hosts = list(dict.fromkeys(alive_hosts))

                # Create a dictionary for easier access to HTTP probe data
                # Map both hostnames and URLs to the data for better matching
                http_probe_results = {}
                for host_data in alive_hosts_data:
                    hostname = host_data.get('host', '')
                    url = host_data.get('url', '')

                    if hostname:
                        http_probe_results[hostname] = host_data

                    # Also extract hostname from URL for better matching
                    if url:
                        url_hostname_match = re.search(r'https?://([^:/]+)', url)
                        if url_hostname_match:
                            url_hostname = url_hostname_match.group(1)
                            http_probe_results[url_hostname] = host_data

                logger.info(f"🌐 HTTPX: HTTP probing completed, found {len(alive_hosts)} alive hosts from {len(alive_hosts_data)} responses")

                # Debug: Show what hostnames we have
                stored_assets = Asset.query.filter_by(organization_id=organization_id).filter(
                    Asset.asset_metadata.op('->>')('scan_source') == 'progressive_large_scale_orchestrator'
                ).all()
                stored_hostnames = [asset.name for asset in stored_assets]
                probe_hostnames = list(http_probe_results.keys())

                logger.info(f"🔍 DEBUG: Stored hostnames: {stored_hostnames[:5]}{'...' if len(stored_hostnames) > 5 else ''}")
                logger.info(f"🔍 DEBUG: Probe hostnames: {probe_hostnames[:5]}{'...' if len(probe_hostnames) > 5 else ''}")

                # Update assets with HTTP probe data progressively
                http_updated_count = 0

                # Get all progressive scanning assets for better matching
                all_progressive_assets = Asset.query.filter_by(organization_id=organization_id).filter(
                    Asset.asset_metadata.op('->>')('scan_source') == 'progressive_large_scale_orchestrator'
                ).all()

                for hostname, http_data in http_probe_results.items():
                    try:
                        existing_asset = None
                        matched_hostname = hostname

                        # Try direct hostname match first
                        for asset in all_progressive_assets:
                            if asset.name == hostname:
                                existing_asset = asset
                                matched_hostname = asset.name
                                break

                        # If not found and we have a URL, try to match by URL hostname
                        if not existing_asset and 'url' in http_data:
                            url = http_data['url']
                            url_hostname_match = re.search(r'https?://([^:/]+)', url)
                            if url_hostname_match:
                                url_hostname = url_hostname_match.group(1)
                                for asset in all_progressive_assets:
                                    if asset.name == url_hostname:
                                        existing_asset = asset
                                        matched_hostname = asset.name
                                        break

                        if existing_asset:
                            existing_metadata = existing_asset.asset_metadata or {}
                            existing_metadata = existing_metadata.copy()
                            existing_metadata['http_probe'] = http_data
                            existing_metadata['scan_status'] = 'http_complete'
                            existing_metadata['last_http_probe'] = datetime.now().isoformat()
                            existing_asset.asset_metadata = existing_metadata
                            http_updated_count += 1
                            logger.debug(f"✅ Updated {matched_hostname} with HTTP data: {http_data.get('status_code', 'N/A')}")
                        else:
                            logger.warning(f"⚠️ Asset not found for HTTP update: {hostname}")

                    except Exception as e:
                        logger.error(f"❌ HTTP probe update failed for {hostname}: {str(e)}")
                        continue

                # Commit HTTP probe updates
                try:
                    db.session.commit()
                    logger.info(f"📊 Progressive HTTP probing: Updated {http_updated_count} assets with HTTP data")
                except Exception as e:
                    logger.error(f"❌ HTTP probe commit failed: {str(e)}")
                    db.session.rollback()

                # Send progressive update for HTTP probing
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'stage': 'http_probing_complete',
                        'domain': domain,
                        'progress': 60,
                        'message': f'HTTP probing completed, found {len(alive_hosts)} alive hosts, starting port scanning...',
                        'current_phase': 'HTTP probing complete - Starting port scanning',
                        'subdomains_found': len(subdomains),
                        'alive_hosts_found': len(alive_hosts),
                        'progressive_update': {
                            'type': 'http_probing_complete',
                            'alive_hosts': len(alive_hosts),
                            'http_updated': http_updated_count,
                            'timestamp': datetime.now().isoformat()
                        }
                    }
                )

            except Exception as e:
                logger.error(f"❌ HTTP probing failed: {str(e)}")
                logger.exception("HTTP probing exception details:")
                # Continue with port scanning even if HTTP probing fails
                alive_hosts = subdomain_list  # Use all subdomains for port scanning
        else:
            logger.warning(f"⚠️ Skipping HTTP probing - no subdomains found (subdomains: {len(subdomains)})")

        # PROGRESSIVE STAGE 3: Port Scanning with Progressive Updates
        port_scan_results = {}

        logger.info(f"🔍 Starting port scanning stage with {len(alive_hosts)} alive hosts")

        if alive_hosts and len(alive_hosts) > 0:
            self.update_state(
                state='PROGRESS',
                meta={
                    'stage': 'port_scanning',
                    'domain': domain,
                    'progress': 70,
                    'message': f'Port scanning {len(alive_hosts)} alive hosts...',
                    'current_phase': 'Nmap port scanning',
                    'subdomains_found': len(subdomains),
                    'alive_hosts_found': len(alive_hosts),
                    'progressive_update': {
                        'type': 'port_scanning_started',
                        'alive_hosts_count': len(alive_hosts),
                        'timestamp': datetime.now().isoformat()
                    }
                }
            )

            # Run Nmap port scanning on alive hosts
            try:
                logger.info(f"🔍 NMAP: Starting port scanning for {len(alive_hosts)} alive hosts")

                # Configure Nmap for progressive scanning
                nmap_config = {
                    'top_ports': 100 if scan_type == 'quick' else 1000,
                    'timeout': 300 if scan_type == 'quick' else 600,
                    'service_detection': True
                }

                port_results = scanning_service.scanner_manager.port_scan_only(alive_hosts, **nmap_config)
                open_ports_data = port_results.get('open_ports', [])

                logger.info(f"🔍 NMAP: Port scanning completed, found {len(open_ports_data)} open ports")

                # Group port data by hostname for easier processing
                # Also create a mapping from IP addresses back to original hostnames
                ip_to_hostname_map = {}
                for host_data in alive_hosts_data:
                    hostname_from_url = None
                    if 'url' in host_data:
                        url_match = re.search(r'https?://([^:/]+)', host_data['url'])
                        if url_match:
                            hostname_from_url = url_match.group(1)

                    host_ip = host_data.get('host', '')
                    if host_ip and hostname_from_url:
                        ip_to_hostname_map[host_ip] = hostname_from_url

                port_scan_results = {}
                for port_info in open_ports_data:
                    ip_address = port_info.get('host', '')
                    if ip_address:
                        # Try to map IP back to hostname
                        hostname = ip_to_hostname_map.get(ip_address, ip_address)

                        if hostname not in port_scan_results:
                            port_scan_results[hostname] = []
                        port_scan_results[hostname].append(port_info)

                # Debug: Show what hostnames we have for port scanning
                port_hostnames = list(port_scan_results.keys())
                logger.info(f"🔍 DEBUG: Port scan hostnames: {port_hostnames[:5]}{'...' if len(port_hostnames) > 5 else ''}")

                # Update assets with port scan data progressively
                port_updated_count = 0

                # Get all progressive scanning assets for better matching
                all_progressive_assets = Asset.query.filter_by(organization_id=organization_id).filter(
                    Asset.asset_metadata.op('->>')('scan_source') == 'progressive_large_scale_orchestrator'
                ).all()

                for hostname, port_data in port_scan_results.items():
                    try:
                        existing_asset = None
                        matched_hostname = hostname

                        # Try direct hostname match first
                        for asset in all_progressive_assets:
                            if asset.name == hostname:
                                existing_asset = asset
                                matched_hostname = asset.name
                                break

                        if existing_asset:
                            existing_metadata = existing_asset.asset_metadata or {}
                            existing_metadata = existing_metadata.copy()
                            existing_metadata['ports'] = port_data  # port_data is already a list of port info
                            existing_metadata['scan_status'] = 'port_complete'
                            existing_metadata['last_port_scan'] = datetime.now().isoformat()
                            existing_asset.asset_metadata = existing_metadata
                            port_updated_count += 1
                            logger.debug(f"✅ Updated {matched_hostname} with {len(port_data)} ports")
                        else:
                            logger.warning(f"⚠️ Asset not found for port update: {hostname}")

                    except Exception as e:
                        logger.error(f"❌ Port scan update failed for {hostname}: {str(e)}")
                        continue

                # Commit port scan updates
                try:
                    db.session.commit()
                    logger.info(f"📊 Progressive port scanning: Updated {port_updated_count} assets with port data")
                except Exception as e:
                    logger.error(f"❌ Port scan commit failed: {str(e)}")
                    db.session.rollback()

                # Send progressive update for port scanning
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'stage': 'port_scanning_complete',
                        'domain': domain,
                        'progress': 90,
                        'message': f'Port scanning completed, finalizing results...',
                        'current_phase': 'Port scanning complete - Finalizing',
                        'subdomains_found': len(subdomains),
                        'alive_hosts_found': len(alive_hosts),
                        'port_scan_results': len(port_scan_results),
                        'progressive_update': {
                            'type': 'port_scanning_complete',
                            'port_updated': port_updated_count,
                            'timestamp': datetime.now().isoformat()
                        }
                    }
                )

            except Exception as e:
                logger.error(f"❌ Port scanning failed: {str(e)}")
                logger.exception("Port scanning exception details:")
        else:
            logger.warning(f"⚠️ Skipping port scanning - no alive hosts found (alive_hosts: {len(alive_hosts)})")

        # PROGRESSIVE STAGE 4: Launch Asynchronous Nuclei Scan for Main Domain Only
        vulnerability_results = []
        vulnerabilities_stored_count = 0
        nuclei_task_id = None

        # Launch comprehensive Nuclei scan for main domain only (asynchronous)
        try:
            self.update_state(
                state='PROGRESS',
                meta={
                    'stage': 'launching_nuclei_scan',
                    'domain': domain,
                    'progress': 75,
                    'message': f'Launching comprehensive vulnerability scan for main domain: {domain}',
                    'current_phase': 'Starting asynchronous Nuclei scan',
                    'subdomains_found': len(subdomains),
                    'alive_hosts_found': len(alive_hosts),
                    'progressive_update': {
                        'type': 'nuclei_scan_launched',
                        'main_domain': domain,
                        'timestamp': datetime.now().isoformat()
                    }
                }
            )

            # Launch asynchronous comprehensive Nuclei scan for main domain
            nuclei_task = comprehensive_nuclei_scan_task.delay(domain, organization_id, scan_type)
            nuclei_task_id = nuclei_task.id

            logger.info(f"🚀 PROGRESSIVE: Launched asynchronous Nuclei scan for {domain} (Task ID: {nuclei_task_id})")

            # Continue with immediate completion of other assets
            self.update_state(
                state='PROGRESS',
                meta={
                    'stage': 'nuclei_launched_continuing',
                    'domain': domain,
                    'progress': 80,
                    'message': f'Nuclei scan launched for {domain}, completing other assets...',
                    'current_phase': 'Parallel processing - Nuclei running in background',
                    'subdomains_found': len(subdomains),
                    'alive_hosts_found': len(alive_hosts),
                    'nuclei_task_id': nuclei_task_id,
                    'progressive_update': {
                        'type': 'parallel_processing_active',
                        'nuclei_task_id': nuclei_task_id,
                        'timestamp': datetime.now().isoformat()
                    }
                }
            )

        except Exception as e:
            logger.error(f"❌ Failed to launch Nuclei scan: {str(e)}")
            logger.info("🔄 Continuing with asset completion without Nuclei scan")

        # PROGRESSIVE STAGE 5: Final Completion (Parallel Processing)
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'finalizing',
                'domain': domain,
                'progress': 95,
                'message': f'Completing asset discovery (Nuclei scan running in background)...',
                'current_phase': 'Finalizing progressive scan - Parallel Nuclei processing',
                'subdomains_found': len(subdomains),
                'alive_hosts_found': len(alive_hosts),
                'nuclei_task_id': nuclei_task_id,
                'nuclei_status': 'running_async' if nuclei_task_id else 'not_launched',
                'progressive_update': {
                    'type': 'finalizing_with_parallel_nuclei',
                    'nuclei_task_id': nuclei_task_id,
                    'timestamp': datetime.now().isoformat()
                }
            }
        )

        # Mark non-main-domain assets as completed, leave main domain for Nuclei
        try:
            # Get all progressive scanning assets except the main domain
            all_progressive_assets = Asset.query.filter_by(organization_id=organization_id).filter(
                Asset.asset_metadata.op('->>')('scan_source') == 'progressive_large_scale_orchestrator'
            ).filter(
                Asset.asset_metadata.op('->>')('scan_status').in_(['scanning', 'http_complete', 'port_complete'])
            ).all()

            completed_count = 0
            main_domain_asset_updated = False

            for asset in all_progressive_assets:
                if asset.asset_metadata:
                    existing_metadata = asset.asset_metadata.copy()

                    # Check if this is the main domain (strip protocol for comparison)
                    clean_main_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
                    if asset.name == clean_main_domain:
                        # Mark main domain as awaiting Nuclei results
                        existing_metadata['scan_status'] = 'awaiting_nuclei'
                        existing_metadata['nuclei_task_id'] = nuclei_task_id
                        existing_metadata['nuclei_launched_at'] = datetime.now().isoformat()
                        main_domain_asset_updated = True
                        logger.info(f"📊 Main domain {clean_main_domain} marked as awaiting Nuclei results")
                    else:
                        # Mark other assets as completed
                        existing_metadata['scan_status'] = 'completed'
                        existing_metadata['scan_completed_at'] = datetime.now().isoformat()
                        completed_count += 1

                    asset.asset_metadata = existing_metadata
                    asset.last_scanned = datetime.now()

            db.session.commit()
            logger.info(f"📊 Progressive completion: Marked {completed_count} non-main-domain assets as completed")
            if main_domain_asset_updated:
                logger.info(f"📊 Main domain {clean_main_domain} status updated to awaiting Nuclei scan")

        except Exception as e:
            logger.error(f"❌ Progressive completion failed: {str(e)}")
            db.session.rollback()

        # Final success update - Progressive scan completed, Nuclei running async
        self.update_state(
            state='SUCCESS',
            meta={
                'stage': 'completed_with_async_nuclei',
                'domain': domain,
                'progress': 100,
                'message': f'Progressive scanning completed! Nuclei scan running in background for {domain}',
                'current_phase': 'Completed - Nuclei processing main domain asynchronously',
                'subdomains_found': len(subdomains),
                'alive_hosts_found': len(alive_hosts),
                'nuclei_task_id': nuclei_task_id,
                'nuclei_status': 'running_async' if nuclei_task_id else 'not_launched',
                'progressive_update': {
                    'type': 'scan_completed_with_async_nuclei',
                    'nuclei_task_id': nuclei_task_id,
                    'main_domain': domain,
                    'timestamp': datetime.now().isoformat()
                }
            }
        )

        return {
            'success': True,
            'domain': domain,
            'scan_type': scan_type,
            'subdomains_found': len(subdomains),
            'progressive_stored': progressive_stored_count,
            'alive_hosts_found': len(alive_hosts),
            'http_probe_results': len(http_probe_results),
            'port_scan_results': len(port_scan_results),
            'nuclei_task_id': nuclei_task_id,
            'nuclei_status': 'running_async' if nuclei_task_id else 'not_launched',
            'message': 'Progressive scanning completed successfully with asynchronous Nuclei scan for main domain'
        }

    except Exception as e:
        logger.error(f"❌ Progressive large-scale scan failed for {domain}: {str(e)}")
        self.update_state(
            state='FAILURE',
            meta={
                'domain': domain,
                'error': str(e),
                'stage': 'failed',
                'progressive_update': {
                    'type': 'scan_failed',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }
            }
        )
        raise
