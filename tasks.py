#!/usr/bin/env python3
"""
Celery tasks for Attack Surface Discovery SaaS
Background tasks for scanning, processing, and notifications
Optimized for large-scale domain scanning with hundreds/thousands of subdomains
"""

import logging
import json
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

        # Stage 1: Subdomain Discovery
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

        # Stage 4: Store subdomains in database (WITH HTTP and port data)
        self.update_state(
            state='PROGRESS',
            meta={
                'stage': 'database_storage',
                'domain': domain,
                'progress': 90,
                'message': f'Storing {len(subdomains)} subdomains with metadata in database...',
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
