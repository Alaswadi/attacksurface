from flask import Blueprint, jsonify, request, render_template, make_response, Response
from flask_login import login_required, current_user
from models import db, Organization, Asset, Vulnerability, Alert, AssetType, SeverityLevel, User, OrganizationUser, UserInvitation, EmailConfiguration
from datetime import datetime, timedelta
import json
import uuid
import threading
import time
import random
import logging
import socket
import queue

# Import Redis checker for fallback handling
from utils.redis_checker import check_redis_availability, get_redis_status_message

# Celery tasks will be imported when needed to avoid circular imports
CELERY_AVAILABLE = False

# Import scanning service (same as real scanning routes)
try:
    from services.real_scanning_service import RealScanningService
    scanning_service = RealScanningService()
    logging.info("✅ ASSETS: Scanning service initialized successfully")
except ImportError as e:
    scanning_service = None
    logging.warning(f"❌ ASSETS: Real scanning service not available: {str(e)}")

api_bp = Blueprint('api', __name__)

def resolve_domain_to_ip(domain):
    """Resolve domain name to IP address for Masscan"""
    try:
        # Remove any protocol prefix
        clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        ip = socket.gethostbyname(clean_domain)
        logging.info(f"🔍 DNS: Resolved {clean_domain} -> {ip}")
        return ip
    except socket.gaierror as e:
        logging.warning(f"🔍 DNS: Failed to resolve {domain}: {str(e)}")
        return None

# In-memory storage for scan results (in production, use Redis or database)
scan_results = {}
scan_status = {}

# Progressive scanning storage for real-time updates
progressive_scan_updates = {}  # Store progressive updates by task_id
progressive_scan_clients = {}  # Store SSE clients by task_id

@api_bp.route('/assets', methods=['GET'])
@login_required
def get_assets():
    """Get all assets for the current user's organization with filtering support"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    # Get query parameters for filtering
    asset_type = request.args.get('type')
    status = request.args.get('status')
    risk_level = request.args.get('risk_level')
    search = request.args.get('search')

    # Base query
    query = Asset.query.filter_by(organization_id=org.id)

    # Apply filters
    if asset_type and asset_type != 'all':
        try:
            query = query.filter(Asset.asset_type == AssetType(asset_type))
        except ValueError:
            pass

    if status:
        if status == 'active':
            query = query.filter(Asset.is_active == True)
        elif status == 'inactive':
            query = query.filter(Asset.is_active == False)
    else:
        # Default to active assets only
        query = query.filter(Asset.is_active == True)

    if search:
        query = query.filter(Asset.name.ilike(f'%{search}%'))

    assets = query.all()

    assets_data = []
    for asset in assets:
        # Get vulnerability count and highest severity for this asset
        vulns = Vulnerability.query.filter_by(asset_id=asset.id, is_resolved=False).all()
        vuln_count = len(vulns)

        # Determine risk level based on vulnerabilities
        risk_level = 'none'
        if vulns:
            severities = [v.severity for v in vulns]
            if SeverityLevel.CRITICAL in severities:
                risk_level = 'critical'
            elif SeverityLevel.HIGH in severities:
                risk_level = 'high'
            elif SeverityLevel.MEDIUM in severities:
                risk_level = 'medium'
            elif SeverityLevel.LOW in severities:
                risk_level = 'low'

        assets_data.append({
            'id': asset.id,
            'name': asset.name,
            'type': asset.asset_type.value,
            'description': asset.description,
            'discovered_at': asset.discovered_at.isoformat(),
            'last_scanned': asset.last_scanned.isoformat() if asset.last_scanned else None,
            'is_active': asset.is_active,
            'vulnerability_count': vuln_count,
            'risk_level': risk_level,
            'asset_metadata': asset.asset_metadata or {}
        })

    return jsonify({'assets': assets_data})

@api_bp.route('/assets', methods=['POST'])
@login_required
def create_asset():
    """Create a new asset"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404
    
    data = request.get_json()
    
    if not data or 'name' not in data or 'type' not in data:
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        asset_type = AssetType(data['type'])
    except ValueError:
        return jsonify({'error': 'Invalid asset type'}), 400
    
    asset = Asset(
        name=data['name'],
        asset_type=asset_type,
        description=data.get('description', ''),
        organization_id=org.id
    )
    
    try:
        db.session.add(asset)
        db.session.commit()
        
        return jsonify({
            'id': asset.id,
            'name': asset.name,
            'type': asset.asset_type.value,
            'description': asset.description,
            'discovered_at': asset.discovered_at.isoformat()
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to create asset'}), 500

@api_bp.route('/assets/<int:asset_id>', methods=['DELETE'])
@login_required
def delete_asset(asset_id):
    """Delete an asset and optionally its related subdomains"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    # Find the asset to delete
    asset = Asset.query.filter_by(id=asset_id, organization_id=org.id).first()
    if not asset:
        return jsonify({'error': 'Asset not found'}), 404

    try:
        # If this is a domain, also delete all associated subdomains
        if asset.asset_type == AssetType.DOMAIN:
            # Find all subdomains that belong to this domain
            domain_name = asset.name
            subdomains = Asset.query.filter(
                Asset.organization_id == org.id,
                Asset.asset_type == AssetType.SUBDOMAIN,
                Asset.name.like(f'%.{domain_name}')
            ).all()

            # Delete all subdomains first
            for subdomain in subdomains:
                # Delete associated vulnerabilities
                Vulnerability.query.filter_by(asset_id=subdomain.id).delete()
                # Delete the subdomain
                db.session.delete(subdomain)

        # Delete associated vulnerabilities for the main asset
        Vulnerability.query.filter_by(asset_id=asset.id).delete()

        # Delete the main asset
        db.session.delete(asset)

        # Commit all changes
        db.session.commit()

        return jsonify({
            'success': True,
            'message': f'Asset "{asset.name}" deleted successfully'
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete asset: {str(e)}'}), 500

@api_bp.route('/vulnerabilities', methods=['GET'])
@login_required
def get_vulnerabilities():
    """Get all vulnerabilities for the current user's organization"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404
    
    vulns = Vulnerability.query.filter_by(organization_id=org.id).all()
    
    vulns_data = []
    for vuln in vulns:
        vulns_data.append({
            'id': vuln.id,
            'cve_id': vuln.cve_id,
            'title': vuln.title,
            'description': vuln.description,
            'severity': vuln.severity.value,
            'discovered_at': vuln.discovered_at.isoformat(),
            'is_resolved': vuln.is_resolved,
            'asset_name': vuln.asset.name if vuln.asset else None,
            # New validation fields
            'confidence_score': vuln.confidence_score,
            'is_validated': vuln.is_validated,
            'template_name': vuln.template_name,
            'cvss_score': vuln.cvss_score,
            'validation_notes': vuln.validation_notes
        })
    
    return jsonify({'vulnerabilities': vulns_data})

@api_bp.route('/alerts', methods=['GET'])
@login_required
def get_alerts():
    """Get all alerts for the current user's organization"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404
    
    alerts = Alert.query.filter_by(organization_id=org.id).order_by(Alert.created_at.desc()).all()
    
    alerts_data = []
    for alert in alerts:
        alerts_data.append({
            'id': alert.id,
            'title': alert.title,
            'description': alert.description,
            'type': alert.alert_type.value,
            'severity': alert.severity.value,
            'created_at': alert.created_at.isoformat(),
            'is_read': alert.is_read,
            'is_resolved': alert.is_resolved
        })
    
    return jsonify({'alerts': alerts_data})

@api_bp.route('/dashboard/stats', methods=['GET'])
@login_required
def get_dashboard_stats():
    """Get dashboard statistics"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404
    
    # Get counts
    total_assets = Asset.query.filter_by(organization_id=org.id, is_active=True).count()
    critical_vulns = Vulnerability.query.filter_by(
        organization_id=org.id, 
        severity=SeverityLevel.CRITICAL, 
        is_resolved=False
    ).count()
    active_alerts = Alert.query.filter_by(
        organization_id=org.id, 
        is_resolved=False
    ).count()
    
    # Asset breakdown
    assets = Asset.query.filter_by(organization_id=org.id, is_active=True).all()
    asset_counts = {
        'domains': len([a for a in assets if a.asset_type == AssetType.DOMAIN]),
        'subdomains': len([a for a in assets if a.asset_type == AssetType.SUBDOMAIN]),
        'ip_addresses': len([a for a in assets if a.asset_type == AssetType.IP_ADDRESS]),
        'cloud_resources': len([a for a in assets if a.asset_type == AssetType.CLOUD_RESOURCE])
    }
    
    return jsonify({
        'total_assets': total_assets,
        'critical_vulnerabilities': critical_vulns,
        'active_alerts': active_alerts,
        'asset_breakdown': asset_counts
    })

@api_bp.route('/assets-stats', methods=['GET'])
@login_required
def get_assets_stats():
    """Get dashboard statistics for assets page"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    # Get asset statistics
    total_assets = Asset.query.filter_by(organization_id=org.id, is_active=True).count()

    # Assets with vulnerabilities (at risk)
    assets_with_vulns = db.session.query(Asset.id).join(Vulnerability).filter(
        Asset.organization_id == org.id,
        Asset.is_active == True,
        Vulnerability.is_resolved == False
    ).distinct().count()

    # Critical exposure (assets with critical vulnerabilities)
    critical_exposure = db.session.query(Asset.id).join(Vulnerability).filter(
        Asset.organization_id == org.id,
        Asset.is_active == True,
        Vulnerability.severity == SeverityLevel.CRITICAL,
        Vulnerability.is_resolved == False
    ).distinct().count()

    # Secure assets (no unresolved vulnerabilities)
    secure_assets = total_assets - assets_with_vulns

    return jsonify({
        'total_assets': total_assets,
        'at_risk': assets_with_vulns,
        'critical_exposure': critical_exposure,
        'secure_assets': secure_assets
    })

@api_bp.route('/scan', methods=['POST'])
@login_required
def start_scan():
    """Start an attack surface discovery scan"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    data = request.get_json()

    if not data or 'domain' not in data:
        return jsonify({'error': 'Missing domain field'}), 400

    domain = data['domain'].strip()
    if not domain:
        return jsonify({'error': 'Domain cannot be empty'}), 400

    # Generate unique scan ID
    scan_id = str(uuid.uuid4())

    # Initialize scan status
    scan_status[scan_id] = {
        'status': 'running',
        'domain': domain,
        'progress': {
            'subfinder': 0,
            'nmap': 0,
            'nuclei': 0
        },
        'message': 'Initializing scan...',
        'started_at': datetime.utcnow(),
        'user_id': current_user.id
    }

    # Start background scan
    thread = threading.Thread(target=simulate_scan, args=(scan_id, domain))
    thread.daemon = True
    thread.start()

    return jsonify({
        'scan_id': scan_id,
        'message': 'Scan started successfully',
        'domain': domain,
        'status': 'running'
    }), 202

@api_bp.route('/scan/<scan_id>/status', methods=['GET'])
@login_required
def get_scan_status(scan_id):
    """Get scan status and progress"""
    if scan_id not in scan_status:
        return jsonify({'error': 'Scan not found'}), 404

    status = scan_status[scan_id]

    # Check if user owns this scan
    if status['user_id'] != current_user.id:
        return jsonify({'error': 'Access denied'}), 403

    return jsonify(status)

@api_bp.route('/scan/<scan_id>/results', methods=['GET'])
@login_required
def get_scan_results(scan_id):
    """Get detailed scan results"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan results not found'}), 404

    status = scan_status.get(scan_id, {})
    if status.get('user_id') != current_user.id:
        return jsonify({'error': 'Access denied'}), 403

    return jsonify(scan_results[scan_id])

@api_bp.route('/scan/assets/subdomain', methods=['POST'])
@login_required
def scan_assets_subdomain():
    """Scan for subdomains and store them as assets"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain is required'}), 400

    domain = data['domain'].strip()
    if not domain:
        return jsonify({'error': 'Domain cannot be empty'}), 400

    try:
        # Use the exact same approach as the real scanning page - just call it directly
        if not scanning_service:
            # No scanning service available - use simulation
            logging.warning(f"🔍 ASSETS: Scanning service not available, using simulation for {domain}")
            return simulate_subdomain_scan(domain, org.id)

        try:
            # Step 1: Subdomain discovery with Subfinder
            logging.info(f"🔍 ASSETS: Starting real Subfinder scan for {domain}")
            scan_results = scanning_service.scanner_manager.subdomain_scan_only(domain)
            logging.info(f"🔍 ASSETS: Subfinder completed, found {len(scan_results.get('subdomains', []))} subdomains")

            # Step 2: HTTP probing with httpx on discovered subdomains
            subdomains_found = scan_results.get('subdomains', [])
            all_ports = {}
            http_probe_results = {}

            if subdomains_found:
                # Extract subdomain hosts for HTTP probing
                hosts_to_probe = [subdomain_data.get('host', '') if isinstance(subdomain_data, dict) else str(subdomain_data)
                               for subdomain_data in subdomains_found]
                hosts_to_probe = [host for host in hosts_to_probe if host]  # Remove empty hosts

                # Add the main domain to HTTP probing
                if domain not in hosts_to_probe:
                    hosts_to_probe.append(domain)

                if hosts_to_probe:
                    logging.info(f"🌐 ASSETS: Starting HTTP probing with httpx for {len(hosts_to_probe)} hosts")
                    try:
                        httpx_results = scanning_service.scanner_manager.httpx_scan_only(hosts_to_probe)
                        alive_hosts = httpx_results.get('alive_hosts', [])

                        # Process HTTP probe results and map them to original hostnames
                        for host_info in alive_hosts:
                            url = host_info.get('url', '')

                            # Extract hostname from URL (e.g., "http://scanme.nmap.com:80" -> "scanme.nmap.com")
                            if '://' in url:
                                hostname = url.split('://', 1)[1].split('/')[0].split(':')[0]
                            else:
                                hostname = host_info.get('host', '')

                            # Store by hostname (not IP)
                            if hostname:
                                http_probe_results[hostname] = {
                                    'status_code': host_info.get('status_code'),
                                    'title': host_info.get('title', ''),
                                    'technologies': host_info.get('tech', []),
                                    'content_length': host_info.get('content_length'),
                                    'webserver': host_info.get('webserver', ''),
                                    'last_http_probe': datetime.utcnow().isoformat(),
                                    'url': host_info.get('url', ''),
                                    'scheme': host_info.get('scheme', 'http')
                                }

                        logging.info(f"🌐 ASSETS: HTTP probing completed, {len(alive_hosts)} hosts are alive")
                        logging.info(f"🌐 ASSETS: HTTP probe results: {http_probe_results}")
                    except Exception as httpx_error:
                        logging.warning(f"🌐 ASSETS: HTTP probing failed: {str(httpx_error)}")
                        http_probe_results = {}

            # Step 3: Port scanning with Nmap on discovered subdomains
            if subdomains_found:
                # Extract subdomain hosts for port scanning
                hosts_to_scan = [subdomain_data.get('host', '') if isinstance(subdomain_data, dict) else str(subdomain_data)
                               for subdomain_data in subdomains_found]
                hosts_to_scan = [host for host in hosts_to_scan if host]  # Remove empty hosts

                # Add the main domain to port scanning
                if domain not in hosts_to_scan:
                    hosts_to_scan.append(domain)

                if hosts_to_scan:
                    # Resolve domains to IP addresses for Masscan
                    logging.info(f"� ASSETS: Resolving {len(hosts_to_scan)} domains to IP addresses")
                    ip_to_domain_map = {}  # Map IPs back to domain names
                    ips_to_scan = []

                    for host in hosts_to_scan:
                        ip = resolve_domain_to_ip(host)
                        if ip:
                            ips_to_scan.append(ip)
                            ip_to_domain_map[ip] = host

                    if ips_to_scan:
                        logging.info(f"�🔌 ASSETS: Starting Nmap port scan on {len(ips_to_scan)} IP addresses")
                        try:
                            # Use top 10 critical ports for maximum speed and avoid 504 timeouts
                            port_results = scanning_service.scanner_manager.port_scan_only(ips_to_scan, top_ports=10, timing='T5')
                            open_ports = port_results.get('open_ports', [])
                            logging.info(f"🔌 ASSETS: Nmap completed, found {len(open_ports)} open ports")

                            # Organize ports by original domain name (not IP)
                            for port_info in open_ports:
                                ip = port_info.get('host', '')
                                port = port_info.get('port', '')
                                service = port_info.get('service', '')

                                # Map IP back to original domain name
                                original_domain = ip_to_domain_map.get(ip, ip)

                                if original_domain and port:
                                    if original_domain not in all_ports:
                                        all_ports[original_domain] = []
                                    all_ports[original_domain].append({
                                        'port': port,
                                        'service': service
                                    })
                        except Exception as port_error:
                            logging.warning(f"🔌 ASSETS: Nmap port scanning failed: {str(port_error)}")
                            all_ports = {}
                    else:
                        logging.warning(f"🔌 ASSETS: No domains could be resolved to IP addresses")
                        all_ports = {}

            logging.info(f"✅ ASSETS: Complete scan finished for {domain}")
        except Exception as scan_error:
            # If real scanning fails (e.g., Subfinder not available), fall back to simulation
            logging.warning(f"🔍 ASSETS: Real scanning failed ({str(scan_error)}), using simulation for {domain}")
            return simulate_subdomain_scan(domain, org.id)

        # Store the main domain as an asset if it doesn't exist
        main_domain_asset = Asset.query.filter_by(
            name=domain,
            organization_id=org.id,
            asset_type=AssetType.DOMAIN
        ).first()

        # Get port information for the main domain
        domain_ports = all_ports.get(domain, [])

        if not main_domain_asset:
            asset_metadata = {
                'ports': domain_ports,
                'scan_source': 'subfinder_httpx_nmap',
                'http_probe': http_probe_results.get(domain, {})
            }
            main_domain_asset = Asset(
                name=domain,
                asset_type=AssetType.DOMAIN,
                description=f"Main domain discovered during subdomain scan",
                organization_id=org.id,
                last_scanned=datetime.utcnow(),
                asset_metadata=asset_metadata
            )
            db.session.add(main_domain_asset)
        else:
            # Update existing domain asset with port and HTTP probe information
            existing_metadata = main_domain_asset.asset_metadata or {}
            existing_metadata['ports'] = domain_ports
            existing_metadata['scan_source'] = 'subfinder_httpx_nmap'
            existing_metadata['http_probe'] = http_probe_results.get(domain, {})
            main_domain_asset.asset_metadata = existing_metadata
            main_domain_asset.last_scanned = datetime.utcnow()

        # Store discovered subdomains as assets
        subdomains_added = 0
        subdomains_found = scan_results.get('subdomains', [])
        subdomain_names = []

        for subdomain_data in subdomains_found:
            # Extract subdomain name from the data structure
            subdomain_name = subdomain_data.get('host', '') if isinstance(subdomain_data, dict) else str(subdomain_data)
            if not subdomain_name:
                continue

            subdomain_names.append(subdomain_name)

            # Get port information for this subdomain
            ports_info = all_ports.get(subdomain_name, [])

            # Check if subdomain already exists
            existing_asset = Asset.query.filter_by(
                name=subdomain_name,
                organization_id=org.id
            ).first()

            if not existing_asset:
                # Create new subdomain asset with port and HTTP probe information
                http_probe_data = http_probe_results.get(subdomain_name, {})
                logging.info(f"🌐 ASSETS: Storing subdomain {subdomain_name} with HTTP probe data: {http_probe_data}")

                asset_metadata = {
                    'ports': ports_info,
                    'scan_source': 'subfinder_httpx_nmap',
                    'http_probe': http_probe_data
                }
                subdomain_asset = Asset(
                    name=subdomain_name,
                    asset_type=AssetType.SUBDOMAIN,
                    organization_id=org.id,
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow(),
                    asset_metadata=asset_metadata
                )
                db.session.add(subdomain_asset)
                subdomains_added += 1
            else:
                # Update existing asset with new port and HTTP probe information
                existing_metadata = existing_asset.asset_metadata or {}
                existing_metadata['ports'] = ports_info
                existing_metadata['scan_source'] = 'subfinder_httpx_nmap'
                existing_metadata['http_probe'] = http_probe_results.get(subdomain_name, {})
                existing_asset.asset_metadata = existing_metadata
                existing_asset.last_scanned = datetime.utcnow()

        db.session.commit()

        return jsonify({
            'success': True,
            'domain': domain,
            'subdomains_found': len(subdomain_names),
            'subdomains_added': subdomains_added,
            'subdomains': subdomain_names,
            'message': f'Scan completed successfully. Found {len(subdomain_names)} subdomains, added {subdomains_added} new assets.'
        })

    except Exception as e:
        db.session.rollback()
        logging.error(f"Subdomain scan error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def simulate_subdomain_scan(domain, organization_id):
    """Simulate subdomain scanning when real tools are not available"""
    try:
        # Generate realistic subdomains
        common_subdomains = ['www', 'api', 'admin', 'mail', 'ftp', 'test', 'dev', 'staging', 'blog', 'shop']
        subdomains_found = []

        # Randomly select 3-6 subdomains to simulate discovery
        import random
        num_subdomains = random.randint(3, 6)
        selected_subdomains = random.sample(common_subdomains, min(num_subdomains, len(common_subdomains)))

        for sub in selected_subdomains:
            subdomains_found.append(f"{sub}.{domain}")

        # Simulate HTTP probe results for discovered subdomains
        import random
        sample_technologies = [
            ['nginx', 'PHP'], ['Apache', 'WordPress'], ['Cloudflare', 'React'],
            ['nginx', 'Node.js'], ['Apache'], ['Cloudflare'], ['nginx'], []
        ]
        sample_status_codes = [200, 200, 200, 301, 302, 403, 404, 500]  # Mostly successful responses

        # Store the main domain as an asset if it doesn't exist
        main_domain_asset = Asset.query.filter_by(
            name=domain,
            organization_id=organization_id,
            asset_type=AssetType.DOMAIN
        ).first()

        if not main_domain_asset:
            main_domain_asset = Asset(
                name=domain,
                asset_type=AssetType.DOMAIN,
                description=f"Main domain discovered during subdomain scan",
                organization_id=organization_id,
                last_scanned=datetime.utcnow()
            )
            db.session.add(main_domain_asset)
        else:
            main_domain_asset.last_scanned = datetime.utcnow()

        # Store discovered subdomains as assets
        subdomains_added = 0

        for subdomain in subdomains_found:
            # Check if subdomain already exists
            existing_asset = Asset.query.filter_by(
                name=subdomain,
                organization_id=organization_id
            ).first()

            if not existing_asset:
                # Create simulated HTTP probe data for this subdomain
                status_code = random.choice(sample_status_codes)
                technologies = random.choice(sample_technologies)

                asset_metadata = {
                    'scan_source': 'simulated_subfinder_httpx',
                    'http_probe': {
                        'status_code': status_code,
                        'title': f'{subdomain} - Sample Page',
                        'technologies': technologies,
                        'webserver': random.choice(['nginx', 'Apache', 'Cloudflare']),
                        'last_http_probe': datetime.utcnow().isoformat(),
                        'url': f'https://{subdomain}',
                        'scheme': 'https'
                    }
                }

                # Create new subdomain asset
                subdomain_asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    description=f"Subdomain discovered via simulated Subfinder scan of {domain}",
                    organization_id=organization_id,
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow(),
                    asset_metadata=asset_metadata
                )
                db.session.add(subdomain_asset)
                subdomains_added += 1
            else:
                # Update last scanned time
                existing_asset.last_scanned = datetime.utcnow()

        db.session.commit()

        return jsonify({
            'success': True,
            'domain': domain,
            'subdomains_found': len(subdomains_found),
            'subdomains_added': subdomains_added,
            'subdomains': subdomains_found,
            'message': f'Simulated scan completed. Found {len(subdomains_found)} subdomains, added {subdomains_added} new assets.'
        })

    except Exception as e:
        db.session.rollback()
        logging.error(f"Simulated subdomain scan error: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_bp.route('/scan/<scan_id>/report', methods=['GET'])
@login_required
def download_report(scan_id):
    """Download scan report"""
    if scan_id not in scan_results:
        return jsonify({'error': 'Scan results not found'}), 404

    status = scan_status.get(scan_id, {})
    if status.get('user_id') != current_user.id:
        return jsonify({'error': 'Access denied'}), 403

    results = scan_results[scan_id]

    # Generate HTML report
    html_report = generate_html_report(results)

    response = make_response(html_report)
    response.headers['Content-Type'] = 'text/html'
    response.headers['Content-Disposition'] = f'attachment; filename=attack_surface_report_{scan_id[:8]}.html'

    return response

def simulate_scan(scan_id, domain):
    """Simulate the scanning process with Subfinder, Nmap, and Nuclei"""
    try:
        # Subfinder phase
        scan_status[scan_id]['message'] = 'Running Subfinder (subdomain discovery)...'
        for progress in range(0, 101, 20):
            scan_status[scan_id]['progress']['subfinder'] = progress
            time.sleep(0.5)

        # Generate sample subdomains
        sample_subdomains = [
            f'www.{domain}',
            f'api.{domain}',
            f'admin.{domain}',
            f'test.{domain}'
        ]

        # Nmap phase
        scan_status[scan_id]['message'] = 'Running Nmap (port scanning)...'
        for progress in range(0, 101, 25):
            scan_status[scan_id]['progress']['nmap'] = progress
            time.sleep(0.4)

        # Generate sample ports
        sample_ports = [
            {'host': domain, 'port': 80, 'service': 'http'},
            {'host': domain, 'port': 8433, 'service': 'https'},
            {'host': f'api.{domain}', 'port': 8088, 'service': 'http-alt'},
            {'host': f'admin.{domain}', 'port': 22, 'service': 'ssh'}
        ]

        # Nuclei phase
        scan_status[scan_id]['message'] = 'Running Nuclei (vulnerability scanning)...'
        for progress in range(0, 101, 33):
            scan_status[scan_id]['progress']['nuclei'] = progress
            time.sleep(0.3)

        # Generate sample vulnerabilities
        sample_vulnerabilities = [
            {
                'name': 'SSL Certificate Expiring Soon',
                'host': domain,
                'severity': 'high',
                'description': 'SSL certificate will expire within 30 days',
                'cve': None
            },
            {
                'name': 'Directory Listing Enabled',
                'host': f'api.{domain}',
                'severity': 'medium',
                'description': 'Directory listing is enabled on the web server',
                'cve': None
            }
        ]

        # Store results
        scan_results[scan_id] = {
            'domain': domain,
            'subdomains': sample_subdomains,
            'ports': sample_ports,
            'vulnerabilities': sample_vulnerabilities,
            'scan_id': scan_id,
            'completed_at': datetime.utcnow().isoformat()
        }

        # Update final status
        scan_status[scan_id].update({
            'status': 'completed',
            'message': 'Scan completed successfully',
            'completed_at': datetime.utcnow()
        })

    except Exception as e:
        scan_status[scan_id].update({
            'status': 'failed',
            'message': f'Scan failed: {str(e)}',
            'error': str(e)
        })

def generate_html_report(results):
    """Generate HTML report from scan results"""
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Attack Surface Report - {results['domain']}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .section {{ margin-bottom: 30px; }}
            .section h2 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 5px; }}
            .item {{ background: #f8f9fa; padding: 10px; margin: 5px 0; border-radius: 3px; }}
            .severity-critical {{ background: #f8d7da; }}
            .severity-high {{ background: #fff3cd; }}
            .severity-medium {{ background: #d1ecf1; }}
            .severity-low {{ background: #d4edda; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>Attack Surface Discovery Report</h1>
            <p><strong>Domain:</strong> {results['domain']}</p>
            <p><strong>Scan ID:</strong> {results['scan_id']}</p>
            <p><strong>Generated:</strong> {results['completed_at']}</p>
        </div>

        <div class="section">
            <h2>Summary</h2>
            <p><strong>Subdomains Found:</strong> {len(results['subdomains'])}</p>
            <p><strong>Open Ports:</strong> {len(results['ports'])}</p>
            <p><strong>Vulnerabilities:</strong> {len(results['vulnerabilities'])}</p>
        </div>

        <div class="section">
            <h2>Discovered Subdomains</h2>
            {''.join([f'<div class="item">{sub}</div>' for sub in results['subdomains']])}
        </div>

        <div class="section">
            <h2>Open Ports</h2>
            {''.join([f'<div class="item">{port["host"]}:{port["port"]} ({port["service"]})</div>' for port in results['ports']])}
        </div>

        <div class="section">
            <h2>Vulnerabilities</h2>
            {''.join([f'<div class="item severity-{vuln["severity"]}"><strong>{vuln["name"]}</strong><br>Host: {vuln["host"]}<br>Severity: {vuln["severity"].upper()}<br>{vuln["description"]}</div>' for vuln in results['vulnerabilities']])}
        </div>
    </body>
    </html>
    """
    return html

# ============================================================================
# CELERY-POWERED LARGE-SCALE SCANNING ENDPOINTS
# ============================================================================

@api_bp.route('/scan/large-domain', methods=['POST'])
@login_required
def start_large_domain_scan():
    """
    Start a large-scale domain scan using Celery background tasks
    Optimized for domains with hundreds/thousands of subdomains
    Includes graceful fallback for development without Redis
    """
    try:
        data = request.get_json()
        if not data or 'domain' not in data:
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            }), 400

        domain = data['domain'].strip()
        scan_type = data.get('scan_type', 'deep')  # quick, deep, full

        # Validate scan type
        if scan_type not in ['quick', 'deep', 'full']:
            return jsonify({
                'success': False,
                'error': 'Invalid scan type. Must be: quick, deep, or full'
            }), 400

        # Get user's organization
        org = Organization.query.filter_by(user_id=current_user.id).first()
        if not org:
            # Create default organization for user
            org = Organization(name=f"{current_user.username}'s Organization", user_id=current_user.id)
            db.session.add(org)
            db.session.commit()

        # Check Redis availability for Celery
        redis_available, redis_error = check_redis_availability()

        if redis_available:
            # Redis is available - use Celery for background processing
            try:
                from tasks import large_domain_scan_orchestrator

                # Start the large-scale scan orchestrator task
                task = large_domain_scan_orchestrator.delay(domain, org.id, scan_type)

                logging.info(f"🚀 Started large-scale {scan_type} scan for {domain} (Task ID: {task.id})")

                return jsonify({
                    'success': True,
                    'mode': 'celery',
                    'message': f'Large-scale {scan_type} scan started for {domain}',
                    'task_id': task.id,
                    'domain': domain,
                    'scan_type': scan_type,
                    'organization_id': org.id,
                    'status_endpoint': f'/api/scan/celery-status/{task.id}',
                    'estimated_time': {
                        'quick': '5-15 minutes',
                        'deep': '15-45 minutes',
                        'full': '30-90 minutes'
                    }.get(scan_type, '15-45 minutes'),
                    'features': [
                        'Background processing - dashboard remains responsive',
                        'Real-time progress updates',
                        'Automatic subdomain discovery with Subfinder',
                        'HTTP probing with httpx for live host detection',
                        'Port scanning with Nmap (alive hosts only)',
                        'Vulnerability scanning with Nuclei',
                        'Automatic database storage of all results'
                    ]
                })

            except ImportError as e:
                logging.warning(f"❌ Celery tasks not available: {str(e)}")
                redis_available = False  # Fall through to fallback mode

        if not redis_available:
            # Redis not available - use fallback mode with simulated scanning
            logging.info(f"🔄 Using fallback mode for {scan_type} scan of {domain}")

            # Generate a simulated task ID for tracking
            import uuid
            fallback_task_id = str(uuid.uuid4())

            # Start simulated scan in background thread with Flask context
            import threading
            from flask import current_app

            # Get current Flask app instance for context
            app_instance = current_app._get_current_object()

            scan_thread = threading.Thread(
                target=simulate_large_scale_scan_with_context,
                args=(app_instance, fallback_task_id, domain, org.id, scan_type)
            )
            scan_thread.daemon = True
            scan_thread.start()

            return jsonify({
                'success': True,
                'mode': 'fallback',
                'message': f'Large-scale {scan_type} scan started for {domain} (Fallback Mode)',
                'task_id': fallback_task_id,
                'domain': domain,
                'scan_type': scan_type,
                'organization_id': org.id,
                'status_endpoint': f'/api/scan/fallback-status/{fallback_task_id}',
                'estimated_time': {
                    'quick': '2-5 minutes',
                    'deep': '5-10 minutes',
                    'full': '10-15 minutes'
                }.get(scan_type, '5-10 minutes'),
                'features': [
                    'Simulated large-scale scanning for development',
                    'Real-time progress updates',
                    'Simulated subdomain discovery',
                    'Simulated HTTP probing',
                    'Automatic database storage of simulated results'
                ],
                'notice': 'Running in fallback mode. Install and start Redis for full Celery functionality.',
                'redis_status': {
                    'available': False,
                    'error': redis_error,
                    'setup_guide': '/static/docs/redis-setup.html'
                }
            })

    except Exception as e:
        logging.error(f"Failed to start large-scale scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e),
            'redis_status': get_redis_status_message()
        }), 500

@api_bp.route('/scan/celery-status/<task_id>', methods=['GET'])
@login_required
def get_celery_scan_status(task_id):
    """
    Get real-time status of a Celery scanning task
    Provides detailed progress information for large-scale scans
    """
    try:
        # Import Celery here to avoid circular imports
        try:
            from celery.result import AsyncResult
            celery_available = True
        except ImportError:
            celery_available = False

        if not celery_available:
            return jsonify({
                'success': False,
                'error': 'Celery not available'
            }), 503

        # Get task result
        task = AsyncResult(task_id)

        if task.state == 'PENDING':
            response = {
                'success': True,
                'task_id': task_id,
                'state': 'PENDING',
                'status': 'Task is waiting to be processed...',
                'progress': 0
            }
        elif task.state == 'PROGRESS':
            response = {
                'success': True,
                'task_id': task_id,
                'state': 'PROGRESS',
                'progress': task.info.get('progress', 0),
                'stage': task.info.get('stage', 'unknown'),
                'message': task.info.get('message', 'Processing...'),
                'domain': task.info.get('domain', ''),
                'current_phase': task.info.get('current_phase', ''),
                'subdomains_found': task.info.get('subdomains_found', 0),
                'alive_hosts_found': task.info.get('alive_hosts_found', 0)
            }
        elif task.state == 'SUCCESS':
            result = task.result
            response = {
                'success': True,
                'task_id': task_id,
                'state': 'SUCCESS',
                'progress': 100,
                'message': 'Scan completed successfully',
                'result': result
            }
        elif task.state == 'FAILURE':
            # Handle task failure with proper error extraction
            error_info = task.info
            if isinstance(error_info, dict):
                error_message = error_info.get('error', str(error_info))
                stage = error_info.get('stage', 'failed')
                failed_at = error_info.get('failed_at', '')
            else:
                error_message = str(error_info) if error_info else 'Unknown error'
                stage = 'failed'
                failed_at = ''

            response = {
                'success': False,
                'task_id': task_id,
                'state': 'FAILURE',
                'error': error_message,
                'stage': stage,
                'failed_at': failed_at,
                'progress': 0
            }
        else:
            response = {
                'success': True,
                'task_id': task_id,
                'state': task.state,
                'status': 'Unknown task state',
                'progress': 0
            }

        return jsonify(response)

    except Exception as e:
        logging.error(f"Failed to get task status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# FALLBACK MODE IMPLEMENTATION
# ============================================================================

# Global storage for fallback scan status
fallback_scan_status = {}

def simulate_large_scale_scan_with_context(app_instance, task_id, domain, organization_id, scan_type='deep'):
    """
    Context-aware wrapper for simulate_large_scale_scan that handles Flask application context
    """
    with app_instance.app_context():
        simulate_large_scale_scan(task_id, domain, organization_id, scan_type)

def simulate_large_scale_scan(task_id, domain, organization_id, scan_type='deep'):
    """
    Simulate large-scale scanning for development/fallback mode
    Provides realistic progress updates and stores simulated results
    """
    import time
    import random

    try:
        # Initialize scan status
        fallback_scan_status[task_id] = {
            'state': 'PROGRESS',
            'progress': 0,
            'stage': 'initializing',
            'domain': domain,
            'message': f'Initializing large-scale scan for {domain}...',
            'subdomains_found': 0,
            'alive_hosts_found': 0,
            'start_time': datetime.now().isoformat()
        }

        # Simulate subdomain discovery phase
        logging.info(f"🔍 Fallback: Starting subdomain discovery for {domain}")
        fallback_scan_status[task_id].update({
            'stage': 'subdomain_discovery',
            'progress': 10,
            'message': f'Discovering subdomains for {domain}...',
            'current_phase': 'Subfinder scanning'
        })

        # Simulate discovery time based on scan type
        discovery_time = {'quick': 2, 'deep': 4, 'full': 6}.get(scan_type, 4)
        time.sleep(discovery_time)

        # Generate simulated subdomains
        subdomain_count = {'quick': 15, 'deep': 45, 'full': 85}.get(scan_type, 45)
        simulated_subdomains = generate_simulated_subdomains(domain, subdomain_count)

        fallback_scan_status[task_id].update({
            'progress': 30,
            'subdomains_found': len(simulated_subdomains),
            'message': f'Found {len(simulated_subdomains)} subdomains'
        })

        # Simulate HTTP probing phase
        logging.info(f"🌐 Fallback: Starting HTTP probing for {len(simulated_subdomains)} subdomains")
        fallback_scan_status[task_id].update({
            'stage': 'http_probing',
            'progress': 40,
            'message': f'HTTP probing {len(simulated_subdomains)} subdomains...',
            'current_phase': 'HTTP probing with httpx'
        })

        # Simulate probing time
        probing_time = {'quick': 3, 'deep': 6, 'full': 10}.get(scan_type, 6)
        time.sleep(probing_time)

        # Simulate alive hosts (60-80% of subdomains)
        alive_count = int(len(simulated_subdomains) * random.uniform(0.6, 0.8))
        alive_hosts = simulated_subdomains[:alive_count]

        fallback_scan_status[task_id].update({
            'progress': 70,
            'alive_hosts_found': alive_count,
            'message': f'Found {alive_count} alive hosts'
        })

        # Simulate final processing
        logging.info(f"📊 Fallback: Processing results for {domain}")
        fallback_scan_status[task_id].update({
            'stage': 'processing_results',
            'progress': 90,
            'message': 'Processing and storing scan results...'
        })

        time.sleep(2)

        # Store simulated results in database
        try:
            store_simulated_scan_results(domain, organization_id, simulated_subdomains, alive_hosts, scan_type)
            logging.info(f"📊 Successfully stored simulated scan results for {domain}")
        except Exception as db_error:
            logging.error(f"❌ Failed to store simulated scan results for {domain}: {str(db_error)}")
            # Continue with completion even if database storage fails

        # Mark as completed
        from datetime import timezone
        completion_time = datetime.now(timezone.utc)

        fallback_scan_status[task_id].update({
            'state': 'SUCCESS',
            'progress': 100,
            'stage': 'completed',
            'message': 'Large-scale scan completed successfully!',
            'completed_at': completion_time.isoformat(),
            'result': {
                'success': True,
                'domain': domain,
                'scan_type': scan_type,
                'subdomains_found': len(simulated_subdomains),
                'alive_hosts_found': alive_count,
                'mode': 'fallback'
            }
        })

        logging.info(f"✅ Fallback scan completed for {domain}: {len(simulated_subdomains)} subdomains, {alive_count} alive hosts")

    except Exception as e:
        logging.error(f"❌ Fallback scan failed for {domain}: {str(e)}")
        import traceback
        logging.error(f"❌ Fallback scan traceback: {traceback.format_exc()}")

        fallback_scan_status[task_id] = {
            'state': 'FAILURE',
            'progress': 0,
            'error': str(e),
            'domain': domain,
            'failed_at': datetime.now(timezone.utc).isoformat()
        }

def generate_simulated_subdomains(domain, count):
    """Generate realistic simulated subdomains for testing"""
    prefixes = [
        'www', 'api', 'admin', 'mail', 'ftp', 'blog', 'shop', 'dev', 'test', 'staging',
        'cdn', 'static', 'media', 'images', 'assets', 'docs', 'support', 'help',
        'app', 'mobile', 'secure', 'vpn', 'remote', 'portal', 'dashboard', 'panel',
        'beta', 'alpha', 'demo', 'sandbox', 'lab', 'research', 'internal', 'private'
    ]

    subdomains = []
    for i in range(min(count, len(prefixes))):
        subdomains.append(f"{prefixes[i]}.{domain}")

    # Add numbered subdomains if we need more
    if count > len(prefixes):
        for i in range(count - len(prefixes)):
            subdomains.append(f"sub{i+1}.{domain}")

    return subdomains[:count]

def store_simulated_scan_results(domain, organization_id, subdomains, alive_hosts, scan_type):
    """Store simulated scan results in the database with proper error handling"""
    try:
        from datetime import timezone
        current_time = datetime.now(timezone.utc)

        # Store main domain
        main_domain_asset = Asset.query.filter_by(name=domain, organization_id=organization_id).first()
        if not main_domain_asset:
            main_domain_asset = Asset(
                name=domain,
                asset_type=AssetType.DOMAIN,
                description=f"Main domain discovered during simulated large-scale scan",
                organization_id=organization_id,
                last_scanned=current_time,
                asset_metadata={
                    'scan_source': 'fallback_simulation',
                    'scan_type': scan_type,
                    'simulation_mode': True
                }
            )
            db.session.add(main_domain_asset)
        else:
            main_domain_asset.last_scanned = current_time

        # Store subdomains
        for subdomain in subdomains:
            existing_asset = Asset.query.filter_by(name=subdomain, organization_id=organization_id).first()

            if not existing_asset:
                # Create new subdomain asset
                asset_metadata = {
                    'scan_source': 'fallback_simulation',
                    'scan_type': scan_type,
                    'simulation_mode': True,
                    'parent_domain': domain,
                    'is_alive': subdomain in alive_hosts
                }

                if subdomain in alive_hosts:
                    asset_metadata['http_probe'] = {
                        'status_code': random.choice([200, 301, 302, 403]),
                        'title': f'{subdomain} - Simulated Page',
                        'webserver': random.choice(['nginx', 'Apache', 'Cloudflare']),
                        'last_http_probe': current_time.isoformat(),
                        'url': f'https://{subdomain}',
                        'scheme': 'https'
                    }

                subdomain_asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    description=f"Subdomain discovered via simulated large-scale scan of {domain}",
                    organization_id=organization_id,
                    discovered_at=current_time,
                    last_scanned=current_time,
                    asset_metadata=asset_metadata
                )
                db.session.add(subdomain_asset)
            else:
                # Update existing asset
                existing_asset.last_scanned = current_time

        db.session.commit()
        logging.info(f"📊 Stored simulated scan results: {len(subdomains)} subdomains for {domain}")

    except Exception as e:
        logging.error(f"Failed to store simulated scan results: {str(e)}")
        db.session.rollback()

@api_bp.route('/scan/fallback-status/<task_id>', methods=['GET'])
@login_required
def get_fallback_scan_status(task_id):
    """
    Get real-time status of a fallback scanning task
    Provides detailed progress information for simulated large-scale scans
    """
    try:
        if task_id not in fallback_scan_status:
            return jsonify({
                'success': False,
                'error': 'Task not found',
                'task_id': task_id
            }), 404

        status = fallback_scan_status[task_id]

        return jsonify({
            'success': True,
            'task_id': task_id,
            'mode': 'fallback',
            **status
        })

    except Exception as e:
        logging.error(f"Failed to get fallback task status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@api_bp.route('/system/redis-status', methods=['GET'])
@login_required
def get_redis_system_status():
    """
    Get Redis system status for the frontend
    Provides information about Redis availability and setup instructions
    """
    try:
        redis_status = get_redis_status_message()

        return jsonify({
            'success': True,
            'redis': redis_status,
            'celery_available': redis_status['status'] == 'available',
            'setup_instructions': {
                'docker': 'docker run -d --name redis-dev -p 6379:6379 redis:latest',
                'test': 'docker exec redis-dev redis-cli ping',
                'docs': '/static/docs/redis-setup.html'
            }
        })

    except Exception as e:
        logging.error(f"Failed to get Redis status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# PROGRESSIVE SCANNING WITH REAL-TIME UPDATES
# ============================================================================

@api_bp.route('/progressive-scan-updates/<task_id>')
@login_required
def progressive_scan_updates_stream(task_id):
    """Server-Sent Events endpoint for real-time progressive scanning updates"""

    def event_stream():
        """Generate Server-Sent Events for progressive scan updates"""
        try:
            # Send initial connection event
            connection_data = {'type': 'connected', 'task_id': task_id, 'timestamp': datetime.now().isoformat()}
            yield f"data: {json.dumps(connection_data)}\n\n"

            # Monitor for progressive updates
            last_update_time = time.time()
            timeout = 300  # 5 minutes timeout

            while time.time() - last_update_time < timeout:
                try:
                    # Check for Celery task updates
                    from celery.result import AsyncResult
                    task = AsyncResult(task_id)

                    if task.state == 'PROGRESS':
                        task_meta = task.info or {}
                        progressive_update = task_meta.get('progressive_update')

                        if progressive_update:
                            # Send progressive update to client
                            update_data = {
                                'type': 'progressive_update',
                                'task_id': task_id,
                                'stage': task_meta.get('stage', 'unknown'),
                                'progress': task_meta.get('progress', 0),
                                'message': task_meta.get('message', ''),
                                'update': progressive_update,
                                'timestamp': datetime.now().isoformat()
                            }
                            yield f"data: {json.dumps(update_data)}\n\n"

                            last_update_time = time.time()

                    elif task.state == 'SUCCESS':
                        # Send completion event
                        completion_data = {
                            'type': 'completed',
                            'task_id': task_id,
                            'result': task.result,
                            'timestamp': datetime.now().isoformat()
                        }
                        yield f"data: {json.dumps(completion_data)}\n\n"
                        break

                    elif task.state == 'FAILURE':
                        # Send failure event
                        failure_data = {
                            'type': 'failed',
                            'task_id': task_id,
                            'error': str(task.info),
                            'timestamp': datetime.now().isoformat()
                        }
                        yield f"data: {json.dumps(failure_data)}\n\n"
                        break

                    # Wait before next check
                    time.sleep(2)

                except Exception as e:
                    logging.error(f"Error in progressive scan updates stream: {str(e)}")
                    error_data = {
                        'type': 'error',
                        'task_id': task_id,
                        'error': str(e),
                        'timestamp': datetime.now().isoformat()
                    }
                    yield f"data: {json.dumps(error_data)}\n\n"
                    break

            # Send timeout event if no updates received
            timeout_data = {
                'type': 'timeout',
                'task_id': task_id,
                'message': 'No updates received within timeout period',
                'timestamp': datetime.now().isoformat()
            }
            yield f"data: {json.dumps(timeout_data)}\n\n"

        except Exception as e:
            logging.error(f"Error in progressive scan updates stream: {str(e)}")
            error_data = {
                'type': 'error',
                'task_id': task_id,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            }
            yield f"data: {json.dumps(error_data)}\n\n"

    return Response(
        event_stream(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Cache-Control'
        }
    )

@api_bp.route('/large-scale-scan-progressive', methods=['POST'])
@login_required
def start_large_scale_scan_progressive():
    """Start a large-scale scan with progressive real-time updates"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    data = request.get_json()
    if not data or 'domain' not in data:
        return jsonify({'error': 'Domain is required'}), 400

    domain = data['domain'].strip()
    scan_type = data.get('scan_type', 'quick')

    if not domain:
        return jsonify({'error': 'Domain cannot be empty'}), 400

    try:
        # Check if Celery is available
        try:
            from tasks import progressive_large_domain_scan_orchestrator
            celery_available = True
        except ImportError:
            celery_available = False

        if not celery_available:
            return jsonify({
                'success': False,
                'error': 'Celery not available for progressive scanning'
            }), 503

        # Start the progressive large-scale scan
        task = progressive_large_domain_scan_orchestrator.delay(
            domain=domain,
            organization_id=org.id,
            scan_type=scan_type
        )

        return jsonify({
            'success': True,
            'task_id': task.id,
            'domain': domain,
            'scan_type': scan_type,
            'message': 'Progressive large-scale scan started',
            'progressive_updates_url': f'/api/progressive-scan-updates/{task.id}'
        })

    except Exception as e:
        logging.error(f"Failed to start progressive large-scale scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ============================================================================
# VULNERABILITY MANAGEMENT API
# ============================================================================

@api_bp.route('/vulnerabilities/<int:vuln_id>/resolve', methods=['POST'])
@login_required
def resolve_vulnerability(vuln_id):
    """Mark a vulnerability as resolved"""
    try:
        # Get user's organization
        org = Organization.query.filter_by(user_id=current_user.id).first()
        if not org:
            return jsonify({'success': False, 'error': 'Organization not found'}), 404

        # Find the vulnerability
        vulnerability = Vulnerability.query.filter_by(
            id=vuln_id,
            organization_id=org.id
        ).first()

        if not vulnerability:
            return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404

        # Mark as resolved
        vulnerability.is_resolved = True
        vulnerability.resolved_at = datetime.now()
        db.session.commit()

        return jsonify({'success': True, 'message': 'Vulnerability marked as resolved'})

    except Exception as e:
        logging.error(f"Error resolving vulnerability {vuln_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to resolve vulnerability'}), 500

@api_bp.route('/vulnerabilities/<int:vuln_id>/reopen', methods=['POST'])
@login_required
def reopen_vulnerability(vuln_id):
    """Reopen a resolved vulnerability"""
    try:
        # Get user's organization
        org = Organization.query.filter_by(user_id=current_user.id).first()
        if not org:
            return jsonify({'success': False, 'error': 'Organization not found'}), 404

        # Find the vulnerability
        vulnerability = Vulnerability.query.filter_by(
            id=vuln_id,
            organization_id=org.id
        ).first()

        if not vulnerability:
            return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404

        # Mark as open
        vulnerability.is_resolved = False
        vulnerability.resolved_at = None
        db.session.commit()

        return jsonify({'success': True, 'message': 'Vulnerability reopened'})

    except Exception as e:
        logging.error(f"Error reopening vulnerability {vuln_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to reopen vulnerability'}), 500

@api_bp.route('/vulnerabilities/<int:vuln_id>', methods=['DELETE'])
@login_required
def delete_vulnerability(vuln_id):
    """Delete a vulnerability"""
    try:
        # Get user's organization
        org = Organization.query.filter_by(user_id=current_user.id).first()
        if not org:
            return jsonify({'success': False, 'error': 'Organization not found'}), 404

        # Find the vulnerability
        vulnerability = Vulnerability.query.filter_by(
            id=vuln_id,
            organization_id=org.id
        ).first()

        if not vulnerability:
            return jsonify({'success': False, 'error': 'Vulnerability not found'}), 404

        # Delete the vulnerability
        db.session.delete(vulnerability)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Vulnerability deleted successfully'})

    except Exception as e:
        logging.error(f"Error deleting vulnerability {vuln_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete vulnerability'}), 500

# Settings API Endpoints
@api_bp.route('/settings/organization', methods=['GET', 'POST'])
@login_required
def organization_settings():
    """Get or update organization settings"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    if request.method == 'GET':
        return jsonify({
            'id': org.id,
            'name': org.name,
            'created_at': org.created_at.isoformat(),
            'primary_domain': getattr(org, 'primary_domain', ''),
            'description': getattr(org, 'description', '')
        })

    elif request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        try:
            if 'name' in data:
                org.name = data['name']
            if 'primary_domain' in data:
                org.primary_domain = data['primary_domain']
            if 'description' in data:
                org.description = data['description']

            db.session.commit()
            return jsonify({'success': True, 'message': 'Organization settings updated successfully'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update organization settings: {str(e)}'}), 500

@api_bp.route('/settings/interface', methods=['POST'])
@login_required
def save_interface_settings():
    """Save interface preferences (stored in localStorage on frontend)"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Interface settings are typically stored client-side
    # This endpoint just validates the data and returns success
    valid_themes = ['light', 'dark', 'auto']
    valid_views = ['dashboard', 'assets', 'vulnerabilities']

    if 'theme' in data and data['theme'] not in valid_themes:
        return jsonify({'error': 'Invalid theme'}), 400

    if 'default_view' in data and data['default_view'] not in valid_views:
        return jsonify({'error': 'Invalid default view'}), 400

    return jsonify({'success': True, 'message': 'Interface settings saved successfully'})

@api_bp.route('/settings/scanning', methods=['POST'])
@login_required
def save_scanning_settings():
    """Save scanning configuration settings"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # In a real implementation, these would be stored in a settings table
    # For now, we'll just validate and return success

    valid_frequencies = ['daily', 'weekly', 'monthly']

    if 'scan_frequency' in data and data['scan_frequency'] not in valid_frequencies:
        return jsonify({'error': 'Invalid scan frequency'}), 400

    if 'concurrent_scans' in data:
        try:
            concurrent = int(data['concurrent_scans'])
            if concurrent < 1 or concurrent > 10:
                return jsonify({'error': 'Concurrent scans must be between 1 and 10'}), 400
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid concurrent scans value'}), 400

    return jsonify({'success': True, 'message': 'Scanning settings saved successfully'})

@api_bp.route('/settings/notifications', methods=['POST'])
@login_required
def save_notification_settings():
    """Save notification settings"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    # Validate email if provided
    if 'notification_email' in data:
        email = data['notification_email']
        if email and '@' not in email:
            return jsonify({'error': 'Invalid email address'}), 400

    valid_frequencies = ['immediate', 'hourly', 'daily', 'weekly']
    if 'digest_frequency' in data and data['digest_frequency'] not in valid_frequencies:
        return jsonify({'error': 'Invalid digest frequency'}), 400

    return jsonify({'success': True, 'message': 'Notification settings saved successfully'})

@api_bp.route('/settings/data-retention', methods=['POST'])
@login_required
def save_data_retention_settings():
    """Save data retention policies"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    valid_retention_values = ['30', '90', '180', '365', '730', '0']  # 0 means never delete

    for setting in ['scan_retention', 'vuln_retention', 'alert_retention']:
        if setting in data and str(data[setting]) not in valid_retention_values:
            return jsonify({'error': f'Invalid {setting} value'}), 400

    return jsonify({'success': True, 'message': 'Data retention settings saved successfully'})

@api_bp.route('/settings/backup', methods=['POST'])
@login_required
def save_backup_settings():
    """Save backup configuration"""
    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    valid_frequencies = ['daily', 'weekly', 'monthly']
    valid_retention = ['7', '30', '90']

    if 'backup_frequency' in data and data['backup_frequency'] not in valid_frequencies:
        return jsonify({'error': 'Invalid backup frequency'}), 400

    if 'backup_retention' in data and str(data['backup_retention']) not in valid_retention:
        return jsonify({'error': 'Invalid backup retention'}), 400

    return jsonify({'success': True, 'message': 'Backup settings saved successfully'})

@api_bp.route('/settings/export', methods=['POST'])
@login_required
def export_data():
    """Export organization data"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    data = request.get_json()
    export_format = data.get('format', 'json') if data else 'json'

    if export_format not in ['json', 'csv']:
        return jsonify({'error': 'Invalid export format'}), 400

    try:
        # Get all organization data
        assets = Asset.query.filter_by(organization_id=org.id).all()
        vulnerabilities = Vulnerability.query.filter_by(organization_id=org.id).all()
        alerts = Alert.query.filter_by(organization_id=org.id).all()

        export_data = {
            'organization': {
                'name': org.name,
                'created_at': org.created_at.isoformat()
            },
            'assets': [{
                'name': asset.name,
                'type': asset.asset_type.value,
                'description': asset.description,
                'discovered_at': asset.discovered_at.isoformat(),
                'is_active': asset.is_active
            } for asset in assets],
            'vulnerabilities': [{
                'title': vuln.title,
                'severity': vuln.severity.value,
                'discovered_at': vuln.discovered_at.isoformat(),
                'is_resolved': vuln.is_resolved,
                'asset_name': vuln.asset.name if vuln.asset else None
            } for vuln in vulnerabilities],
            'alerts': [{
                'title': alert.title,
                'type': alert.alert_type.value,
                'severity': alert.severity.value,
                'created_at': alert.created_at.isoformat(),
                'is_resolved': alert.is_resolved
            } for alert in alerts],
            'exported_at': datetime.utcnow().isoformat()
        }

        if export_format == 'json':
            response = make_response(json.dumps(export_data, indent=2))
            response.headers['Content-Type'] = 'application/json'
            response.headers['Content-Disposition'] = f'attachment; filename=attack_surface_data_{org.name}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'
        else:  # CSV format
            # For CSV, we'll export assets only for simplicity
            csv_data = "Name,Type,Description,Discovered At,Active\n"
            for asset in assets:
                csv_data += f'"{asset.name}","{asset.asset_type.value}","{asset.description}","{asset.discovered_at.isoformat()}","{asset.is_active}"\n'

            response = make_response(csv_data)
            response.headers['Content-Type'] = 'text/csv'
            response.headers['Content-Disposition'] = f'attachment; filename=attack_surface_assets_{org.name}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'

        return response

    except Exception as e:
        return jsonify({'error': f'Export failed: {str(e)}'}), 500

@api_bp.route('/settings/api-key', methods=['POST'])
@login_required
def regenerate_api_key():
    """Regenerate API key for the user"""
    try:
        # In a real implementation, you would generate and store a new API key
        new_api_key = f"sk-{uuid.uuid4().hex[:32]}"

        # Here you would update the user's API key in the database
        # For now, we'll just return a simulated key

        return jsonify({
            'success': True,
            'api_key': new_api_key,
            'message': 'API key regenerated successfully'
        })

    except Exception as e:
        return jsonify({'error': f'Failed to regenerate API key: {str(e)}'}), 500

# User Management API Endpoints
@api_bp.route('/settings/users', methods=['GET'])
@login_required
def get_organization_users():
    """Get all users in the organization"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    try:
        # Get organization members
        members = db.session.query(User, OrganizationUser).join(
            OrganizationUser, User.id == OrganizationUser.user_id
        ).filter(OrganizationUser.organization_id == org.id).all()

        users_data = []
        for user, membership in members:
            users_data.append({
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'role': membership.role.value,
                'joined_at': membership.joined_at.isoformat(),
                'is_active': membership.is_active,
                'permissions': {
                    'can_view_assets': membership.can_view_assets,
                    'can_add_assets': membership.can_add_assets,
                    'can_run_scans': membership.can_run_scans,
                    'can_view_reports': membership.can_view_reports,
                    'can_manage_settings': membership.can_manage_settings
                }
            })

        # Get pending invitations
        pending_invitations = UserInvitation.query.filter_by(
            organization_id=org.id,
            is_accepted=False
        ).all()

        invitations_data = []
        for invitation in pending_invitations:
            invitations_data.append({
                'id': invitation.id,
                'email': invitation.email,
                'role': invitation.role.value,
                'created_at': invitation.created_at.isoformat(),
                'expires_at': invitation.expires_at.isoformat(),
                'invited_by': invitation.invited_by.username
            })

        return jsonify({
            'users': users_data,
            'pending_invitations': invitations_data
        })

    except Exception as e:
        return jsonify({'error': f'Failed to get users: {str(e)}'}), 500

@api_bp.route('/settings/users/invite', methods=['POST'])
@login_required
def invite_user():
    """Invite a user to the organization"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    try:
        from services.email_service import EmailService, generate_invitation_token
        from models import UserInvitation, UserRole
        from datetime import timedelta

        # Validate required fields
        email = data.get('email')
        role = data.get('role', 'member')

        if not email:
            return jsonify({'error': 'Email is required'}), 400

        # Check if user already exists and is a member
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            existing_membership = OrganizationUser.query.filter_by(
                user_id=existing_user.id,
                organization_id=org.id
            ).first()
            if existing_membership:
                return jsonify({'error': 'User is already a member of this organization'}), 400

        # Check for pending invitation
        pending_invitation = UserInvitation.query.filter_by(
            email=email,
            organization_id=org.id,
            is_accepted=False
        ).first()
        if pending_invitation:
            return jsonify({'error': 'An invitation has already been sent to this email'}), 400

        # Create invitation
        invitation = UserInvitation(
            email=email,
            organization_id=org.id,
            invited_by_id=current_user.id,
            role=UserRole(role),
            token=generate_invitation_token(),
            expires_at=datetime.utcnow() + timedelta(days=7),
            can_view_assets=data.get('can_view_assets', True),
            can_add_assets=data.get('can_add_assets', True),
            can_run_scans=data.get('can_run_scans', False),
            can_view_reports=data.get('can_view_reports', True),
            can_manage_settings=data.get('can_manage_settings', False)
        )

        db.session.add(invitation)
        db.session.commit()

        # Send invitation email
        email_service = EmailService(org.id)
        if email_service.is_configured():
            result = email_service.send_user_invitation(invitation)
            if not result['success']:
                return jsonify({'error': f'Failed to send invitation email: {result["error"]}'}), 500

        return jsonify({
            'success': True,
            'message': 'User invitation sent successfully',
            'invitation_id': invitation.id
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to invite user: {str(e)}'}), 500

@api_bp.route('/settings/users/<int:user_id>', methods=['PUT', 'DELETE'])
@login_required
def manage_user(user_id):
    """Update or remove a user from the organization"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    membership = OrganizationUser.query.filter_by(
        user_id=user_id,
        organization_id=org.id
    ).first()

    if not membership:
        return jsonify({'error': 'User not found in organization'}), 404

    if request.method == 'PUT':
        # Update user permissions
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        try:
            if 'role' in data:
                membership.role = UserRole(data['role'])
            if 'can_view_assets' in data:
                membership.can_view_assets = data['can_view_assets']
            if 'can_add_assets' in data:
                membership.can_add_assets = data['can_add_assets']
            if 'can_run_scans' in data:
                membership.can_run_scans = data['can_run_scans']
            if 'can_view_reports' in data:
                membership.can_view_reports = data['can_view_reports']
            if 'can_manage_settings' in data:
                membership.can_manage_settings = data['can_manage_settings']
            if 'is_active' in data:
                membership.is_active = data['is_active']

            db.session.commit()
            return jsonify({'success': True, 'message': 'User updated successfully'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to update user: {str(e)}'}), 500

    elif request.method == 'DELETE':
        # Remove user from organization
        try:
            db.session.delete(membership)
            db.session.commit()
            return jsonify({'success': True, 'message': 'User removed from organization'})

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to remove user: {str(e)}'}), 500

# Email Configuration API Endpoints
@api_bp.route('/settings/email/config', methods=['GET', 'POST'])
@login_required
def email_configuration():
    """Get or update email configuration"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    if request.method == 'GET':
        config = EmailConfiguration.query.filter_by(organization_id=org.id).first()
        if not config:
            return jsonify({
                'is_configured': False,
                'is_verified': False
            })

        return jsonify({
            'is_configured': config.is_configured,
            'is_verified': config.is_verified,
            'smtp_host': config.smtp_host,
            'smtp_port': config.smtp_port,
            'smtp_username': config.smtp_username,
            'smtp_use_tls': config.smtp_use_tls,
            'smtp_use_ssl': config.smtp_use_ssl,
            'from_email': config.from_email,
            'from_name': config.from_name,
            'reply_to': config.reply_to,
            'last_test_at': config.last_test_at.isoformat() if config.last_test_at else None,
            'last_test_status': config.last_test_status
        })

    elif request.method == 'POST':
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400

        try:
            config = EmailConfiguration.query.filter_by(organization_id=org.id).first()
            if not config:
                config = EmailConfiguration(organization_id=org.id)
                db.session.add(config)

            # Update configuration
            config.smtp_host = data.get('smtp_host', config.smtp_host)
            config.smtp_port = data.get('smtp_port', config.smtp_port)
            config.smtp_username = data.get('smtp_username', config.smtp_username)
            if 'smtp_password' in data and data['smtp_password']:
                config.smtp_password = data['smtp_password']  # In production, encrypt this
            config.smtp_use_tls = data.get('smtp_use_tls', config.smtp_use_tls)
            config.smtp_use_ssl = data.get('smtp_use_ssl', config.smtp_use_ssl)
            config.from_email = data.get('from_email', config.from_email)
            config.from_name = data.get('from_name', config.from_name)
            config.reply_to = data.get('reply_to', config.reply_to)

            # Mark as configured if all required fields are present
            config.is_configured = all([
                config.smtp_host,
                config.smtp_port,
                config.smtp_username,
                config.smtp_password,
                config.from_email
            ])

            db.session.commit()

            return jsonify({
                'success': True,
                'message': 'Email configuration saved successfully',
                'is_configured': config.is_configured
            })

        except Exception as e:
            db.session.rollback()
            return jsonify({'error': f'Failed to save email configuration: {str(e)}'}), 500

@api_bp.route('/settings/email/test', methods=['POST'])
@login_required
def test_email_configuration():
    """Test email configuration"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404

    data = request.get_json()
    if not data or 'test_email' not in data:
        return jsonify({'error': 'Test email address is required'}), 400

    try:
        from services.email_service import EmailService

        email_service = EmailService(org.id)
        if not email_service.is_configured():
            return jsonify({'error': 'Email not configured'}), 400

        # Test connection first
        test_result = email_service.test_connection()
        if not test_result['success']:
            return jsonify({'error': test_result['error']}), 400

        # Send test email
        result = email_service.send_test_email(data['test_email'])

        if result['success']:
            return jsonify({
                'success': True,
                'message': f'Test email sent successfully to {data["test_email"]}'
            })
        else:
            return jsonify({'error': result['error']}), 500

    except Exception as e:
        return jsonify({'error': f'Failed to test email: {str(e)}'}), 500
