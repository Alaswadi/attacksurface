from flask import Blueprint, jsonify, request, render_template, make_response
from flask_login import login_required, current_user
from models import db, Organization, Asset, Vulnerability, Alert, AssetType, SeverityLevel
from datetime import datetime, timedelta
import json
import uuid
import threading
import time
import random
import logging
import socket

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
            'metadata': asset.asset_metadata or {}
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
            'asset_name': vuln.asset.name if vuln.asset else None
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
            'naabu': 0,
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

            # Step 2: Port scanning with Naabu on discovered subdomains
            subdomains_found = scan_results.get('subdomains', [])
            all_ports = {}

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
                        logging.info(f"�🔌 ASSETS: Starting Naabu port scan on {len(ips_to_scan)} IP addresses")
                        try:
                            # Use top 100 ports for faster scanning
                            port_results = scanning_service.scanner_manager.port_scan_only(ips_to_scan, top_ports=100, timeout=30)
                            open_ports = port_results.get('open_ports', [])
                            logging.info(f"🔌 ASSETS: Naabu completed, found {len(open_ports)} open ports")

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
                            logging.warning(f"🔌 ASSETS: Naabu port scanning failed: {str(port_error)}")
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
                'scan_source': 'subfinder_naabu'
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
            # Update existing domain asset with port information
            existing_metadata = main_domain_asset.asset_metadata or {}
            existing_metadata['ports'] = domain_ports
            existing_metadata['scan_source'] = 'subfinder_naabu'
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
                # Create new subdomain asset with port information
                asset_metadata = {
                    'ports': ports_info,
                    'scan_source': 'subfinder_naabu'
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
                # Update existing asset with new port information and last scanned time
                existing_metadata = existing_asset.asset_metadata or {}
                existing_metadata['ports'] = ports_info
                existing_metadata['scan_source'] = 'subfinder_naabu'
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
                # Create new subdomain asset
                subdomain_asset = Asset(
                    name=subdomain,
                    asset_type=AssetType.SUBDOMAIN,
                    description=f"Subdomain discovered via simulated Subfinder scan of {domain}",
                    organization_id=organization_id,
                    discovered_at=datetime.utcnow(),
                    last_scanned=datetime.utcnow()
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
    """Simulate the scanning process with Subfinder, Naabu, and Nuclei"""
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

        # Naabu phase
        scan_status[scan_id]['message'] = 'Running Naabu (port scanning)...'
        for progress in range(0, 101, 25):
            scan_status[scan_id]['progress']['naabu'] = progress
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
