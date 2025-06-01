from flask import Blueprint, jsonify, request, render_template, make_response
from flask_login import login_required, current_user
from models import db, Organization, Asset, Vulnerability, Alert, AssetType, SeverityLevel
from datetime import datetime, timedelta
import json
import uuid
import threading
import time
import random

api_bp = Blueprint('api', __name__)

# In-memory storage for scan results (in production, use Redis or database)
scan_results = {}
scan_status = {}

@api_bp.route('/assets', methods=['GET'])
@login_required
def get_assets():
    """Get all assets for the current user's organization"""
    org = Organization.query.filter_by(user_id=current_user.id).first()
    if not org:
        return jsonify({'error': 'Organization not found'}), 404
    
    assets = Asset.query.filter_by(organization_id=org.id, is_active=True).all()
    
    assets_data = []
    for asset in assets:
        assets_data.append({
            'id': asset.id,
            'name': asset.name,
            'type': asset.asset_type.value,
            'description': asset.description,
            'discovered_at': asset.discovered_at.isoformat(),
            'last_scanned': asset.last_scanned.isoformat() if asset.last_scanned else None
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
            {'host': domain, 'port': 443, 'service': 'https'},
            {'host': f'api.{domain}', 'port': 8080, 'service': 'http-alt'},
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
