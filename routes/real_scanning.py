"""
Real Security Scanning API Routes
"""

from flask import Blueprint, request, jsonify, current_app
from flask_login import login_required, current_user
from services.real_scanning_service import RealScanningService
from models import db, Organization
import logging

logger = logging.getLogger(__name__)

real_scanning_bp = Blueprint('real_scanning', __name__, url_prefix='/api/scan')

# Initialize scanning service
scanning_service = RealScanningService()

@real_scanning_bp.route('/status', methods=['GET'])
@login_required
def get_scan_status():
    """Get status of security scanning tools"""
    try:
        status = scanning_service.get_tool_status()
        return jsonify({
            'success': True,
            'status': status
        })
    except Exception as e:
        logger.error(f"Error getting scan status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/test-tools', methods=['POST'])
@login_required
def test_tools():
    """Test all security tools"""
    try:
        results = scanning_service.test_tools()
        return jsonify({
            'success': True,
            'test_results': results
        })
    except Exception as e:
        logger.error(f"Error testing tools: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/domain', methods=['POST'])
@login_required
def scan_domain():
    """Start a domain scan"""
    try:
        data = request.get_json()
        
        if not data or 'domain' not in data:
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            }), 400
        
        domain = data['domain'].strip()
        scan_type = data.get('scan_type', 'quick')  # quick, deep, custom
        
        # Validate scan type
        if scan_type not in ['quick', 'deep', 'custom']:
            return jsonify({
                'success': False,
                'error': 'Invalid scan type. Must be: quick, deep, or custom'
            }), 400
        
        # Get user's organization
        organization = Organization.query.filter_by(user_id=current_user.id).first()
        if not organization:
            return jsonify({
                'success': False,
                'error': 'No organization found for user'
            }), 400
        
        # Start the scan
        logger.info(f"Starting {scan_type} scan for domain {domain} by user {current_user.username}")
        
        scan_results = scanning_service.scan_domain(
            domain=domain,
            organization_id=organization.id,
            scan_type=scan_type
        )
        
        return jsonify({
            'success': True,
            'scan_results': scan_results
        })
        
    except Exception as e:
        logger.error(f"Error scanning domain: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/subdomain', methods=['POST'])
@login_required
def scan_subdomains():
    """Scan for subdomains only"""
    try:
        data = request.get_json()
        
        if not data or 'domain' not in data:
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            }), 400
        
        domain = data['domain'].strip()
        
        # Get scan options
        options = data.get('options', {})
        
        # Perform subdomain scan
        results = scanning_service.scanner_manager.subdomain_scan_only(domain, **options)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error scanning subdomains: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/ports', methods=['POST'])
@login_required
def scan_ports():
    """Scan for open ports only"""
    try:
        data = request.get_json()
        
        if not data or 'targets' not in data:
            return jsonify({
                'success': False,
                'error': 'Targets are required'
            }), 400
        
        targets = data['targets']
        if not isinstance(targets, list):
            targets = [targets]
        
        # Get scan options
        options = data.get('options', {})
        
        # Perform port scan
        results = scanning_service.scanner_manager.port_scan_only(targets, **options)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error scanning ports: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/vulnerabilities', methods=['POST'])
@login_required
def scan_vulnerabilities():
    """Scan for vulnerabilities only"""
    try:
        data = request.get_json()
        
        if not data or 'targets' not in data:
            return jsonify({
                'success': False,
                'error': 'Targets are required'
            }), 400
        
        targets = data['targets']
        if not isinstance(targets, list):
            targets = [targets]
        
        # Get scan options
        options = data.get('options', {})
        
        # Perform vulnerability scan
        results = scanning_service.scanner_manager.vulnerability_scan_only(targets, **options)
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error scanning vulnerabilities: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/httpx', methods=['POST'])
@login_required
def scan_httpx():
    """Scan for HTTP services only"""
    try:
        data = request.get_json()

        if not data or 'targets' not in data:
            return jsonify({
                'success': False,
                'error': 'Targets are required'
            }), 400

        targets = data['targets']
        if not isinstance(targets, list):
            targets = [targets]

        # Get scan options
        options = data.get('options', {})

        # Perform HTTP probe
        results = scanning_service.scanner_manager.http_probe_only(targets, **options)

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        logger.error(f"Error performing HTTP probe: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/quick', methods=['POST'])
@login_required
def quick_scan():
    """Perform a quick scan (optimized for speed)"""
    try:
        data = request.get_json()
        
        if not data or 'domain' not in data:
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            }), 400
        
        domain = data['domain'].strip()
        
        # Get user's organization
        organization = Organization.query.filter_by(user_id=current_user.id).first()
        if not organization:
            return jsonify({
                'success': False,
                'error': 'No organization found for user'
            }), 400
        
        # Perform quick scan
        scan_results = scanning_service.scan_domain(
            domain=domain,
            organization_id=organization.id,
            scan_type='quick'
        )
        
        return jsonify({
            'success': True,
            'scan_results': scan_results
        })
        
    except Exception as e:
        logger.error(f"Error performing quick scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/deep', methods=['POST'])
@login_required
def deep_scan():
    """Perform a deep scan (comprehensive but slower)"""
    try:
        data = request.get_json()
        
        if not data or 'domain' not in data:
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            }), 400
        
        domain = data['domain'].strip()
        
        # Get user's organization
        organization = Organization.query.filter_by(user_id=current_user.id).first()
        if not organization:
            return jsonify({
                'success': False,
                'error': 'No organization found for user'
            }), 400
        
        # Perform deep scan
        scan_results = scanning_service.scan_domain(
            domain=domain,
            organization_id=organization.id,
            scan_type='deep'
        )
        
        return jsonify({
            'success': True,
            'scan_results': scan_results
        })
        
    except Exception as e:
        logger.error(f"Error performing deep scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@real_scanning_bp.route('/custom', methods=['POST'])
@login_required
def custom_scan():
    """Perform a custom scan with specific parameters"""
    try:
        data = request.get_json()
        
        if not data or 'domain' not in data:
            return jsonify({
                'success': False,
                'error': 'Domain is required'
            }), 400
        
        domain = data['domain'].strip()
        
        # Get user's organization
        organization = Organization.query.filter_by(user_id=current_user.id).first()
        if not organization:
            return jsonify({
                'success': False,
                'error': 'No organization found for user'
            }), 400
        
        # Get custom scan configuration
        scan_config = data.get('config', {})
        
        # Perform custom scan using scanner manager directly
        if scan_config:
            scan_results = scanning_service.scanner_manager.full_scan(domain, **scan_config)
            # Process results
            summary = scanning_service._process_scan_results(scan_results, organization.id)
        else:
            # Default to full scan
            scan_results = scanning_service.scan_domain(
                domain=domain,
                organization_id=organization.id,
                scan_type='custom'
            )
            summary = scan_results
        
        return jsonify({
            'success': True,
            'scan_results': summary
        })
        
    except Exception as e:
        logger.error(f"Error performing custom scan: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
