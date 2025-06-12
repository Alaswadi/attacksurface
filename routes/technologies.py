"""
Technologies Discovery and Analysis API Routes
"""

from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user
from models import db, Asset, Organization
from sqlalchemy import func
import logging
import json
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

technologies_bp = Blueprint('technologies', __name__, url_prefix='/api/technologies')

def process_technology_data(assets):
    """Process asset metadata to extract technology information"""
    tech_data = {
        'technologies': defaultdict(lambda: {
            'name': '',
            'category': '',
            'assets': [],
            'versions': Counter(),
            'total_count': 0
        }),
        'categories': defaultdict(int),
        'total_assets': len(assets),
        'assets_with_tech': 0,
        'web_servers': defaultdict(int),
        'frameworks': defaultdict(int),
        'cms_platforms': defaultdict(int),
        'databases': defaultdict(int),
        'programming_languages': defaultdict(int)
    }
    
    # Technology categorization mapping
    tech_categories = {
        # Web Servers
        'apache': 'Web Server',
        'nginx': 'Web Server', 
        'iis': 'Web Server',
        'microsoft-iis': 'Web Server',
        'lighttpd': 'Web Server',
        'caddy': 'Web Server',
        
        # Frameworks
        'react': 'JavaScript Framework',
        'vue': 'JavaScript Framework',
        'angular': 'JavaScript Framework',
        'jquery': 'JavaScript Library',
        'bootstrap': 'CSS Framework',
        'tailwind': 'CSS Framework',
        'express': 'Backend Framework',
        'django': 'Backend Framework',
        'flask': 'Backend Framework',
        'laravel': 'Backend Framework',
        'symfony': 'Backend Framework',
        'spring': 'Backend Framework',
        
        # CMS Platforms
        'wordpress': 'CMS',
        'drupal': 'CMS',
        'joomla': 'CMS',
        'magento': 'E-commerce',
        'shopify': 'E-commerce',
        'woocommerce': 'E-commerce',
        
        # Programming Languages
        'php': 'Programming Language',
        'python': 'Programming Language',
        'java': 'Programming Language',
        'nodejs': 'Programming Language',
        'node.js': 'Programming Language',
        'ruby': 'Programming Language',
        'go': 'Programming Language',
        'dotnet': 'Programming Language',
        '.net': 'Programming Language',
        
        # Databases
        'mysql': 'Database',
        'postgresql': 'Database',
        'mongodb': 'Database',
        'redis': 'Database',
        'elasticsearch': 'Database',
        
        # CDN & Services
        'cloudflare': 'CDN/Security',
        'aws': 'Cloud Service',
        'google': 'Cloud Service',
        'azure': 'Cloud Service'
    }
    
    for asset in assets:
        if not asset.asset_metadata:
            continue
            
        http_probe = asset.asset_metadata.get('http_probe', {})
        if not http_probe:
            continue
            
        tech_data['assets_with_tech'] += 1
        
        # Extract technologies from httpx tech detection
        technologies = http_probe.get('tech', [])
        webserver = http_probe.get('webserver', '')
        
        # Process detected technologies
        for tech in technologies:
            if not tech:
                continue
                
            tech_lower = tech.lower()
            category = tech_categories.get(tech_lower, 'Other')
            
            tech_data['technologies'][tech_lower]['name'] = tech
            tech_data['technologies'][tech_lower]['category'] = category
            tech_data['technologies'][tech_lower]['assets'].append({
                'id': asset.id,
                'name': asset.name,
                'asset_type': asset.asset_type.value,
                'url': http_probe.get('url', ''),
                'status_code': http_probe.get('status_code', 0),
                'title': http_probe.get('title', '')
            })
            tech_data['technologies'][tech_lower]['total_count'] += 1
            tech_data['categories'][category] += 1
            
            # Categorize for summary stats
            if category == 'Web Server':
                tech_data['web_servers'][tech] += 1
            elif 'Framework' in category or 'Library' in category:
                tech_data['frameworks'][tech] += 1
            elif category == 'CMS':
                tech_data['cms_platforms'][tech] += 1
            elif category == 'Database':
                tech_data['databases'][tech] += 1
            elif category == 'Programming Language':
                tech_data['programming_languages'][tech] += 1
        
        # Process webserver information
        if webserver:
            # Extract server name and version
            server_parts = webserver.split('/')
            server_name = server_parts[0].lower()
            server_version = server_parts[1] if len(server_parts) > 1 else 'Unknown'
            
            if server_name:
                category = 'Web Server'
                tech_data['technologies'][server_name]['name'] = server_parts[0]
                tech_data['technologies'][server_name]['category'] = category
                tech_data['technologies'][server_name]['versions'][server_version] += 1
                tech_data['technologies'][server_name]['assets'].append({
                    'id': asset.id,
                    'name': asset.name,
                    'asset_type': asset.asset_type.value,
                    'url': http_probe.get('url', ''),
                    'status_code': http_probe.get('status_code', 0),
                    'title': http_probe.get('title', ''),
                    'version': server_version
                })
                tech_data['technologies'][server_name]['total_count'] += 1
                tech_data['categories'][category] += 1
                tech_data['web_servers'][server_parts[0]] += 1
    
    # Convert defaultdicts to regular dicts for JSON serialization
    result = {
        'technologies': dict(tech_data['technologies']),
        'categories': dict(tech_data['categories']),
        'summary_stats': {
            'total_assets': tech_data['total_assets'],
            'assets_with_tech': tech_data['assets_with_tech'],
            'unique_technologies': len(tech_data['technologies']),
            'web_servers': dict(tech_data['web_servers']),
            'frameworks': dict(tech_data['frameworks']),
            'cms_platforms': dict(tech_data['cms_platforms']),
            'databases': dict(tech_data['databases']),
            'programming_languages': dict(tech_data['programming_languages'])
        }
    }
    
    # Convert Counter objects to dicts
    for tech_name, tech_info in result['technologies'].items():
        if hasattr(tech_info['versions'], 'items'):
            tech_info['versions'] = dict(tech_info['versions'])
    
    return result

@technologies_bp.route('/overview', methods=['GET'])
@login_required
def get_technologies_overview():
    """Get overview of all discovered technologies"""
    try:
        # Get user's organization
        from utils.permissions import get_user_organization
        organization = get_user_organization()
        if not organization:
            return jsonify({
                'success': False,
                'error': 'No organization found for user'
            }), 400

        # Get all assets with technology data
        assets = Asset.query.filter_by(organization_id=organization.id).all()
        
        # Process technology data
        tech_summary = process_technology_data(assets)
        
        return jsonify({
            'success': True,
            'data': tech_summary
        })
        
    except Exception as e:
        logger.error(f"Error getting technologies overview: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@technologies_bp.route('/filter', methods=['POST'])
@login_required
def filter_technologies():
    """Filter technologies based on criteria"""
    try:
        data = request.get_json()

        # Get user's organization
        from utils.permissions import get_user_organization
        organization = get_user_organization()
        if not organization:
            return jsonify({
                'success': False,
                'error': 'No organization found for user'
            }), 400

        # Get filter criteria
        tech_name = data.get('technology', '').lower()
        category = data.get('category', '')
        version = data.get('version', '')
        
        # Get all assets
        assets = Asset.query.filter_by(organization_id=organization.id).all()
        
        # Process and filter technology data
        tech_data = process_technology_data(assets)
        
        # Apply filters
        filtered_results = {}
        
        for tech_key, tech_info in tech_data['technologies'].items():
            include_tech = True
            
            # Filter by technology name
            if tech_name and tech_name not in tech_key:
                include_tech = False
            
            # Filter by category
            if category and tech_info['category'] != category:
                include_tech = False
            
            # Filter by version
            if version and version not in tech_info.get('versions', {}):
                include_tech = False
            
            if include_tech:
                filtered_results[tech_key] = tech_info
        
        return jsonify({
            'success': True,
            'data': {
                'technologies': filtered_results,
                'total_matches': len(filtered_results),
                'filters_applied': {
                    'technology': tech_name,
                    'category': category,
                    'version': version
                }
            }
        })
        
    except Exception as e:
        logger.error(f"Error filtering technologies: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@technologies_bp.route('/assets/<technology>', methods=['GET'])
@login_required
def get_assets_by_technology(technology):
    """Get all assets using a specific technology"""
    try:
        # Get user's organization
        from utils.permissions import get_user_organization
        organization = get_user_organization()
        if not organization:
            return jsonify({
                'success': False,
                'error': 'No organization found for user'
            }), 400

        # Get all assets
        assets = Asset.query.filter_by(organization_id=organization.id).all()
        
        # Process technology data
        tech_data = process_technology_data(assets)
        
        # Get assets for specific technology
        tech_lower = technology.lower()
        tech_info = tech_data['technologies'].get(tech_lower, {})
        
        if not tech_info:
            return jsonify({
                'success': True,
                'data': {
                    'technology': technology,
                    'assets': [],
                    'total_count': 0
                }
            })
        
        return jsonify({
            'success': True,
            'data': {
                'technology': tech_info.get('name', technology),
                'category': tech_info.get('category', 'Unknown'),
                'assets': tech_info.get('assets', []),
                'total_count': tech_info.get('total_count', 0),
                'versions': tech_info.get('versions', {})
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting assets by technology: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
