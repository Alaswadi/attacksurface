#!/usr/bin/env python3
"""
Add test assets to the database for testing the assets page
"""

from app import create_app
from models import db, User, Organization, Asset, AssetType
from datetime import datetime, timedelta
import random

def add_test_assets():
    """Add test assets to the database"""
    app = create_app()
    
    with app.app_context():
        # Get the admin user
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            print("❌ Admin user not found. Please create admin user first.")
            return
        
        # Get or create organization
        org = Organization.query.filter_by(user_id=admin_user.id).first()
        if not org:
            org = Organization(name=f"{admin_user.username}'s Organization", user_id=admin_user.id)
            db.session.add(org)
            db.session.commit()
            print("✅ Organization created")
        
        # Check if assets already exist
        existing_assets = Asset.query.filter_by(organization_id=org.id).count()
        if existing_assets > 0:
            print(f"ℹ️  {existing_assets} assets already exist")
            return
        
        # Create test assets with metadata
        test_assets = [
            {
                'name': 'example.com',
                'type': AssetType.DOMAIN,
                'description': 'Primary domain',
                'metadata': {
                    'http_probe': {
                        'status_code': 200,
                        'url': 'https://example.com',
                        'tech': ['Apache', 'PHP'],
                        'webserver': 'Apache/2.4.41'
                    },
                    'ports': [
                        {'port': 80, 'service': 'http'},
                        {'port': 443, 'service': 'https'},
                        {'port': 22, 'service': 'ssh'}
                    ]
                }
            },
            {
                'name': 'api.example.com',
                'type': AssetType.SUBDOMAIN,
                'description': 'API endpoint',
                'metadata': {
                    'http_probe': {
                        'status_code': 200,
                        'url': 'https://api.example.com',
                        'tech': ['Nginx', 'Node.js', 'Express'],
                        'webserver': 'nginx/1.18.0'
                    },
                    'ports': [
                        {'port': 80, 'service': 'http'},
                        {'port': 443, 'service': 'https'}
                    ]
                }
            },
            {
                'name': 'admin.example.com',
                'type': AssetType.SUBDOMAIN,
                'description': 'Admin panel',
                'metadata': {
                    'http_probe': {
                        'status_code': 403,
                        'url': 'https://admin.example.com',
                        'tech': ['Apache', 'WordPress'],
                        'webserver': 'Apache/2.4.41'
                    },
                    'ports': [
                        {'port': 80, 'service': 'http'},
                        {'port': 443, 'service': 'https'}
                    ]
                }
            },
            {
                'name': 'staging.example.com',
                'type': AssetType.SUBDOMAIN,
                'description': 'Staging environment',
                'metadata': {
                    'http_probe': {
                        'status_code': 500,
                        'url': 'https://staging.example.com',
                        'tech': ['Nginx', 'Python', 'Django'],
                        'webserver': 'nginx/1.18.0'
                    },
                    'ports': [
                        {'port': 80, 'service': 'http'},
                        {'port': 443, 'service': 'https'},
                        {'port': 8000, 'service': 'django'}
                    ]
                }
            },
            {
                'name': '192.168.1.100',
                'type': AssetType.IP_ADDRESS,
                'description': 'Web server',
                'metadata': {
                    'ports': [
                        {'port': 22, 'service': 'ssh'},
                        {'port': 80, 'service': 'http'},
                        {'port': 443, 'service': 'https'},
                        {'port': 3306, 'service': 'mysql'}
                    ]
                }
            },
            {
                'name': '10.0.0.50',
                'type': AssetType.IP_ADDRESS,
                'description': 'Database server',
                'metadata': {
                    'ports': [
                        {'port': 22, 'service': 'ssh'},
                        {'port': 5432, 'service': 'postgresql'},
                        {'port': 6379, 'service': 'redis'}
                    ]
                }
            },
            {
                'name': 'EC2-web-server-1',
                'type': AssetType.CLOUD_RESOURCE,
                'description': 'AWS EC2 instance',
                'metadata': {}
            },
            {
                'name': 'S3-backup-bucket',
                'type': AssetType.CLOUD_RESOURCE,
                'description': 'AWS S3 bucket',
                'metadata': {}
            },
            {
                'name': 'nginx-service',
                'type': AssetType.SERVICE,
                'description': 'Web server service',
                'metadata': {}
            },
            {
                'name': 'postgresql-service',
                'type': AssetType.SERVICE,
                'description': 'Database service',
                'metadata': {}
            }
        ]
        
        # Create assets
        created_count = 0
        for asset_data in test_assets:
            asset = Asset(
                name=asset_data['name'],
                asset_type=asset_data['type'],
                description=asset_data['description'],
                organization_id=org.id,
                last_scanned=datetime.utcnow() - timedelta(hours=random.randint(1, 24)),
                asset_metadata=asset_data['metadata']
            )
            db.session.add(asset)
            created_count += 1
        
        db.session.commit()
        print(f"✅ {created_count} test assets created successfully!")
        print("\nAssets created:")
        for asset_data in test_assets:
            print(f"  • {asset_data['name']} ({asset_data['type'].value})")

if __name__ == '__main__':
    add_test_assets()
