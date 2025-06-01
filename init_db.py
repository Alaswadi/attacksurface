#!/usr/bin/env python3
"""
Database initialization script for Attack Surface Discovery
This script creates all database tables and sample data
"""

import os
import sys
from flask import Flask
from models import db, User, Organization, Asset, Vulnerability, Alert, AssetType, SeverityLevel, AlertType
from config import config
from datetime import datetime, timedelta

def create_app():
    """Create Flask app for database initialization"""
    app = Flask(__name__)
    
    # Use production config for Docker
    config_name = os.environ.get('FLASK_CONFIG', 'production')
    app.config.from_object(config[config_name])
    
    # Initialize database
    db.init_app(app)
    
    return app

def init_database():
    """Initialize database with tables and sample data"""
    app = create_app()
    
    with app.app_context():
        try:
            print("🔄 Initializing database...")
            
            # Create all tables
            db.create_all()
            print("✅ Database tables created successfully")
            
            # Check if admin user already exists
            if User.query.filter_by(username='admin').first():
                print("ℹ️  Admin user already exists, skipping sample data creation")
                return
            
            # Create sample data
            create_sample_data()
            print("✅ Sample data created successfully")
            
        except Exception as e:
            print(f"❌ Error initializing database: {e}")
            sys.exit(1)

def create_sample_data():
    """Create sample data for demonstration"""
    print("🔄 Creating sample data...")
    
    # Create admin user
    admin_user = User(username='admin', email='admin@attacksurface.com')
    admin_user.set_password('password')
    db.session.add(admin_user)
    db.session.commit()
    print("✅ Admin user created (username: admin, password: password)")
    
    # Create organization
    org = Organization(name='Attack Surface Discovery Demo', user_id=admin_user.id)
    db.session.add(org)
    db.session.commit()
    print("✅ Organization created")
    
    # Create sample assets
    assets_data = [
        ('example.com', AssetType.DOMAIN, 'Primary domain'),
        ('api.example.com', AssetType.SUBDOMAIN, 'API endpoint'),
        ('admin.example.com', AssetType.SUBDOMAIN, 'Admin panel'),
        ('staging.example.com', AssetType.SUBDOMAIN, 'Staging environment'),
        ('192.168.1.100', AssetType.IP_ADDRESS, 'Web server'),
        ('10.0.0.50', AssetType.IP_ADDRESS, 'Database server'),
        ('EC2-web-server-1', AssetType.CLOUD_RESOURCE, 'AWS EC2 instance'),
        ('S3-backup-bucket', AssetType.CLOUD_RESOURCE, 'AWS S3 bucket'),
        ('nginx-service', AssetType.SERVICE, 'Web server service'),
        ('postgresql-service', AssetType.SERVICE, 'Database service')
    ]
    
    assets = []
    for name, asset_type, description in assets_data:
        asset = Asset(
            name=name, 
            asset_type=asset_type, 
            description=description,
            organization_id=org.id,
            last_scanned=datetime.utcnow() - timedelta(hours=random.randint(1, 24))
        )
        assets.append(asset)
        db.session.add(asset)
    
    db.session.commit()
    print(f"✅ {len(assets)} sample assets created")
    
    # Create sample vulnerabilities
    vulnerabilities_data = [
        ('SSL Certificate Expiring Soon', 'SSL certificate will expire in 3 days', SeverityLevel.CRITICAL, 0),
        ('Open Database Port', 'MongoDB port 27017 is publicly accessible', SeverityLevel.HIGH, 5),
        ('Outdated Software Version', 'Nginx version is outdated and has known vulnerabilities', SeverityLevel.MEDIUM, 8),
        ('Missing Security Headers', 'X-Frame-Options header is missing', SeverityLevel.LOW, 1),
        ('Weak SSL Configuration', 'SSL configuration allows weak ciphers', SeverityLevel.MEDIUM, 0),
        ('Directory Listing Enabled', 'Directory listing is enabled on web server', SeverityLevel.LOW, 4)
    ]
    
    for title, description, severity, asset_index in vulnerabilities_data:
        vuln = Vulnerability(
            title=title,
            description=description,
            severity=severity,
            asset_id=assets[asset_index].id,
            organization_id=org.id,
            discovered_at=datetime.utcnow() - timedelta(days=random.randint(1, 30))
        )
        db.session.add(vuln)
    
    db.session.commit()
    print(f"✅ {len(vulnerabilities_data)} sample vulnerabilities created")
    
    # Create sample alerts
    alerts_data = [
        ('Critical: SSL Certificate Expiring', 'The SSL certificate for example.com will expire in 3 days.', 
         AlertType.CERTIFICATE_EXPIRY, SeverityLevel.CRITICAL, 0),
        ('High: Open Database Port Detected', 'MongoDB port 27017 is publicly accessible without authentication.', 
         AlertType.VULNERABILITY, SeverityLevel.HIGH, 5),
        ('Medium: Outdated Software Detected', 'Nginx version is outdated and should be updated.', 
         AlertType.VULNERABILITY, SeverityLevel.MEDIUM, 8),
        ('Info: New Asset Discovered', 'New subdomain staging.example.com discovered during scan.', 
         AlertType.NEW_ASSET, SeverityLevel.INFO, 3),
        ('Low: Security Header Missing', 'X-Frame-Options header is missing from web responses.', 
         AlertType.VULNERABILITY, SeverityLevel.LOW, 1)
    ]
    
    for title, description, alert_type, severity, asset_index in alerts_data:
        alert = Alert(
            title=title,
            description=description,
            alert_type=alert_type,
            severity=severity,
            organization_id=org.id,
            asset_id=assets[asset_index].id,
            created_at=datetime.utcnow() - timedelta(hours=random.randint(1, 72))
        )
        db.session.add(alert)
    
    db.session.commit()
    print(f"✅ {len(alerts_data)} sample alerts created")

if __name__ == '__main__':
    import random
    init_database()
    print("\n🎉 Database initialization completed!")
    print("\nYou can now log in with:")
    print("  Username: admin")
    print("  Password: password")
