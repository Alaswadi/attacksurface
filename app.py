from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
from config import config
from models import db, User, Organization, Asset, Vulnerability, Alert, AssetType, SeverityLevel, AlertType
from forms import LoginForm, RegisterForm
import os
from datetime import datetime, timedelta
import random

def create_app(config_name=None):
    app = Flask(__name__)
    
    if config_name is None:
        config_name = os.environ.get('FLASK_CONFIG', 'default')
    
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    db.init_app(app)
    migrate = Migrate(app, db)
    
    # Initialize Flask-Login
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    # Routes
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('auth.login'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        # Get user's organization
        org = Organization.query.filter_by(user_id=current_user.id).first()
        if not org:
            # Create default organization for user
            org = Organization(name=f"{current_user.username}'s Organization", user_id=current_user.id)
            db.session.add(org)
            db.session.commit()
        
        # Get dashboard data
        assets = Asset.query.filter_by(organization_id=org.id, is_active=True).all()
        vulnerabilities = Vulnerability.query.filter_by(organization_id=org.id, is_resolved=False).all()
        alerts = Alert.query.filter_by(organization_id=org.id, is_resolved=False).order_by(Alert.created_at.desc()).limit(10).all()
        
        # Calculate metrics
        total_assets = len(assets)
        critical_vulns = len([v for v in vulnerabilities if v.severity == SeverityLevel.CRITICAL])
        active_alerts = len(alerts)
        
        # Asset breakdown
        asset_counts = {
            'domains': len([a for a in assets if a.asset_type == AssetType.DOMAIN]),
            'subdomains': len([a for a in assets if a.asset_type == AssetType.SUBDOMAIN]),
            'ip_addresses': len([a for a in assets if a.asset_type == AssetType.IP_ADDRESS]),
            'cloud_resources': len([a for a in assets if a.asset_type == AssetType.CLOUD_RESOURCE])
        }
        
        # Recent discoveries (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recent_assets = Asset.query.filter(
            Asset.organization_id == org.id,
            Asset.discovered_at >= week_ago
        ).order_by(Asset.discovered_at.desc()).limit(4).all()
        
        # Vulnerability chart data (last 7 days)
        chart_data = generate_vulnerability_chart_data(org.id)
        
        return render_template('dashboard.html',
                             total_assets=total_assets,
                             critical_vulns=critical_vulns,
                             active_alerts=active_alerts,
                             asset_counts=asset_counts,
                             recent_assets=recent_assets,
                             alerts=alerts,
                             chart_data=chart_data)
    
    # Authentication routes
    from routes.auth import auth_bp
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    # API routes
    from routes.api import api_bp
    app.register_blueprint(api_bp, url_prefix='/api')
    
    return app

def generate_vulnerability_chart_data(org_id):
    """Generate sample vulnerability chart data"""
    dates = []
    for i in range(7):
        date = datetime.utcnow() - timedelta(days=6-i)
        dates.append(date.strftime("%b %d"))
    
    # Sample data - in production, this would query actual vulnerability data
    data = {
        'dates': dates,
        'critical': [2, 3, 5, 4, 6, 5, 4],
        'high': [8, 10, 9, 11, 13, 15, 12],
        'medium': [18, 16, 19, 15, 17, 14, 16],
        'low': [25, 22, 20, 18, 21, 23, 25]
    }
    return data

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
        
        # Create sample data if no users exist
        if User.query.count() == 0:
            create_sample_data()
    
    app.run(debug=True)

def create_sample_data():
    """Create sample data for demonstration"""
    # Create sample user
    user = User(username='admin', email='admin@example.com')
    user.set_password('password')
    db.session.add(user)
    db.session.commit()
    
    # Create organization
    org = Organization(name='Sample Organization', user_id=user.id)
    db.session.add(org)
    db.session.commit()
    
    # Create sample assets
    assets_data = [
        ('example.com', AssetType.DOMAIN),
        ('api.example.com', AssetType.SUBDOMAIN),
        ('admin.example.com', AssetType.SUBDOMAIN),
        ('192.168.1.100', AssetType.IP_ADDRESS),
        ('10.0.0.50', AssetType.IP_ADDRESS),
        ('EC2-instance-1', AssetType.CLOUD_RESOURCE)
    ]
    
    for name, asset_type in assets_data:
        asset = Asset(name=name, asset_type=asset_type, organization_id=org.id)
        db.session.add(asset)
    
    db.session.commit()
    
    # Create sample vulnerabilities and alerts
    assets = Asset.query.filter_by(organization_id=org.id).all()
    
    # Sample vulnerabilities
    vuln1 = Vulnerability(
        title='SSL Certificate Expiring Soon',
        description='SSL certificate will expire in 3 days',
        severity=SeverityLevel.CRITICAL,
        asset_id=assets[0].id,
        organization_id=org.id
    )
    
    vuln2 = Vulnerability(
        title='Open Database Port',
        description='MongoDB port 27017 is publicly accessible',
        severity=SeverityLevel.HIGH,
        asset_id=assets[3].id,
        organization_id=org.id
    )
    
    db.session.add_all([vuln1, vuln2])
    
    # Sample alerts
    alert1 = Alert(
        title='Critical: SSL Certificate Expiring',
        description='The SSL certificate for payments.example.com will expire in 3 days.',
        alert_type=AlertType.CERTIFICATE_EXPIRY,
        severity=SeverityLevel.CRITICAL,
        organization_id=org.id,
        asset_id=assets[0].id
    )
    
    alert2 = Alert(
        title='High: Open Database Port Detected',
        description='MongoDB port 27017 is publicly accessible without authentication.',
        alert_type=AlertType.VULNERABILITY,
        severity=SeverityLevel.HIGH,
        organization_id=org.id,
        asset_id=assets[3].id
    )
    
    alert3 = Alert(
        title='Info: New Asset Discovered',
        description='New subdomain staging-api.example.com discovered.',
        alert_type=AlertType.NEW_ASSET,
        severity=SeverityLevel.INFO,
        organization_id=org.id
    )
    
    db.session.add_all([alert1, alert2, alert3])
    db.session.commit()
    
    print("Sample data created successfully!")
    print("Login with username: admin, password: password")
