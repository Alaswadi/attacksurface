from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime
import enum

db = SQLAlchemy()
bcrypt = Bcrypt()

class UserRole(enum.Enum):
    ADMIN = "admin"
    VIEWER = "viewer"

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    is_email_verified = db.Column(db.Boolean, default=False)

    # Relationships
    organizations = db.relationship('Organization', backref='owner', lazy=True)
    organization_memberships = db.relationship('OrganizationUser', backref='user', lazy=True)
    invitations = db.relationship('UserInvitation', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Organization(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    primary_domain = db.Column(db.String(255))
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Note: updated_at column will be added manually if needed
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # Relationships
    assets = db.relationship('Asset', backref='organization', lazy=True, cascade='all, delete-orphan')
    vulnerabilities = db.relationship('Vulnerability', backref='organization', lazy=True, cascade='all, delete-orphan')
    alerts = db.relationship('Alert', backref='organization', lazy=True, cascade='all, delete-orphan')
    users = db.relationship('OrganizationUser', backref='organization', lazy=True, cascade='all, delete-orphan')
    email_config = db.relationship('EmailConfiguration', backref='organization', uselist=False, cascade='all, delete-orphan')

class AssetType(enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    CLOUD_RESOURCE = "cloud_resource"
    SERVICE = "service"

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    asset_type = db.Column(db.Enum(AssetType), nullable=False)
    description = db.Column(db.Text)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_scanned = db.Column(db.DateTime)
    is_active = db.Column(db.Boolean, default=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    
    # Additional metadata as JSON
    asset_metadata = db.Column(db.JSON)
    
    # Relationships
    vulnerabilities = db.relationship('Vulnerability', backref='asset', lazy=True)

class SeverityLevel(enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Vulnerability(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(20))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.Enum(SeverityLevel), nullable=False)
    discovered_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_resolved = db.Column(db.Boolean, default=False)
    resolved_at = db.Column(db.DateTime)

    # Validation fields (simplified - no confidence scoring)
    is_validated = db.Column(db.Boolean, default=True, nullable=True)  # Whether it passed validation
    validation_notes = db.Column(db.Text, nullable=True)  # Notes about validation status
    template_name = db.Column(db.String(255), nullable=True)  # Nuclei template that found this
    cvss_score = db.Column(db.Float, nullable=True)  # CVSS score if available

    # Additional metadata as JSON (for storing raw scan data)
    asset_metadata = db.Column(db.JSON, nullable=True)

    # Foreign keys
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)

class AlertType(enum.Enum):
    VULNERABILITY = "vulnerability"
    NEW_ASSET = "new_asset"
    CERTIFICATE_EXPIRY = "certificate_expiry"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    CONFIGURATION_CHANGE = "configuration_change"

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    alert_type = db.Column(db.Enum(AlertType), nullable=False)
    severity = db.Column(db.Enum(SeverityLevel), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    is_resolved = db.Column(db.Boolean, default=False)
    
    # Foreign keys
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=True)

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_type = db.Column(db.String(50), nullable=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    status = db.Column(db.String(20), default='running')  # running, completed, failed
    results = db.Column(db.JSON)

    # Foreign keys
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=True)

class OrganizationUser(db.Model):
    """Many-to-many relationship between users and organizations with roles"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    __table_args__ = (db.UniqueConstraint('user_id', 'organization_id'),)

    def has_permission(self, permission):
        """Check if user has specific permission based on role"""
        if self.role == UserRole.ADMIN:
            return True
        elif self.role == UserRole.VIEWER:
            return permission in ['view_assets', 'view_vulnerabilities', 'view_technologies', 'view_reports']
        return False

    def can_view_assets(self):
        return self.has_permission('view_assets')

    def can_add_assets(self):
        return self.has_permission('add_assets')

    def can_run_scans(self):
        return self.has_permission('run_scans')

    def can_view_reports(self):
        return self.has_permission('view_reports')

    def can_manage_settings(self):
        return self.has_permission('manage_settings')

    def can_view_vulnerabilities(self):
        return self.has_permission('view_vulnerabilities')

    def can_view_technologies(self):
        return self.has_permission('view_technologies')

class UserInvitation(db.Model):
    """User invitations for organizations"""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    invited_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    token = db.Column(db.String(255), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    accepted_at = db.Column(db.DateTime)
    is_accepted = db.Column(db.Boolean, default=False)



    # Relationships
    invited_by = db.relationship('User', foreign_keys=[invited_by_id], overlaps="invitations,user")
    organization = db.relationship('Organization')

class EmailConfiguration(db.Model):
    """Email configuration for organizations"""
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)

    # SMTP Configuration
    smtp_host = db.Column(db.String(255))
    smtp_port = db.Column(db.Integer, default=587)
    smtp_username = db.Column(db.String(255))
    smtp_password = db.Column(db.String(255))  # Should be encrypted
    smtp_use_tls = db.Column(db.Boolean, default=True)
    smtp_use_ssl = db.Column(db.Boolean, default=False)

    # Email Settings
    from_email = db.Column(db.String(255))
    from_name = db.Column(db.String(255))
    reply_to = db.Column(db.String(255))

    # Configuration status
    is_configured = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    last_test_at = db.Column(db.DateTime)
    last_test_status = db.Column(db.String(50))  # success, failed

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class EmailTemplate(db.Model):
    """Email templates for different event types"""
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)

    # Template details
    name = db.Column(db.String(100), nullable=False)
    event_type = db.Column(db.String(50), nullable=False)  # invitation, alert, report, scan_complete
    subject = db.Column(db.String(255), nullable=False)
    body_html = db.Column(db.Text)
    body_text = db.Column(db.Text)

    # Template status
    is_active = db.Column(db.Boolean, default=True)
    is_default = db.Column(db.Boolean, default=False)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    organization = db.relationship('Organization')

class EmailNotificationSettings(db.Model):
    """Email notification preferences for users"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)

    # Email settings
    notification_email = db.Column(db.String(255))  # Override email for notifications
    additional_recipients = db.Column(db.Text)  # Comma-separated additional emails

    # Notification preferences
    notify_new_vulnerabilities = db.Column(db.Boolean, default=True)
    notify_scan_completion = db.Column(db.Boolean, default=True)
    notify_new_assets = db.Column(db.Boolean, default=False)
    notify_user_activity = db.Column(db.Boolean, default=False)
    notify_reports = db.Column(db.Boolean, default=True)

    # Alert severity thresholds
    alert_critical = db.Column(db.Boolean, default=True)
    alert_high = db.Column(db.Boolean, default=True)
    alert_medium = db.Column(db.Boolean, default=True)
    alert_low = db.Column(db.Boolean, default=False)
    alert_info = db.Column(db.Boolean, default=False)

    # Digest settings
    digest_frequency = db.Column(db.String(20), default='daily')  # immediate, hourly, daily, weekly

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = db.relationship('User')
    organization = db.relationship('Organization')

    __table_args__ = (db.UniqueConstraint('user_id', 'organization_id'),)
