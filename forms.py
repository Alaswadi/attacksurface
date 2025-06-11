from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField, IntegerField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional, URL, NumberRange
from models import User, UserRole
import re

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat Password', validators=[
        DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please choose a different one.')

class AssetForm(FlaskForm):
    name = StringField('Asset Name', validators=[DataRequired()])
    asset_type = SelectField('Asset Type', choices=[
        ('domain', 'Domain'),
        ('subdomain', 'Subdomain'),
        ('ip_address', 'IP Address'),
        ('cloud_resource', 'Cloud Resource'),
        ('service', 'Service')
    ], validators=[DataRequired()])
    description = TextAreaField('Description')
    submit = SubmitField('Add Asset')

class ScanForm(FlaskForm):
    scan_type = SelectField('Scan Type', choices=[
        ('port_scan', 'Port Scan'),
        ('vulnerability_scan', 'Vulnerability Scan'),
        ('subdomain_enum', 'Subdomain Enumeration'),
        ('ssl_check', 'SSL Certificate Check')
    ], validators=[DataRequired()])
    target = StringField('Target', validators=[DataRequired()])
    submit = SubmitField('Start Scan')

# Custom validator for domain format
def validate_domain(form, field):
    if field.data:
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(domain_pattern, field.data):
            raise ValidationError('Please enter a valid domain name.')

class OrganizationSettingsForm(FlaskForm):
    """Form for organization general settings"""
    name = StringField('Organization Name', validators=[DataRequired(), Length(min=2, max=100)])
    primary_domain = StringField('Primary Domain', validators=[Optional(), validate_domain])
    description = TextAreaField('Description', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Save Organization Details')

class UserInvitationForm(FlaskForm):
    """Form for inviting users to organization"""
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    role = SelectField('Role', choices=[
        (UserRole.MEMBER.value, 'Member'),
        (UserRole.ADMIN.value, 'Admin'),
        (UserRole.VIEWER.value, 'Viewer')
    ], validators=[DataRequired()])

    # Permissions
    can_view_assets = BooleanField('View Assets', default=True)
    can_add_assets = BooleanField('Add Assets', default=True)
    can_run_scans = BooleanField('Run Scans', default=False)
    can_view_reports = BooleanField('View Reports', default=True)
    can_manage_settings = BooleanField('Manage Settings', default=False)

    submit = SubmitField('Send Invitation')

    def validate_email(self, email):
        # Check if user is already invited or is a member
        from models import User, UserInvitation, OrganizationUser
        from flask_login import current_user
        from flask import request

        # Get organization from current user (this will be set in the route)
        org_id = getattr(self, '_organization_id', None)
        if org_id:
            # Check if user already exists and is a member
            existing_user = User.query.filter_by(email=email.data).first()
            if existing_user:
                existing_membership = OrganizationUser.query.filter_by(
                    user_id=existing_user.id,
                    organization_id=org_id
                ).first()
                if existing_membership:
                    raise ValidationError('This user is already a member of your organization.')

            # Check if there's a pending invitation
            pending_invitation = UserInvitation.query.filter_by(
                email=email.data,
                organization_id=org_id,
                is_accepted=False
            ).first()
            if pending_invitation:
                raise ValidationError('An invitation has already been sent to this email address.')

class EmailConfigurationForm(FlaskForm):
    """Form for email SMTP configuration"""
    smtp_host = StringField('SMTP Host', validators=[DataRequired(), Length(max=255)])
    smtp_port = IntegerField('SMTP Port', validators=[DataRequired(), NumberRange(min=1, max=65535)], default=587)
    smtp_username = StringField('Username', validators=[DataRequired(), Length(max=255)])
    smtp_password = PasswordField('Password', validators=[DataRequired()])
    smtp_use_tls = BooleanField('Use TLS', default=True)
    smtp_use_ssl = BooleanField('Use SSL', default=False)

    from_email = StringField('From Email', validators=[DataRequired(), Email()])
    from_name = StringField('From Name', validators=[DataRequired(), Length(max=255)])
    reply_to = StringField('Reply To', validators=[Optional(), Email()])

    submit = SubmitField('Save Email Configuration')

class TestEmailForm(FlaskForm):
    """Form for testing email configuration"""
    test_email = StringField('Test Email Address', validators=[DataRequired(), Email()])
    submit = SubmitField('Send Test Email')
