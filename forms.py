from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError
from models import User

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
