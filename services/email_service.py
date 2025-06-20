"""
Email service for sending notifications and invitations
"""

import smtplib
import ssl
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Optional, Dict, Any
import logging
from datetime import datetime
import secrets
import string

from models import EmailConfiguration, EmailTemplate, UserInvitation, User, Organization, Asset, Vulnerability, EmailNotificationSettings
from flask import current_app, url_for, render_template_string, render_template

logger = logging.getLogger(__name__)

class EmailService:
    """Service for handling email operations"""
    
    def __init__(self, organization_id: int):
        self.organization_id = organization_id
        self.config = EmailConfiguration.query.filter_by(organization_id=organization_id).first()
    
    def is_configured(self) -> bool:
        """Check if email is properly configured"""
        return self.config and self.config.is_configured and all([
            self.config.smtp_host,
            self.config.smtp_port,
            self.config.smtp_username,
            self.config.smtp_password,
            self.config.from_email
        ])
    
    def test_connection(self) -> Dict[str, Any]:
        """Test email configuration"""
        if not self.is_configured():
            return {'success': False, 'error': 'Email not configured'}
        
        try:
            # Create SMTP connection
            if self.config.smtp_use_ssl:
                server = smtplib.SMTP_SSL(self.config.smtp_host, self.config.smtp_port)
            else:
                server = smtplib.SMTP(self.config.smtp_host, self.config.smtp_port)
                if self.config.smtp_use_tls:
                    server.starttls()
            
            # Login
            server.login(self.config.smtp_username, self.config.smtp_password)
            server.quit()
            
            # Update configuration status
            self.config.is_verified = True
            self.config.last_test_at = datetime.utcnow()
            self.config.last_test_status = 'success'
            
            from models import db
            db.session.commit()
            
            return {'success': True, 'message': 'Email configuration verified successfully'}
            
        except Exception as e:
            logger.error(f"Email test failed: {str(e)}")
            
            # Update configuration status
            if self.config:
                self.config.is_verified = False
                self.config.last_test_at = datetime.utcnow()
                self.config.last_test_status = 'failed'
                
                from models import db
                db.session.commit()
            
            return {'success': False, 'error': f'Email test failed: {str(e)}'}
    
    def send_email(self, to_emails: List[str], subject: str, body_html: str, 
                   body_text: str = None, attachments: List[Dict] = None) -> Dict[str, Any]:
        """Send email to recipients"""
        if not self.is_configured():
            return {'success': False, 'error': 'Email not configured'}
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = f"{self.config.from_name} <{self.config.from_email}>"
            msg['To'] = ', '.join(to_emails)
            
            if self.config.reply_to:
                msg['Reply-To'] = self.config.reply_to
            
            # Add text and HTML parts
            if body_text:
                text_part = MIMEText(body_text, 'plain')
                msg.attach(text_part)
            
            html_part = MIMEText(body_html, 'html')
            msg.attach(html_part)
            
            # Add attachments if any
            if attachments:
                for attachment in attachments:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment['data'])
                    encoders.encode_base64(part)
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= {attachment["filename"]}'
                    )
                    msg.attach(part)
            
            # Send email
            if self.config.smtp_use_ssl:
                server = smtplib.SMTP_SSL(self.config.smtp_host, self.config.smtp_port)
            else:
                server = smtplib.SMTP(self.config.smtp_host, self.config.smtp_port)
                if self.config.smtp_use_tls:
                    server.starttls()
            
            server.login(self.config.smtp_username, self.config.smtp_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email sent successfully to {', '.join(to_emails)}")
            return {'success': True, 'message': 'Email sent successfully'}
            
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")
            return {'success': False, 'error': f'Failed to send email: {str(e)}'}
    
    def send_test_email(self, test_email: str) -> Dict[str, Any]:
        """Send a test email"""
        subject = "Test Email from AttackSurfacePro"
        body_html = """
        <html>
        <body>
            <h2>Email Configuration Test</h2>
            <p>This is a test email to verify your email configuration is working correctly.</p>
            <p>If you received this email, your SMTP settings are configured properly.</p>
            <hr>
            <p><small>Sent from AttackSurfacePro at {timestamp}</small></p>
        </body>
        </html>
        """.format(timestamp=datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'))
        
        body_text = f"""
        Email Configuration Test
        
        This is a test email to verify your email configuration is working correctly.
        If you received this email, your SMTP settings are configured properly.
        
        Sent from AttackSurfacePro at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
        """
        
        return self.send_email([test_email], subject, body_html, body_text)
    
    def send_user_invitation(self, invitation: UserInvitation) -> Dict[str, Any]:
        """Send user invitation email"""
        try:
            # Get base URL dynamically for email links
            from flask import current_app, request

            # Try to get the base URL from the current request context
            try:
                if request:
                    base_url = f"{request.scheme}://{request.host}"
                else:
                    raise RuntimeError("No request context")
            except RuntimeError:
                # Fallback to configuration or environment variables
                server_name = current_app.config.get('SERVER_NAME') or os.environ.get('SERVER_NAME')
                scheme = current_app.config.get('PREFERRED_URL_SCHEME', 'https')

                if server_name:
                    base_url = f"{scheme}://{server_name}"
                else:
                    # Final fallback - use a generic URL
                    base_url = "https://your-domain.com"
                    logger.warning(f"Using fallback base URL for invitation email links: {base_url}")

            # Generate invitation URL
            invitation_url = f"{base_url}/auth/accept_invitation?token={invitation.token}"

            # Get organization details
            org = Organization.query.get(invitation.organization_id)
            invited_by = User.query.get(invitation.invited_by_id)

            subject = f"Invitation to join {org.name} on AttackSurfacePro"

            # Get or create email template
            template = EmailTemplate.query.filter_by(
                organization_id=self.organization_id,
                event_type='invitation',
                is_active=True
            ).first()

            # Prepare template context
            context = {
                'organization_name': org.name,
                'invited_by_name': invited_by.username,
                'invitation_url': invitation_url,
                'role': invitation.role.value.title(),
                'expires_at': invitation.expires_at.strftime('%Y-%m-%d'),
                'recipient_email': invitation.email,
                'current_year': datetime.utcnow().year,
                'unsubscribe_url': f"{base_url}/settings",
                'settings_url': f"{base_url}/settings",
                'logo_url': f"{base_url}/static/img/attacksurfaceproFull.png"
            }

            if template:
                body_html = render_template_string(template.body_html, **context)
                body_text = render_template_string(template.body_text or "", **context)
            else:
                # Use new professional template
                body_html = render_template('emails/user_invitation.html', **context)
                body_text = f"""
                You're invited to join {org.name}

                {invited_by.username} has invited you to join {org.name} on AttackSurfacePro.
                You will be added as a {invitation.role.value.title()}.

                Accept invitation: {invitation_url}

                This invitation expires on {invitation.expires_at.strftime('%Y-%m-%d')}.
                If you don't want to join this organization, you can ignore this email.
                """

            return self.send_email([invitation.email], subject, body_html, body_text)

        except Exception as e:
            logger.error(f"Failed to send invitation email: {str(e)}")
            return {'success': False, 'error': f'Failed to send invitation: {str(e)}'}

    def send_security_alert(self, alert_data: Dict[str, Any], recipients: List[str] = None) -> Dict[str, Any]:
        """Send security alert notification email"""
        try:
            if not recipients:
                # Get users who want security alert notifications
                notification_settings = EmailNotificationSettings.query.filter_by(
                    organization_id=self.organization_id,
                    notify_new_vulnerabilities=True
                ).all()
                recipients = [User.query.get(setting.user_id).email for setting in notification_settings]

            if not recipients:
                return {'success': False, 'error': 'No recipients configured for security alerts'}

            # Get organization details
            org = Organization.query.get(self.organization_id)

            # Get base URL dynamically for email links
            from flask import current_app, request

            # Try to get the base URL from the current request context
            try:
                if request:
                    base_url = f"{request.scheme}://{request.host}"
                else:
                    raise RuntimeError("No request context")
            except RuntimeError:
                # Fallback to configuration or environment variables
                server_name = current_app.config.get('SERVER_NAME') or os.environ.get('SERVER_NAME')
                scheme = current_app.config.get('PREFERRED_URL_SCHEME', 'https')

                if server_name:
                    base_url = f"{scheme}://{server_name}"
                else:
                    # Final fallback - use a generic URL
                    base_url = "https://your-domain.com"
                    logger.warning(f"Using fallback base URL for security alert email links: {base_url}")

            # Prepare template context
            context = {
                'alert_title': alert_data.get('title', 'Security Vulnerability Detected'),
                'alert_description': alert_data.get('description', ''),
                'severity': alert_data.get('severity', 'medium'),
                'detected_at': alert_data.get('detected_at', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')),
                'asset_name': alert_data.get('asset_name', ''),
                'vulnerability_details': alert_data.get('vulnerability_details', {}),
                'recommendations': alert_data.get('recommendations', []),
                'dashboard_url': f"{base_url}/dashboard",
                'organization_name': org.name,
                'summary': alert_data.get('summary', {}),
                'alert_id': alert_data.get('alert_id', ''),
                'generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'current_year': datetime.utcnow().year,
                'unsubscribe_url': f"{base_url}/settings",
                'settings_url': f"{base_url}/settings",
                'logo_url': f"{base_url}/static/img/attacksurfaceproFull.png"
            }

            subject = f"Security Alert: {alert_data.get('title', 'Vulnerability Detected')} - {org.name}"

            # Render email template
            body_html = render_template('emails/security_alert.html', **context)

            return self.send_email(recipients, subject, body_html)

        except Exception as e:
            logger.error(f"Failed to send security alert email: {str(e)}")
            return {'success': False, 'error': f'Failed to send security alert email: {str(e)}'}

    def send_scan_completion(self, scan_data: Dict[str, Any], recipients: List[str] = None) -> Dict[str, Any]:
        """Send scan completion notification email (always sent after scans)"""
        try:
            if not recipients:
                # Get users who want scan completion notifications
                notification_settings = EmailNotificationSettings.query.filter_by(
                    organization_id=self.organization_id,
                    notify_scan_completion=True
                ).all()

                recipients = []
                for setting in notification_settings:
                    user = User.query.get(setting.user_id)
                    if user:
                        email = setting.notification_email or user.email
                        recipients.append(email)
                        if setting.additional_recipients:
                            additional = [email.strip() for email in setting.additional_recipients.split(',') if email.strip()]
                            recipients.extend(additional)

            if not recipients:
                return {'success': False, 'error': 'No recipients configured for scan completion notifications'}

            # Get organization details
            org = Organization.query.get(self.organization_id)

            # Get base URL dynamically for email links
            from flask import current_app, request

            # Try to get the base URL from the current request context
            try:
                if request:
                    base_url = f"{request.scheme}://{request.host}"
                else:
                    raise RuntimeError("No request context")
            except RuntimeError:
                # Fallback to configuration or environment variables
                server_name = current_app.config.get('SERVER_NAME') or os.environ.get('SERVER_NAME')
                scheme = current_app.config.get('PREFERRED_URL_SCHEME', 'https')

                if server_name:
                    base_url = f"{scheme}://{server_name}"
                else:
                    # Final fallback - use a generic URL
                    base_url = "https://your-domain.com"
                    logger.warning(f"Using fallback base URL for email links: {base_url}")

            # Prepare template context
            context = {
                'scan_target': scan_data.get('target', ''),
                'scan_type': scan_data.get('scan_type', 'Security Scan'),
                'scan_duration': scan_data.get('duration', ''),
                'scan_started_at': scan_data.get('started_at', ''),
                'scan_completed_at': scan_data.get('completed_at', ''),
                'assets_discovered': scan_data.get('assets_discovered', {}),
                'vulnerabilities_found': scan_data.get('vulnerabilities_found', {}),
                'top_vulnerabilities': scan_data.get('top_vulnerabilities', []),
                'scan_notes': scan_data.get('notes', ''),
                'next_scan_scheduled': scan_data.get('next_scan_scheduled', ''),
                'dashboard_url': f"{base_url}/dashboard",
                'settings_url': f"{base_url}/settings",
                'organization_name': org.name,
                'scan_id': scan_data.get('scan_id', ''),
                'initiated_by': scan_data.get('initiated_by', ''),
                'current_year': datetime.utcnow().year,
                'unsubscribe_url': f"{base_url}/settings",
                'logo_url': f"{base_url}/static/img/attacksurfaceproFull.png"
            }

            subject = f"Scan Complete: {scan_data.get('target', 'Security Scan')} - {org.name}"

            # Render email template
            body_html = render_template('emails/scan_completion.html', **context)

            return self.send_email(recipients, subject, body_html)

        except Exception as e:
            logger.error(f"Failed to send scan completion email: {str(e)}")
            return {'success': False, 'error': f'Failed to send scan completion email: {str(e)}'}

    def send_dual_scan_notifications(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send both scan completion and security alert emails based on scan results

        Always sends:
        1. Scan completion email (if user has notify_scan_completion=True)

        Conditionally sends:
        2. Security alert email (if vulnerabilities found AND user has notify_new_vulnerabilities=True)

        Args:
            scan_data (dict): Complete scan data including vulnerabilities

        Returns:
            dict: Results of both email operations
        """
        try:
            results = {
                'scan_completion': {'sent': False, 'success': False},
                'security_alert': {'sent': False, 'success': False},
                'overall_success': False
            }

            # 1. ALWAYS send scan completion email (regardless of vulnerabilities)
            logger.info(f"📧 Sending scan completion email for {scan_data.get('target', 'unknown target')}")

            scan_completion_result = self.send_scan_completion(scan_data)
            results['scan_completion']['sent'] = True
            results['scan_completion']['success'] = scan_completion_result['success']

            if scan_completion_result['success']:
                logger.info("✅ Scan completion email sent successfully")
            else:
                logger.warning(f"⚠️ Scan completion email failed: {scan_completion_result.get('error')}")

            # 2. CONDITIONALLY send security alert email (only if vulnerabilities found)
            vulnerabilities_found = scan_data.get('vulnerabilities_found', {})
            total_vulns = vulnerabilities_found.get('total', 0)

            if total_vulns > 0:
                logger.info(f"🚨 {total_vulns} vulnerabilities detected - sending security alert email")

                # Prepare security alert data from scan results
                alert_data = self._prepare_security_alert_from_scan(scan_data)

                security_alert_result = self.send_security_alert(alert_data)
                results['security_alert']['sent'] = True
                results['security_alert']['success'] = security_alert_result['success']

                if security_alert_result['success']:
                    logger.info("✅ Security alert email sent successfully")
                else:
                    logger.warning(f"⚠️ Security alert email failed: {security_alert_result.get('error')}")
            else:
                logger.info("✅ No vulnerabilities found - skipping security alert email")
                results['security_alert']['sent'] = False
                results['security_alert']['success'] = True  # Not sending is considered success

            # Overall success if at least scan completion succeeded
            results['overall_success'] = results['scan_completion']['success']

            return results

        except Exception as e:
            logger.error(f"Failed to send dual scan notifications: {str(e)}")
            return {
                'scan_completion': {'sent': False, 'success': False},
                'security_alert': {'sent': False, 'success': False},
                'overall_success': False,
                'error': str(e)
            }

    def _prepare_security_alert_from_scan(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert scan completion data into security alert data format

        Args:
            scan_data (dict): Scan completion data

        Returns:
            dict: Security alert data format
        """
        vulnerabilities_found = scan_data.get('vulnerabilities_found', {})
        top_vulnerabilities = scan_data.get('top_vulnerabilities', [])

        # Count critical and high severity vulnerabilities
        critical_count = vulnerabilities_found.get('critical', 0)
        high_count = vulnerabilities_found.get('high', 0)
        medium_count = vulnerabilities_found.get('medium', 0)
        total_count = vulnerabilities_found.get('total', 0)

        # Determine alert severity based on highest vulnerability severity
        if critical_count > 0:
            alert_severity = 'critical'
            alert_title = f"Critical Security Vulnerabilities Detected on {scan_data.get('target', 'Target')}"
        elif high_count > 0:
            alert_severity = 'high'
            alert_title = f"High Severity Vulnerabilities Detected on {scan_data.get('target', 'Target')}"
        elif medium_count > 0:
            alert_severity = 'medium'
            alert_title = f"Medium Severity Vulnerabilities Detected on {scan_data.get('target', 'Target')}"
        else:
            alert_severity = 'low'
            alert_title = f"Security Vulnerabilities Detected on {scan_data.get('target', 'Target')}"

        # Create description
        description_parts = [
            f"A security scan of {scan_data.get('target', 'your target')} has detected {total_count} vulnerabilities."
        ]

        if critical_count > 0:
            description_parts.append(f"⚠️ {critical_count} CRITICAL vulnerabilities require immediate attention.")
        if high_count > 0:
            description_parts.append(f"🔴 {high_count} HIGH severity vulnerabilities should be addressed promptly.")
        if medium_count > 0:
            description_parts.append(f"🟡 {medium_count} MEDIUM severity vulnerabilities should be reviewed.")

        description_parts.append("Please review the detailed findings and take appropriate remediation actions.")

        alert_data = {
            'title': alert_title,
            'description': ' '.join(description_parts),
            'severity': alert_severity,
            'detected_at': scan_data.get('completed_at', datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')),
            'asset_name': scan_data.get('target', ''),
            'vulnerability_details': {
                'total_vulnerabilities': total_count,
                'critical_count': critical_count,
                'high_count': high_count,
                'medium_count': medium_count,
                'scan_type': scan_data.get('scan_type', 'Security Scan'),
                'scan_duration': scan_data.get('duration', ''),
                'top_vulnerabilities': top_vulnerabilities[:5]  # Limit to top 5
            },
            'recommendations': [
                'Review all critical and high severity vulnerabilities immediately',
                'Implement security patches and updates for affected services',
                'Consider temporarily disabling vulnerable services if patches are not available',
                'Monitor for exploitation attempts and unusual activity',
                'Schedule regular security scans to detect new vulnerabilities'
            ],
            'summary': {
                'total_vulnerabilities': total_count,
                'critical_high_count': critical_count + high_count,
                'scan_target': scan_data.get('target', ''),
                'assets_scanned': scan_data.get('assets_discovered', {}).get('subdomains', 0)
            },
            'alert_id': f"vuln_{scan_data.get('target', 'scan')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        }

        return alert_data

def generate_invitation_token() -> str:
    """Generate a secure token for user invitations"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(32))

def create_default_email_templates(organization_id: int):
    """Create default email templates for an organization"""
    from models import db, EmailTemplate

    templates = [
        {
            'name': 'User Invitation',
            'event_type': 'invitation',
            'subject': 'Invitation to join {{ organization_name }} on AttackSurfacePro',
            'body_html': '''
            <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                    <h2 style="color: #10b981;">You're invited to join {{ organization_name }}</h2>
                    <p>{{ invited_by_name }} has invited you to join <strong>{{ organization_name }}</strong> on AttackSurfacePro.</p>
                    <p>You will be added as a <strong>{{ role }}</strong>.</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{{ invitation_url }}" style="background-color: #10b981; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Accept Invitation</a>
                    </div>
                    <p>This invitation expires on {{ expires_at }}.</p>
                    <p style="color: #666; font-size: 14px;">If you don't want to join this organization, you can ignore this email.</p>
                </div>
            </body>
            </html>
            ''',
            'body_text': '''
            You're invited to join {{ organization_name }}

            {{ invited_by_name }} has invited you to join {{ organization_name }} on AttackSurfacePro.
            You will be added as a {{ role }}.

            Accept invitation: {{ invitation_url }}

            This invitation expires on {{ expires_at }}.
            If you don't want to join this organization, you can ignore this email.
            '''
        },
        {
            'name': 'Security Alert',
            'event_type': 'security_alert',
            'subject': 'Security Alert: {{ alert_title }} - {{ organization_name }}',
            'body_html': 'Uses templates/emails/security_alert.html',
            'body_text': '''
            Security Alert: {{ alert_title }}

            {{ alert_description }}

            Severity: {{ severity }}
            Asset: {{ asset_name }}
            Detected: {{ detected_at }}

            Please review this vulnerability and take appropriate action.

            View in Dashboard: {{ dashboard_url }}
            '''
        },
        {
            'name': 'Scan Completion',
            'event_type': 'scan_completion',
            'subject': 'Scan Complete: {{ scan_target }} - {{ organization_name }}',
            'body_html': 'Uses templates/emails/scan_completion.html',
            'body_text': '''
            Scan Complete: {{ scan_target }}

            Your {{ scan_type }} scan has completed successfully.

            Results Summary:
            - Subdomains: {{ assets_discovered.subdomains }}
            - Live Hosts: {{ assets_discovered.live_hosts }}
            - Vulnerabilities: {{ vulnerabilities_found.total }}

            Duration: {{ scan_duration }}
            Completed: {{ scan_completed_at }}

            View Full Results: {{ dashboard_url }}
            '''
        }
    ]

    for template_data in templates:
        template = EmailTemplate(
            organization_id=organization_id,
            **template_data,
            is_active=True,
            is_default=True
        )
        db.session.add(template)

    db.session.commit()
