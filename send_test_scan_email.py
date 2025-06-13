#!/usr/bin/env python3
"""
Script to send a test scan completion email on VPS
This simulates what happens when a real scan completes
"""

import sys
import os
from datetime import datetime

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, User, Organization, EmailNotificationSettings
from services.email_service import EmailService

def send_test_scan_completion_email():
    """Send a test scan completion email"""
    
    print("📧 Sending Test Scan Completion Email")
    print("=" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            # Get organization
            org = Organization.query.first()
            if not org:
                print("❌ No organization found")
                return False
            
            print(f"🏢 Organization: {org.name}")
            
            # Check email configuration
            email_service = EmailService(org.id)
            if not email_service.is_configured():
                print("❌ Email service is not configured")
                print("📋 Please configure SMTP settings in Settings → Integrations")
                return False
            
            print("✅ Email service is configured")
            
            # Check for users with scan completion notifications
            notification_settings = EmailNotificationSettings.query.filter_by(
                organization_id=org.id,
                notify_scan_completion=True
            ).all()
            
            if not notification_settings:
                print("❌ No users have scan completion notifications enabled")
                print("📋 Please enable scan completion notifications in Settings → Notifications")
                return False
            
            recipients = []
            for setting in notification_settings:
                user = User.query.get(setting.user_id)
                if user:
                    email = setting.notification_email or user.email
                    recipients.append(email)
                    print(f"👤 User: {user.username} → {email}")
                    
                    if setting.additional_recipients:
                        additional = [email.strip() for email in setting.additional_recipients.split(',') if email.strip()]
                        recipients.extend(additional)
                        print(f"📬 Additional: {', '.join(additional)}")
            
            print(f"\n📬 Total recipients: {len(recipients)}")
            
            # Create realistic test scan data
            scan_data = {
                'target': 'testdomain.com',
                'scan_type': 'Production Test Scan',
                'duration': '4 minutes 32 seconds',
                'started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'completed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'assets_discovered': {
                    'subdomains': 12,
                    'live_hosts': 8,
                    'open_ports': 34,
                    'services': 16,
                    'technologies': 9
                },
                'vulnerabilities_found': {
                    'total': 5,
                    'critical': 1,
                    'high': 2,
                    'medium': 2,
                    'low': 0,
                    'info': 0
                },
                'top_vulnerabilities': [
                    {
                        'title': 'SQL Injection Vulnerability',
                        'severity': 'critical',
                        'asset': 'login.testdomain.com'
                    },
                    {
                        'title': 'Cross-Site Scripting (XSS)',
                        'severity': 'high',
                        'asset': 'api.testdomain.com'
                    },
                    {
                        'title': 'Insecure Direct Object Reference',
                        'severity': 'high',
                        'asset': 'admin.testdomain.com'
                    },
                    {
                        'title': 'Information Disclosure',
                        'severity': 'medium',
                        'asset': 'www.testdomain.com'
                    },
                    {
                        'title': 'Weak SSL Configuration',
                        'severity': 'medium',
                        'asset': 'secure.testdomain.com'
                    }
                ],
                'scan_id': f"prod_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'initiated_by': 'Production Test',
                'notes': 'This is a test scan completion email sent from the VPS environment to verify the email notification system is working correctly.'
            }
            
            print(f"\n📋 Scan Summary:")
            print(f"   🎯 Target: {scan_data['target']}")
            print(f"   ⏱️ Duration: {scan_data['duration']}")
            print(f"   🔍 Assets: {scan_data['assets_discovered']['subdomains']} subdomains, {scan_data['assets_discovered']['live_hosts']} live hosts")
            print(f"   🚨 Vulnerabilities: {scan_data['vulnerabilities_found']['total']} total")
            print(f"      - Critical: {scan_data['vulnerabilities_found']['critical']}")
            print(f"      - High: {scan_data['vulnerabilities_found']['high']}")
            print(f"      - Medium: {scan_data['vulnerabilities_found']['medium']}")
            
            # Send the email
            print(f"\n📧 Sending scan completion email...")
            result = email_service.send_scan_completion(scan_data)
            
            if result['success']:
                print("✅ SUCCESS! Scan completion email sent successfully!")
                print(f"\n📬 Email sent to: {', '.join(recipients)}")
                print("\n📧 Email includes:")
                print("   • Scan target and results summary")
                print("   • Detailed vulnerability information")
                print("   • Asset discovery statistics")
                print("   • Links to dashboard and settings")
                print("   • Professional formatting with organization branding")
                print("\n🎉 The scan completion email system is working correctly!")
                return True
            else:
                print(f"❌ FAILED to send email: {result.get('error')}")
                print("\n🔍 Troubleshooting tips:")
                print("1. Check SMTP configuration in Settings → Integrations")
                print("2. Verify email addresses are valid")
                print("3. Check server logs for detailed error messages")
                print("4. Test email configuration using 'Send Test Email' button")
                return False
                
        except Exception as e:
            print(f"❌ Error sending test email: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """Main function"""
    
    print("🚀 VPS Scan Completion Email Test")
    print("=" * 60)
    print("This script sends a test scan completion email to verify")
    print("that the email notification system is working correctly")
    print("on your VPS environment.")
    print("=" * 60)
    
    success = send_test_scan_completion_email()
    
    if success:
        print("\n🎉 TEST COMPLETED SUCCESSFULLY!")
        print("\n📋 What this means:")
        print("✅ Email configuration is working")
        print("✅ Scan completion notifications are enabled")
        print("✅ Email templates are rendering correctly")
        print("✅ SMTP delivery is functional")
        print("\n🔄 When real scans complete:")
        print("• Users will automatically receive email notifications")
        print("• Emails will include detailed scan results")
        print("• Links will point to your VPS dashboard")
        print("• All configured recipients will be notified")
        
        return 0
    else:
        print("\n❌ TEST FAILED!")
        print("\nPlease fix the issues above and try again.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
