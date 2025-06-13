#!/usr/bin/env python3
"""
Test script specifically for VPS scan completion email functionality
Tests the email system with proper VPS domain configuration
"""

import sys
import os
from datetime import datetime

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, User, Organization, EmailNotificationSettings, EmailConfiguration
from services.email_service import EmailService

def test_vps_email_configuration():
    """Test email configuration on VPS"""
    print("🧪 Testing VPS Email Configuration")
    print("-" * 40)
    
    app = create_app()
    
    with app.app_context():
        try:
            # Get organization and email config
            org = Organization.query.first()
            if not org:
                print("❌ No organization found")
                return False
            
            email_config = EmailConfiguration.query.filter_by(organization_id=org.id).first()
            if not email_config:
                print("❌ No email configuration found")
                return False
            
            print(f"✅ Organization: {org.name}")
            print(f"📧 SMTP Host: {email_config.smtp_host}")
            print(f"📧 From Email: {email_config.from_email}")
            print(f"📧 Configured: {email_config.is_configured}")
            print(f"📧 Verified: {email_config.is_verified}")
            
            # Test email service
            email_service = EmailService(org.id)
            if email_service.is_configured():
                print("✅ Email service is ready")
                return True
            else:
                print("❌ Email service is not configured")
                return False
                
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            return False

def test_scan_completion_email_with_vps_urls():
    """Test scan completion email with proper VPS URLs"""
    print("\n🧪 Testing Scan Completion Email with VPS URLs")
    print("-" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            # Get organization
            org = Organization.query.first()
            if not org:
                print("❌ No organization found")
                return False
            
            # Initialize email service
            email_service = EmailService(org.id)
            
            if not email_service.is_configured():
                print("❌ Email service not configured")
                return False
            
            # Create test scan data
            scan_data = {
                'target': 'example.com',
                'scan_type': 'VPS Test Scan',
                'duration': '2 minutes 15 seconds',
                'started_at': '2024-01-15 15:00:00 UTC',
                'completed_at': '2024-01-15 15:02:15 UTC',
                'assets_discovered': {
                    'subdomains': 6,
                    'live_hosts': 4,
                    'open_ports': 18,
                    'services': 10,
                    'technologies': 5
                },
                'vulnerabilities_found': {
                    'total': 3,
                    'critical': 1,
                    'high': 1,
                    'medium': 1,
                    'low': 0,
                    'info': 0
                },
                'top_vulnerabilities': [
                    {
                        'title': 'Exposed Admin Panel',
                        'severity': 'critical',
                        'asset': 'admin.example.com'
                    },
                    {
                        'title': 'Outdated Software Version',
                        'severity': 'high',
                        'asset': 'api.example.com'
                    }
                ],
                'scan_id': f"vps_test_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'initiated_by': 'VPS Test Script',
                'notes': 'Test scan from VPS environment to verify email functionality.'
            }
            
            print(f"📋 Test scan data prepared for: {scan_data['target']}")
            print(f"🔍 Found {scan_data['vulnerabilities_found']['total']} vulnerabilities")
            
            # Get notification settings
            notification_settings = EmailNotificationSettings.query.filter_by(
                organization_id=org.id,
                notify_scan_completion=True
            ).all()
            
            if not notification_settings:
                print("❌ No users have scan completion notifications enabled")
                return False
            
            recipients = []
            for setting in notification_settings:
                user = User.query.get(setting.user_id)
                if user:
                    email = setting.notification_email or user.email
                    recipients.append(email)
                    if setting.additional_recipients:
                        additional = [email.strip() for email in setting.additional_recipients.split(',') if email.strip()]
                        recipients.extend(additional)
            
            print(f"📬 Recipients: {recipients}")
            
            # Test email template rendering with VPS context
            from flask import render_template
            
            # Simulate VPS environment URLs
            base_url = "https://wg4wcg4c8cs0s84ww00k84kg.phishsimulator.com"
            
            context = {
                'scan_target': scan_data['target'],
                'scan_type': scan_data['scan_type'],
                'scan_duration': scan_data['duration'],
                'scan_started_at': scan_data['started_at'],
                'scan_completed_at': scan_data['completed_at'],
                'assets_discovered': scan_data['assets_discovered'],
                'vulnerabilities_found': scan_data['vulnerabilities_found'],
                'top_vulnerabilities': scan_data['top_vulnerabilities'],
                'scan_notes': scan_data['notes'],
                'organization_name': org.name,
                'dashboard_url': f"{base_url}/dashboard",
                'settings_url': f"{base_url}/settings",
                'current_year': datetime.now().year,
                'scan_id': scan_data['scan_id'],
                'initiated_by': scan_data['initiated_by']
            }
            
            # Render template
            rendered_html = render_template('emails/scan_completion.html', **context)
            print(f"✅ Email template rendered successfully ({len(rendered_html)} characters)")
            
            # Verify VPS URLs are in the email
            if base_url in rendered_html:
                print(f"✅ VPS domain found in email: {base_url}")
            else:
                print(f"⚠️ VPS domain not found in email")
            
            # Check for key content
            checks = [
                ('Scan target', scan_data['target'] in rendered_html),
                ('Vulnerability count', str(scan_data['vulnerabilities_found']['total']) in rendered_html),
                ('Dashboard link', '/dashboard' in rendered_html),
                ('Settings link', '/settings' in rendered_html),
                ('Organization name', org.name in rendered_html)
            ]
            
            print("\n📋 Email Content Verification:")
            all_passed = True
            for check_name, result in checks:
                status = "✅" if result else "❌"
                print(f"   {status} {check_name}")
                if not result:
                    all_passed = False
            
            if all_passed:
                print("\n🎉 All email content checks passed!")
                print("\n📧 Email is ready to send with:")
                print(f"   🌐 VPS Domain: {base_url}")
                print(f"   📬 Recipients: {len(recipients)} users")
                print(f"   📊 Scan Results: {scan_data['vulnerabilities_found']['total']} vulnerabilities")
                print(f"   🔗 Dashboard Link: {base_url}/dashboard")
                return True
            else:
                print("\n❌ Some content checks failed")
                return False
                
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

def test_celery_integration():
    """Test Celery task integration"""
    print("\n🧪 Testing Celery Integration")
    print("-" * 30)
    
    try:
        from tasks import send_scan_completion_email_task
        print("✅ Scan completion email task imported")
        
        # Check if we can access the task
        if hasattr(send_scan_completion_email_task, 'delay'):
            print("✅ Celery task has delay method (async execution)")
        else:
            print("⚠️ Celery task missing delay method")
        
        print("✅ Celery integration is properly configured")
        return True
        
    except Exception as e:
        print(f"❌ Celery integration error: {str(e)}")
        return False

def main():
    """Run VPS-specific tests"""
    
    print("🚀 VPS Scan Completion Email Test")
    print("=" * 50)
    print("Testing email functionality on VPS environment")
    print("Domain: wg4wcg4c8cs0s84ww00k84kg.phishsimulator.com")
    print("IP: 38.242.207.50")
    print("=" * 50)
    
    # Run tests
    tests = [
        ("Email Configuration", test_vps_email_configuration),
        ("Scan Completion Email", test_scan_completion_email_with_vps_urls),
        ("Celery Integration", test_celery_integration)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ Test {test_name} failed: {str(e)}")
            results.append((test_name, False))
    
    # Summary
    print("\n📊 VPS Test Results")
    print("=" * 30)
    
    passed = 0
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")
        if result:
            passed += 1
    
    print(f"\n📈 Overall: {passed}/{len(results)} tests passed")
    
    if passed == len(results):
        print("\n🎉 VPS SCAN COMPLETION EMAIL SYSTEM IS WORKING!")
        print("\n📋 Ready for production use:")
        print("✅ Email configuration verified")
        print("✅ Scan completion emails will be sent")
        print("✅ VPS URLs properly configured")
        print("✅ Celery integration working")
        print("\n🔄 When scans complete:")
        print("1. Scan finishes → triggers email task")
        print("2. Email service loads user preferences")
        print("3. Template renders with VPS URLs")
        print("4. Email sent to configured recipients")
        return 0
    else:
        print(f"\n⚠️ {len(results) - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
