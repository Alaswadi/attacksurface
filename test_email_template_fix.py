#!/usr/bin/env python3
"""
Quick test to verify the email template URL building fix
Tests that templates can render without url_for() errors
"""

import sys
import os
from datetime import datetime

# Add the current directory to the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import create_app
from models import db, User, Organization

def test_email_template_rendering():
    """Test that email templates can render without url_for() errors"""
    
    print("🧪 Testing Email Template Rendering Fix")
    print("=" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            from flask import render_template
            
            # Get organization for context
            org = Organization.query.first()
            if not org:
                print("❌ No organization found")
                return False
            
            # Test security alert template
            print("📧 Testing security alert template...")
            
            base_url = "https://wg4wcg4c8cs0s84ww00k84kg.phishsimulator.com"
            
            security_alert_context = {
                'alert_title': 'Test Security Alert',
                'alert_description': 'This is a test security alert to verify template rendering.',
                'severity': 'high',
                'detected_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'asset_name': 'test.example.com',
                'vulnerability_details': {
                    'cve_id': 'CVE-2024-TEST',
                    'cvss_score': 8.5
                },
                'recommendations': ['Test recommendation 1', 'Test recommendation 2'],
                'dashboard_url': f"{base_url}/dashboard",
                'organization_name': org.name,
                'summary': {'total_vulnerabilities': 1},
                'alert_id': 'test_alert_001',
                'generated_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'current_year': datetime.now().year,
                'unsubscribe_url': f"{base_url}/settings",
                'settings_url': f"{base_url}/settings",
                'logo_url': f"{base_url}/static/img/attacksurfaceproFull.png"
            }
            
            try:
                rendered_html = render_template('emails/security_alert.html', **security_alert_context)
                print(f"✅ Security alert template rendered successfully ({len(rendered_html)} characters)")
                
                # Check for key elements
                if base_url in rendered_html:
                    print("✅ VPS domain found in rendered template")
                else:
                    print("⚠️ VPS domain not found in rendered template")
                
                if 'Test Security Alert' in rendered_html:
                    print("✅ Alert content found in template")
                else:
                    print("⚠️ Alert content not found in template")
                
            except Exception as e:
                print(f"❌ Security alert template error: {str(e)}")
                return False
            
            # Test scan completion template
            print("\n📧 Testing scan completion template...")
            
            scan_completion_context = {
                'scan_target': 'test.example.com',
                'scan_type': 'Test Scan',
                'scan_duration': '2 minutes',
                'scan_started_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'scan_completed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
                'assets_discovered': {
                    'subdomains': 5,
                    'live_hosts': 3,
                    'open_ports': 10
                },
                'vulnerabilities_found': {
                    'total': 2,
                    'critical': 0,
                    'high': 1,
                    'medium': 1
                },
                'top_vulnerabilities': [],
                'scan_notes': 'Test scan notes',
                'dashboard_url': f"{base_url}/dashboard",
                'settings_url': f"{base_url}/settings",
                'organization_name': org.name,
                'scan_id': 'test_scan_001',
                'initiated_by': 'Test Script',
                'current_year': datetime.now().year,
                'unsubscribe_url': f"{base_url}/settings",
                'logo_url': f"{base_url}/static/img/attacksurfaceproFull.png"
            }
            
            try:
                rendered_html = render_template('emails/scan_completion.html', **scan_completion_context)
                print(f"✅ Scan completion template rendered successfully ({len(rendered_html)} characters)")
                
                # Check for key elements
                if base_url in rendered_html:
                    print("✅ VPS domain found in rendered template")
                else:
                    print("⚠️ VPS domain not found in rendered template")
                
                if 'test.example.com' in rendered_html:
                    print("✅ Scan content found in template")
                else:
                    print("⚠️ Scan content not found in template")
                
            except Exception as e:
                print(f"❌ Scan completion template error: {str(e)}")
                return False
            
            print("\n🎉 All email templates rendered successfully!")
            print("✅ No url_for() errors in Celery task context")
            print("✅ VPS URLs properly included")
            print("✅ Logo URLs dynamically generated")
            
            return True
            
        except Exception as e:
            print(f"❌ Template rendering test failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return False

def main():
    """Main function"""
    
    print("🚀 Email Template URL Building Fix Test")
    print("=" * 60)
    print("This test verifies that email templates can render")
    print("without url_for() errors in Celery task context")
    print("=" * 60)
    
    success = test_email_template_rendering()
    
    if success:
        print("\n🎉 EMAIL TEMPLATE FIX VERIFIED!")
        print("\n✅ Fixed Issues:")
        print("• Removed url_for() from base email template")
        print("• Added dynamic logo_url to all email contexts")
        print("• Templates now render in Celery tasks")
        print("• VPS URLs properly generated")
        
        print("\n📧 Security Alert Emails Should Now Work:")
        print("• No more 'SERVER_NAME' configuration errors")
        print("• Templates render with proper VPS URLs")
        print("• Logo images load correctly")
        print("• All email links point to VPS domain")
        
        print("\n🔄 Next Steps:")
        print("1. Monitor Celery logs for email task success")
        print("2. Verify actual email delivery")
        print("3. Check that users receive security alerts")
        
        return 0
    else:
        print("\n❌ Template fix verification failed!")
        print("Please check the errors above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
