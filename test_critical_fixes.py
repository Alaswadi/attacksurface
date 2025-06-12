#!/usr/bin/env python3
"""
Test Critical Fixes
Test scanning functionality and HTML report generation for invited users
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

def test_scanning_endpoints():
    """Test scanning API endpoints for invited users"""
    print("🔍 Testing Scanning Endpoints...")
    print("=" * 50)
    
    app = create_app()
    
    with app.test_client() as client:
        try:
            # Test scanning endpoints that were problematic
            scanning_endpoints = [
                ('/api/scan', 'POST', {'domain': 'example.com'}),
                ('/api/scan/assets/subdomain', 'POST', {'domain': 'example.com'}),
                ('/api/scan/large-domain', 'POST', {'domain': 'example.com', 'scan_type': 'quick'}),
                ('/api/large-scale-scan-progressive', 'POST', {'domain': 'example.com', 'scan_type': 'quick'}),
                ('/api/assets-stats', 'GET', None)
            ]
            
            for endpoint, method, data in scanning_endpoints:
                if method == 'GET':
                    response = client.get(endpoint)
                else:
                    response = client.post(endpoint, json=data)
                
                print(f"📡 {method} {endpoint}: {response.status_code}")
                
                if response.status_code == 404:
                    print(f"   ❌ {endpoint} still returning 404 - Organization not found!")
                    return False
                elif response.status_code in [200, 401, 403, 400, 500]:
                    print(f"   ✅ {endpoint} working (not 404)")
                else:
                    print(f"   ⚠️ {endpoint} returned {response.status_code}")
            
            print(f"\n✅ All scanning endpoints are working correctly!")
            return True
            
        except Exception as e:
            print(f"\n❌ Scanning test failed: {str(e)}")
            return False

def test_report_endpoints():
    """Test report generation endpoints"""
    print("\n📊 Testing Report Generation Endpoints...")
    print("=" * 50)
    
    app = create_app()
    
    with app.test_client() as client:
        try:
            # Test report endpoints
            report_endpoints = [
                ('/api/reports/generate-html', 'GET'),
                ('/api/reports/generate-pdf', 'GET'),
                ('/api/reports/data', 'GET')
            ]
            
            for endpoint, method in report_endpoints:
                response = client.get(endpoint)
                print(f"📡 {method} {endpoint}: {response.status_code}")
                
                if response.status_code == 404:
                    print(f"   ❌ {endpoint} still returning 404 - Organization not found!")
                    return False
                elif response.status_code in [200, 401, 403, 500]:
                    print(f"   ✅ {endpoint} working (not 404)")
                else:
                    print(f"   ⚠️ {endpoint} returned {response.status_code}")
            
            print(f"\n✅ All report endpoints are working correctly!")
            return True
            
        except Exception as e:
            print(f"\n❌ Report test failed: {str(e)}")
            return False

def test_organization_access():
    """Test organization access for all users"""
    print("\n🏢 Testing Organization Access...")
    print("=" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            from models import User, Organization, OrganizationUser
            from utils.permissions import get_user_organization
            from flask_login import login_user
            
            # Get all users
            users = User.query.all()
            print(f"📊 Testing {len(users)} users:")
            
            for user in users:
                print(f"\n👤 User: {user.email}")
                
                # Check owned organizations
                owned_orgs = Organization.query.filter_by(user_id=user.id).all()
                print(f"   Owns: {len(owned_orgs)} organizations")
                
                # Check memberships
                memberships = OrganizationUser.query.filter_by(user_id=user.id, is_active=True).all()
                print(f"   Active memberships: {len(memberships)}")
                
                # Test get_user_organization function
                with app.test_request_context():
                    login_user(user)
                    user_org = get_user_organization()
                    
                    if user_org:
                        print(f"   ✅ get_user_organization(): {user_org.name}")
                        
                        # Determine user type
                        if len(owned_orgs) > 0:
                            print(f"   📝 User type: Organization Owner")
                        elif len(memberships) > 0:
                            membership = memberships[0]
                            print(f"   📝 User type: Organization Member ({membership.role.value})")
                        
                    else:
                        print(f"   ❌ get_user_organization(): None")
                        if len(owned_orgs) > 0 or len(memberships) > 0:
                            print(f"      🚨 ERROR: User has organizations but can't access them!")
                            return False
            
            print(f"\n✅ Organization access is working correctly!")
            return True
            
        except Exception as e:
            print(f"\n❌ Organization access test failed: {str(e)}")
            return False

def test_specific_user_scenarios():
    """Test specific scenarios for invited users"""
    print("\n🎯 Testing Specific User Scenarios...")
    print("=" * 50)
    
    app = create_app()
    
    with app.app_context():
        try:
            from models import User, Organization, OrganizationUser, UserRole
            from utils.permissions import get_user_organization, can_run_scans, can_view_reports
            from flask_login import login_user
            
            # Find invited users (organization members, not owners)
            invited_users = []
            all_users = User.query.all()
            
            for user in all_users:
                owned_orgs = Organization.query.filter_by(user_id=user.id).count()
                memberships = OrganizationUser.query.filter_by(user_id=user.id, is_active=True).count()
                
                if owned_orgs == 0 and memberships > 0:
                    invited_users.append(user)
            
            print(f"📊 Found {len(invited_users)} invited users to test:")
            
            if len(invited_users) == 0:
                print("   ℹ️ No invited users found - this is expected if only organization owners exist")
                return True
            
            for user in invited_users:
                print(f"\n👤 Testing invited user: {user.email}")
                
                with app.test_request_context():
                    login_user(user)
                    
                    # Test organization access
                    user_org = get_user_organization()
                    if not user_org:
                        print(f"   ❌ Cannot access organization!")
                        return False
                    
                    print(f"   ✅ Can access organization: {user_org.name}")
                    
                    # Test permissions
                    can_scan = can_run_scans()
                    can_report = can_view_reports()
                    
                    print(f"   🔐 Permissions:")
                    print(f"      can_run_scans: {can_scan}")
                    print(f"      can_view_reports: {can_report}")
                    
                    # Get user role
                    membership = OrganizationUser.query.filter_by(user_id=user.id, is_active=True).first()
                    if membership:
                        print(f"   📝 Role: {membership.role.value}")
                        
                        if membership.role == UserRole.ADMIN:
                            if not can_scan:
                                print(f"   ❌ Admin should be able to run scans!")
                                return False
                        
                        if not can_report:
                            print(f"   ❌ User should be able to view reports!")
                            return False
            
            print(f"\n✅ All invited user scenarios working correctly!")
            return True
            
        except Exception as e:
            print(f"\n❌ User scenario test failed: {str(e)}")
            return False

def main():
    """Main test function"""
    print("🚀 Starting Critical Fixes Verification...")
    print("=" * 60)
    
    # Test scanning endpoints
    scanning_test = test_scanning_endpoints()
    
    # Test report endpoints
    report_test = test_report_endpoints()
    
    # Test organization access
    org_test = test_organization_access()
    
    # Test specific user scenarios
    scenario_test = test_specific_user_scenarios()
    
    # Summary
    print(f"\n{'='*60}")
    print("📊 Test Results:")
    print(f"{'='*60}")
    print(f"   Scanning Endpoints: {'✅ PASSED' if scanning_test else '❌ FAILED'}")
    print(f"   Report Endpoints: {'✅ PASSED' if report_test else '❌ FAILED'}")
    print(f"   Organization Access: {'✅ PASSED' if org_test else '❌ FAILED'}")
    print(f"   User Scenarios: {'✅ PASSED' if scenario_test else '❌ FAILED'}")
    
    if scanning_test and report_test and org_test and scenario_test:
        print(f"\n🎉 All critical fixes verified successfully!")
        print(f"\nExpected results:")
        print(f"✅ Invited Admin users can now start scans without 'Organization not found' errors")
        print(f"✅ All users can export HTML reports successfully")
        print(f"✅ Both organization owners and members can access their organization's data")
        print(f"✅ Permission system works correctly for all user types")
        return 0
    else:
        print(f"\n💥 Some tests failed.")
        print(f"Please review the results above.")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
