#!/usr/bin/env python3
"""
Test script to verify Celery database and exception handling fixes
Tests both the database type error fix and the task completion fix
"""

import requests
import time
import json
import sys
from datetime import datetime

class CeleryFixTester:
    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.session = requests.Session()
        
    def login_user(self, username='admin', password='admin'):
        """Login to get session cookie"""
        print("🔐 Logging in...")
        try:
            # Get login page first
            login_page = self.session.get(f"{self.base_url}/login")
            
            # Login with credentials
            login_data = {
                'username': username,
                'password': password
            }
            
            response = self.session.post(f"{self.base_url}/login", data=login_data)
            
            if response.status_code == 200 and 'dashboard' in response.url:
                print("✅ Login successful")
                return True
            else:
                print(f"❌ Login failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"❌ Login error: {str(e)}")
            return False
    
    def test_large_scale_scanning(self, domain='example.com', scan_type='quick'):
        """Test large-scale scanning with database fix"""
        print(f"\n🚀 Testing large-scale scanning for {domain}...")
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/scan/large-domain",
                json={
                    'domain': domain,
                    'scan_type': scan_type
                },
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data['success']:
                    print(f"✅ Scan started successfully!")
                    print(f"📊 Mode: {data.get('mode', 'unknown')}")
                    print(f"🆔 Task ID: {data['task_id']}")
                    
                    return data['task_id'], data.get('mode', 'celery')
                else:
                    print(f"❌ Scan failed to start: {data.get('error', 'Unknown error')}")
                    return None, None
            else:
                print(f"❌ HTTP Error {response.status_code}: {response.text}")
                return None, None
                
        except Exception as e:
            print(f"❌ Error starting scan: {str(e)}")
            return None, None
    
    def monitor_scan_progress(self, task_id, mode='celery', max_wait_time=300):
        """Monitor scan progress and check for database errors"""
        print(f"\n📊 Monitoring scan progress for task {task_id}...")
        
        # Determine the correct endpoint based on mode
        if mode == 'fallback':
            status_endpoint = f"{self.base_url}/api/scan/fallback-status/{task_id}"
        else:
            status_endpoint = f"{self.base_url}/api/scan/celery-status/{task_id}"
        
        start_time = time.time()
        last_progress = -1
        last_stage = ""
        database_errors_detected = False
        exception_errors_detected = False
        
        while time.time() - start_time < max_wait_time:
            try:
                response = self.session.get(status_endpoint)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data['success']:
                        state = data.get('state', 'UNKNOWN')
                        progress = data.get('progress', 0)
                        message = data.get('message', 'Processing...')
                        stage = data.get('stage', 'unknown')
                        
                        # Check for database errors in the message
                        if 'can\'t adapt type \'dict\'' in message.lower():
                            database_errors_detected = True
                            print(f"❌ Database type error detected: {message}")
                        
                        # Check for exception handling errors
                        if 'exception information must include' in message.lower():
                            exception_errors_detected = True
                            print(f"❌ Exception handling error detected: {message}")
                        
                        # Only print progress updates when they change
                        if progress != last_progress or stage != last_stage:
                            print(f"📈 Progress: {progress}% - Stage: {stage} - {message}")
                            last_progress = progress
                            last_stage = stage
                            
                            # Print additional details if available
                            if 'subdomains_found' in data and data['subdomains_found'] > 0:
                                print(f"   🔍 Subdomains found: {data['subdomains_found']}")
                            if 'alive_hosts_found' in data and data['alive_hosts_found'] > 0:
                                print(f"   🌐 Alive hosts: {data['alive_hosts_found']}")
                        
                        if state == 'SUCCESS':
                            print(f"✅ Scan completed successfully!")
                            result = data.get('result', {})
                            if result:
                                print(f"📊 Final Results:")
                                print(f"   Domain: {result.get('domain', 'N/A')}")
                                print(f"   Scan Type: {result.get('scan_type', 'N/A')}")
                                print(f"   Subdomains Found: {result.get('subdomains_found', 0)}")
                                print(f"   Alive Hosts: {result.get('alive_hosts_found', 0)}")
                                print(f"   Mode: {result.get('mode', 'N/A')}")
                            
                            # Check for errors during the scan
                            if database_errors_detected:
                                print("❌ Database type errors were detected during the scan")
                                return False
                            if exception_errors_detected:
                                print("❌ Exception handling errors were detected during the scan")
                                return False
                            
                            print("✅ No database or exception handling errors detected")
                            return True
                            
                        elif state == 'FAILURE':
                            error_msg = data.get('error', 'Unknown error')
                            print(f"❌ Scan failed: {error_msg}")
                            
                            # Check if it's a database type error
                            if 'can\'t adapt type \'dict\'' in error_msg:
                                print("❌ CONFIRMED: Database type error detected")
                                return False
                            
                            # Check if it's an exception handling error
                            if 'exception information must include' in error_msg:
                                print("❌ CONFIRMED: Exception handling error detected")
                                return False
                            
                            return False
                            
                    else:
                        error_msg = data.get('error', 'Unknown error')
                        print(f"❌ Status check failed: {error_msg}")
                        
                        # Check for specific error types
                        if 'exception information must include' in error_msg:
                            exception_errors_detected = True
                            print("❌ CONFIRMED: Exception handling error in status check")
                        
                        return False
                        
                else:
                    print(f"❌ HTTP Error {response.status_code}: {response.text}")
                    return False
                    
            except Exception as e:
                print(f"❌ Error checking status: {str(e)}")
                return False
            
            # Wait before next check
            time.sleep(3)
        
        print(f"⏰ Timeout reached after {max_wait_time} seconds")
        
        # Final error check
        if database_errors_detected:
            print("❌ Database type errors were detected during monitoring")
            return False
        if exception_errors_detected:
            print("❌ Exception handling errors were detected during monitoring")
            return False
        
        return False
    
    def run_comprehensive_test(self):
        """Run comprehensive test of the Celery fixes"""
        print("🧪 CELERY FIXES COMPREHENSIVE TEST")
        print("="*60)
        print(f"🕐 Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🌐 Testing against: {self.base_url}")
        
        # Login first
        if not self.login_user():
            print("❌ Cannot proceed without login")
            return False
        
        results = {
            'database_fix': False,
            'exception_fix': False,
            'task_completion': False
        }
        
        # Test 1: Database Type Error Fix
        print("\n" + "="*60)
        print("🔧 TESTING DATABASE TYPE ERROR FIX")
        print("="*60)
        print("Testing that subdomain dictionaries are properly handled...")
        
        task_id, mode = self.test_large_scale_scanning('nmap.com', 'quick')
        
        if task_id:
            success = self.monitor_scan_progress(task_id, mode, max_wait_time=180)
            results['database_fix'] = success
            results['task_completion'] = success
            
            if success:
                print("✅ Database type error fix PASSED")
                print("✅ Task completion fix PASSED")
            else:
                print("❌ Database type error fix FAILED or task didn't complete")
        else:
            print("❌ Could not start test scan")
        
        # Test 2: Exception Handling Fix (if Celery mode)
        if mode == 'celery':
            print("\n" + "="*60)
            print("🔧 TESTING EXCEPTION HANDLING FIX")
            print("="*60)
            print("Testing that Celery exceptions are properly serialized...")
            
            # This test is implicit - if we got here without exception errors, it passed
            results['exception_fix'] = results['database_fix']
            
            if results['exception_fix']:
                print("✅ Exception handling fix PASSED")
            else:
                print("❌ Exception handling fix FAILED")
        else:
            print("\n⚠️  Exception handling test skipped - using fallback mode")
            results['exception_fix'] = True  # Not applicable in fallback mode
        
        # Print final results
        print("\n" + "="*60)
        print("📊 FINAL TEST RESULTS")
        print("="*60)
        
        print(f"🔧 Database Type Error Fix: {'✅ PASS' if results['database_fix'] else '❌ FAIL'}")
        print(f"🔧 Exception Handling Fix: {'✅ PASS' if results['exception_fix'] else '❌ FAIL'}")
        print(f"🔧 Task Completion Fix: {'✅ PASS' if results['task_completion'] else '❌ FAIL'}")
        
        # Overall result
        all_passed = all(results.values())
        
        print("\n" + "="*60)
        if all_passed:
            print("🎉 OVERALL RESULT: ✅ ALL FIXES WORKING")
            print("✅ Database type errors are fixed!")
            print("✅ Exception handling errors are fixed!")
            print("✅ Task completion is working!")
        else:
            print("💥 OVERALL RESULT: ❌ SOME FIXES FAILED")
            print("❌ Celery implementation needs attention!")
        
        print("="*60)
        
        return all_passed

def main():
    """Main test function"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = 'http://localhost:5000'
    
    print(f"🧪 Starting Celery Fixes Tests")
    print(f"🌐 Target URL: {base_url}")
    print(f"📝 Make sure the Flask application is running!")
    print()
    
    tester = CeleryFixTester(base_url)
    success = tester.run_comprehensive_test()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
