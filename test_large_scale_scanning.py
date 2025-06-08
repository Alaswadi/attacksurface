#!/usr/bin/env python3
"""
Test script for Large-Scale Scanning functionality
Tests both Celery mode (with Redis) and Fallback mode (without Redis)
"""

import requests
import time
import json
import sys
from datetime import datetime

class LargeScaleScanningTester:
    def __init__(self, base_url='http://localhost:5000'):
        self.base_url = base_url
        self.session = requests.Session()
        
    def test_redis_status(self):
        """Test Redis status endpoint"""
        print("🔍 Testing Redis status...")
        try:
            response = self.session.get(f"{self.base_url}/api/system/redis-status")
            if response.status_code == 200:
                data = response.json()
                print(f"✅ Redis Status: {data['redis']['status']}")
                print(f"📊 Celery Available: {data['celery_available']}")
                return data['celery_available']
            else:
                print(f"❌ Redis status check failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Redis status check error: {str(e)}")
            return False
    
    def start_large_scale_scan(self, domain='example.com', scan_type='deep'):
        """Start a large-scale scan"""
        print(f"\n🚀 Starting large-scale {scan_type} scan for {domain}...")
        
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
                    print(f"⏱️  Estimated time: {data['estimated_time']}")
                    
                    if data.get('mode') == 'fallback':
                        print(f"⚠️  Notice: {data.get('notice', 'Running in fallback mode')}")
                    
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
        """Monitor scan progress until completion"""
        print(f"\n📊 Monitoring scan progress for task {task_id}...")
        
        # Determine the correct endpoint based on mode
        if mode == 'fallback':
            status_endpoint = f"{self.base_url}/api/scan/fallback-status/{task_id}"
        else:
            status_endpoint = f"{self.base_url}/api/scan/celery-status/{task_id}"
        
        start_time = time.time()
        last_progress = -1
        
        while time.time() - start_time < max_wait_time:
            try:
                response = self.session.get(status_endpoint)
                
                if response.status_code == 200:
                    data = response.json()
                    
                    if data['success']:
                        state = data.get('state', 'UNKNOWN')
                        progress = data.get('progress', 0)
                        message = data.get('message', 'Processing...')
                        
                        # Only print progress updates when they change
                        if progress != last_progress:
                            print(f"📈 Progress: {progress}% - {message}")
                            last_progress = progress
                            
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
                            return True
                            
                        elif state == 'FAILURE':
                            print(f"❌ Scan failed: {data.get('error', 'Unknown error')}")
                            return False
                            
                    else:
                        print(f"❌ Status check failed: {data.get('error', 'Unknown error')}")
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
        return False
    
    def test_fallback_mode(self):
        """Test fallback mode functionality"""
        print("\n" + "="*60)
        print("🔄 TESTING FALLBACK MODE (Without Redis)")
        print("="*60)
        
        # Start scan
        task_id, mode = self.start_large_scale_scan('testdomain.com', 'quick')
        
        if task_id and mode == 'fallback':
            print(f"✅ Fallback mode activated correctly")
            
            # Monitor progress
            success = self.monitor_scan_progress(task_id, mode, max_wait_time=120)
            
            if success:
                print("✅ Fallback mode test PASSED")
                return True
            else:
                print("❌ Fallback mode test FAILED - monitoring failed")
                return False
        else:
            print("❌ Fallback mode test FAILED - scan didn't start or wrong mode")
            return False
    
    def test_celery_mode(self):
        """Test Celery mode functionality (requires Redis)"""
        print("\n" + "="*60)
        print("🚀 TESTING CELERY MODE (With Redis)")
        print("="*60)
        
        # Check if Redis is available
        redis_available = self.test_redis_status()
        
        if not redis_available:
            print("⚠️  Skipping Celery mode test - Redis not available")
            print("💡 To test Celery mode, run: setup-redis-dev.bat")
            return None
        
        # Start scan
        task_id, mode = self.start_large_scale_scan('example.com', 'quick')
        
        if task_id and mode == 'celery':
            print(f"✅ Celery mode activated correctly")
            
            # Monitor progress
            success = self.monitor_scan_progress(task_id, mode, max_wait_time=300)
            
            if success:
                print("✅ Celery mode test PASSED")
                return True
            else:
                print("❌ Celery mode test FAILED - monitoring failed")
                return False
        else:
            print("❌ Celery mode test FAILED - scan didn't start or wrong mode")
            return False
    
    def run_comprehensive_test(self):
        """Run comprehensive test of both modes"""
        print("🧪 LARGE-SCALE SCANNING COMPREHENSIVE TEST")
        print("="*60)
        print(f"🕐 Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🌐 Testing against: {self.base_url}")
        
        results = {
            'redis_status': False,
            'fallback_mode': False,
            'celery_mode': None
        }
        
        # Test Redis status
        results['redis_status'] = self.test_redis_status()
        
        # Test fallback mode
        results['fallback_mode'] = self.test_fallback_mode()
        
        # Test Celery mode if Redis is available
        if results['redis_status']:
            results['celery_mode'] = self.test_celery_mode()
        else:
            print("\n⚠️  Celery mode test skipped - Redis not available")
        
        # Print final results
        print("\n" + "="*60)
        print("📊 FINAL TEST RESULTS")
        print("="*60)
        
        print(f"🔍 Redis Status Check: {'✅ PASS' if results['redis_status'] else '❌ FAIL'}")
        print(f"🔄 Fallback Mode Test: {'✅ PASS' if results['fallback_mode'] else '❌ FAIL'}")
        
        if results['celery_mode'] is not None:
            print(f"🚀 Celery Mode Test: {'✅ PASS' if results['celery_mode'] else '❌ FAIL'}")
        else:
            print(f"🚀 Celery Mode Test: ⚠️  SKIPPED (Redis not available)")
        
        # Overall result
        critical_tests_passed = results['fallback_mode']
        if results['redis_status']:
            critical_tests_passed = critical_tests_passed and results['celery_mode']
        
        print("\n" + "="*60)
        if critical_tests_passed:
            print("🎉 OVERALL RESULT: ✅ ALL TESTS PASSED")
            print("✅ Large-scale scanning is working correctly!")
        else:
            print("💥 OVERALL RESULT: ❌ SOME TESTS FAILED")
            print("❌ Large-scale scanning needs attention!")
        
        print("="*60)
        
        return critical_tests_passed

def main():
    """Main test function"""
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
    else:
        base_url = 'http://localhost:5000'
    
    print(f"🧪 Starting Large-Scale Scanning Tests")
    print(f"🌐 Target URL: {base_url}")
    print(f"📝 Make sure the Flask application is running!")
    print()
    
    tester = LargeScaleScanningTester(base_url)
    success = tester.run_comprehensive_test()
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == '__main__':
    main()
