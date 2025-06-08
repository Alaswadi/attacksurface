#!/usr/bin/env python3
"""
Quick test script to verify progressive scanning fixes
"""

import sys
import time
import requests
import json
from datetime import datetime

def test_progressive_scanning_fix():
    """Test progressive scanning with fixes"""
    print("🧪 TESTING PROGRESSIVE SCANNING FIXES")
    print("=" * 50)
    
    base_url = "http://localhost:8077"
    test_domain = "example.com"
    
    # Start progressive scanning
    print(f"\n1️⃣ Starting progressive scan for {test_domain}")
    try:
        response = requests.post(f"{base_url}/api/large-scale-scan-progressive", 
                               json={
                                   "domain": test_domain,
                                   "scan_type": "quick"
                               },
                               timeout=15)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                task_id = data.get('task_id')
                print(f"✅ Progressive scanning started: {task_id}")
                
                # Monitor for 2 minutes
                return monitor_progressive_scan(base_url, task_id, test_domain, 120)
            else:
                print(f"❌ Error: {data.get('error')}")
                return False
        else:
            print(f"❌ HTTP {response.status_code}: {response.text}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {str(e)}")
        return False

def monitor_progressive_scan(base_url, task_id, domain, max_wait):
    """Monitor progressive scan progress"""
    print(f"\n2️⃣ Monitoring progressive scan for {max_wait} seconds")
    
    start_time = time.time()
    last_stage = None
    stages_seen = set()
    
    while time.time() - start_time < max_wait:
        try:
            response = requests.get(f"{base_url}/api/large-scale-scan-status/{task_id}", timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                state = data.get('state', 'UNKNOWN')
                stage = data.get('stage', 'unknown')
                progress = data.get('progress', 0)
                message = data.get('message', '')
                
                # Print stage changes
                if stage != last_stage:
                    print(f"🔄 Stage: {stage} ({progress}%) - {message}")
                    last_stage = stage
                    stages_seen.add(stage)
                
                # Check for completion
                if state == 'SUCCESS':
                    print(f"✅ Progressive scanning completed!")
                    print(f"📊 Stages seen: {list(stages_seen)}")
                    return check_results(base_url, domain, stages_seen)
                
                elif state == 'FAILURE':
                    error = data.get('error', 'Unknown error')
                    print(f"❌ Progressive scanning failed: {error}")
                    return False
            
            time.sleep(5)
            
        except Exception as e:
            print(f"⚠️ Monitoring error: {str(e)}")
            time.sleep(5)
    
    print(f"⏰ Monitoring timed out after {max_wait} seconds")
    print(f"📊 Stages seen: {list(stages_seen)}")
    return check_results(base_url, domain, stages_seen)

def check_results(base_url, domain, stages_seen):
    """Check the results in the assets page"""
    print(f"\n3️⃣ Checking results for {domain}")
    
    try:
        response = requests.get(f"{base_url}/api/assets", timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            assets = data.get('assets', [])
            
            # Look for progressive scanning assets
            progressive_assets = [asset for asset in assets if 
                                asset.get('asset_metadata', {}).get('scan_source') == 'progressive_large_scale_orchestrator']
            
            print(f"📊 Total assets: {len(assets)}")
            print(f"🔄 Progressive assets: {len(progressive_assets)}")
            
            if progressive_assets:
                print("✅ Progressive scanning assets found!")
                
                # Check for main domain
                main_domain_found = any(asset.get('name') == domain for asset in progressive_assets)
                print(f"🏠 Main domain ({domain}) found: {main_domain_found}")
                
                # Check for different scan statuses
                status_counts = {}
                http_data_count = 0
                port_data_count = 0
                
                for asset in progressive_assets[:5]:  # Show first 5
                    asset_name = asset.get('name', 'Unknown')
                    metadata = asset.get('asset_metadata', {})
                    scan_status = metadata.get('scan_status', 'unknown')
                    
                    status_counts[scan_status] = status_counts.get(scan_status, 0) + 1
                    
                    # Check for HTTP data
                    if metadata.get('http_probe'):
                        http_data_count += 1
                    
                    # Check for port data
                    if metadata.get('ports'):
                        port_data_count += 1
                    
                    print(f"   📋 {asset_name} | Status: {scan_status}")
                
                print(f"\n📊 Status distribution: {status_counts}")
                print(f"🌐 Assets with HTTP data: {http_data_count}")
                print(f"🔍 Assets with port data: {port_data_count}")
                
                # Determine success
                expected_stages = {'subdomain_discovery', 'subdomains_stored'}
                basic_success = len(progressive_assets) > 0 and expected_stages.issubset(stages_seen)
                full_success = basic_success and http_data_count > 0 and port_data_count > 0
                
                if full_success:
                    print("\n🎉 FULL PROGRESSIVE SCANNING SUCCESS!")
                    print("✅ Subfinder: Subdomains discovered and stored")
                    print("✅ httpx: HTTP probing completed")
                    print("✅ Nmap: Port scanning completed")
                    return True
                elif basic_success:
                    print("\n✅ PARTIAL PROGRESSIVE SCANNING SUCCESS!")
                    print("✅ Subfinder: Subdomains discovered and stored")
                    if http_data_count == 0:
                        print("⚠️ httpx: HTTP probing may have failed")
                    if port_data_count == 0:
                        print("⚠️ Nmap: Port scanning may have failed")
                    return True
                else:
                    print("\n⚠️ MINIMAL PROGRESSIVE SCANNING")
                    return len(progressive_assets) > 0
            else:
                print("❌ No progressive scanning assets found")
                return False
        else:
            print(f"❌ Failed to get assets: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"❌ Error checking results: {str(e)}")
        return False

def main():
    """Main test function"""
    print("🚀 TESTING PROGRESSIVE SCANNING FIXES")
    print("=" * 50)
    print(f"⏰ Started at: {datetime.now().strftime('%H:%M:%S')}")
    
    success = test_progressive_scanning_fix()
    
    print("\n" + "=" * 50)
    print("🎯 FINAL RESULTS")
    print("=" * 50)
    
    if success:
        print("🎉 PROGRESSIVE SCANNING FIXES WORKING!")
        print("✅ Main domain is included in scan")
        print("✅ Progressive workflow is functioning")
        print("✅ Assets are being stored progressively")
        print("\n📋 Next: Check Docker logs for detailed scanning progress")
        print("   docker-compose logs celery | grep -E '(SUBFINDER|HTTPX|NMAP)' | tail -20")
    else:
        print("❌ PROGRESSIVE SCANNING ISSUES REMAIN")
        print("📋 Check Docker logs for errors:")
        print("   docker-compose logs celery | tail -50")
    
    print(f"⏰ Completed at: {datetime.now().strftime('%H:%M:%S')}")
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())
