#!/usr/bin/env python3
"""
Test script to verify httpx integration with the attack surface management application
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from tools.httpx import HttpxScanner
from tools.scanner_manager import ScannerManager
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_httpx_scanner():
    """Test the HttpxScanner directly"""
    logger.info("🧪 Testing HttpxScanner directly...")
    
    try:
        scanner = HttpxScanner()
        logger.info("✅ HttpxScanner initialized successfully")
        
        # Test with a few common domains
        test_targets = ['google.com', 'github.com', 'stackoverflow.com']
        logger.info(f"🌐 Testing HTTP probing on: {', '.join(test_targets)}")
        
        result = scanner.scan(test_targets, timeout=10, threads=10)
        
        logger.info(f"📊 Scan Results:")
        logger.info(f"   - Total targets: {len(test_targets)}")
        logger.info(f"   - Alive hosts: {len(result.get('alive_hosts', []))}")
        
        for host in result.get('alive_hosts', [])[:3]:  # Show first 3 results
            logger.info(f"   - {host.get('url', 'N/A')} -> {host.get('status_code', 'N/A')} ({host.get('title', 'No title')[:50]})")
            if host.get('tech'):
                logger.info(f"     Technologies: {', '.join(host.get('tech', []))}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ HttpxScanner test failed: {str(e)}")
        return False

def test_scanner_manager():
    """Test the ScannerManager httpx integration"""
    logger.info("🧪 Testing ScannerManager httpx integration...")
    
    try:
        manager = ScannerManager()
        logger.info("✅ ScannerManager initialized successfully")
        
        # Check if httpx is available
        tools = manager.get_available_tools()
        if not tools.get('httpx', False):
            logger.warning("⚠️  Httpx not available in ScannerManager")
            return False
        
        logger.info("✅ Httpx is available in ScannerManager")
        
        # Test httpx_scan_only method
        test_targets = ['example.com', 'httpbin.org']
        logger.info(f"🌐 Testing httpx_scan_only with: {', '.join(test_targets)}")
        
        result = manager.httpx_scan_only(test_targets, timeout=10)
        
        logger.info(f"📊 ScannerManager Results:")
        logger.info(f"   - Total targets: {len(test_targets)}")
        logger.info(f"   - Alive hosts: {len(result.get('alive_hosts', []))}")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ ScannerManager test failed: {str(e)}")
        return False

def test_tool_availability():
    """Test if httpx tool is available in the system"""
    logger.info("🧪 Testing httpx tool availability...")
    
    import subprocess
    try:
        # Try to run httpx version command
        result = subprocess.run(['httpx', '-version'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            logger.info(f"✅ Httpx tool is available: {result.stdout.strip()}")
            return True
        else:
            logger.error(f"❌ Httpx tool returned error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error("❌ Httpx tool command timed out")
        return False
    except FileNotFoundError:
        logger.error("❌ Httpx tool not found in PATH")
        return False
    except Exception as e:
        logger.error(f"❌ Error testing httpx tool: {str(e)}")
        return False

def main():
    """Run all tests"""
    logger.info("🚀 Starting httpx integration tests...")
    
    tests = [
        ("Tool Availability", test_tool_availability),
        ("HttpxScanner", test_httpx_scanner),
        ("ScannerManager", test_scanner_manager)
    ]
    
    results = {}
    
    for test_name, test_func in tests:
        logger.info(f"\n{'='*50}")
        logger.info(f"Running {test_name} test...")
        logger.info(f"{'='*50}")
        
        try:
            results[test_name] = test_func()
        except Exception as e:
            logger.error(f"❌ {test_name} test crashed: {str(e)}")
            results[test_name] = False
    
    # Summary
    logger.info(f"\n{'='*50}")
    logger.info("📋 TEST SUMMARY")
    logger.info(f"{'='*50}")
    
    passed = 0
    total = len(results)
    
    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        logger.info(f"{test_name}: {status}")
        if result:
            passed += 1
    
    logger.info(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        logger.info("🎉 All tests passed! Httpx integration is working correctly.")
        return 0
    else:
        logger.error("⚠️  Some tests failed. Check the logs above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
