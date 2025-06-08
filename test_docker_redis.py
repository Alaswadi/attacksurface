#!/usr/bin/env python3
"""
Docker Redis Connection Test
Tests Redis connectivity in Docker environment using environment variables
"""

import os
import sys
import redis
import logging
from urllib.parse import urlparse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def test_redis_connection():
    """Test Redis connection using environment variables"""
    
    # Get Redis URL from environment (Docker setup)
    redis_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
    
    logger.info(f"🔍 Testing Redis connection...")
    logger.info(f"📍 Redis URL: {redis_url.replace(':password@', ':***@') if ':' in redis_url else redis_url}")
    
    try:
        # Parse Redis URL
        parsed = urlparse(redis_url)
        
        # Extract connection details
        host = parsed.hostname or 'localhost'
        port = parsed.port or 6379
        password = parsed.password
        db = int(parsed.path.lstrip('/')) if parsed.path else 0
        
        logger.info(f"🌐 Connecting to Redis at {host}:{port} (db={db})")
        
        # Create Redis connection
        if password:
            r = redis.Redis(host=host, port=port, password=password, db=db, decode_responses=True)
        else:
            r = redis.Redis(host=host, port=port, db=db, decode_responses=True)
        
        # Test connection with ping
        logger.info("📡 Testing Redis ping...")
        response = r.ping()
        
        if response:
            logger.info("✅ Redis ping successful!")
            
            # Test basic operations
            logger.info("🧪 Testing basic Redis operations...")
            
            # Set a test key
            test_key = 'docker_test_key'
            test_value = 'docker_test_value'
            r.set(test_key, test_value, ex=60)  # Expire in 60 seconds
            logger.info(f"✅ SET operation successful: {test_key} = {test_value}")
            
            # Get the test key
            retrieved_value = r.get(test_key)
            if retrieved_value == test_value:
                logger.info(f"✅ GET operation successful: {test_key} = {retrieved_value}")
            else:
                logger.error(f"❌ GET operation failed: expected {test_value}, got {retrieved_value}")
                return False
            
            # Delete the test key
            r.delete(test_key)
            logger.info(f"✅ DELETE operation successful: {test_key} removed")
            
            # Test Redis info
            logger.info("📊 Getting Redis server info...")
            info = r.info()
            logger.info(f"✅ Redis version: {info.get('redis_version', 'unknown')}")
            logger.info(f"✅ Redis mode: {info.get('redis_mode', 'unknown')}")
            logger.info(f"✅ Connected clients: {info.get('connected_clients', 'unknown')}")
            
            logger.info("🎉 All Redis tests passed!")
            return True
            
        else:
            logger.error("❌ Redis ping failed!")
            return False
            
    except redis.ConnectionError as e:
        logger.error(f"❌ Redis connection error: {str(e)}")
        logger.error("💡 Possible causes:")
        logger.error("   - Redis server is not running")
        logger.error("   - Wrong host/port configuration")
        logger.error("   - Network connectivity issues")
        logger.error("   - Authentication problems")
        return False
        
    except redis.AuthenticationError as e:
        logger.error(f"❌ Redis authentication error: {str(e)}")
        logger.error("💡 Check your Redis password configuration")
        return False
        
    except Exception as e:
        logger.error(f"❌ Unexpected error: {str(e)}")
        return False

def test_celery_broker():
    """Test Celery broker connectivity"""
    logger.info("\n🔧 Testing Celery broker connectivity...")
    
    try:
        from celery import Celery
        
        # Get broker URL from environment
        broker_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')
        result_backend = os.environ.get('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0')
        
        logger.info(f"📍 Broker URL: {broker_url.replace(':password@', ':***@') if ':' in broker_url else broker_url}")
        logger.info(f"📍 Result Backend: {result_backend.replace(':password@', ':***@') if ':' in result_backend else result_backend}")
        
        # Create Celery app
        app = Celery('test_app')
        app.conf.update(
            broker_url=broker_url,
            result_backend=result_backend,
            task_serializer='json',
            accept_content=['json'],
            result_serializer='json',
            timezone='UTC',
            enable_utc=True,
        )
        
        # Test broker connection
        logger.info("🔗 Testing Celery broker connection...")
        
        # Get broker connection
        with app.connection() as conn:
            conn.ensure_connection(max_retries=3)
            logger.info("✅ Celery broker connection successful!")
            
        logger.info("🎉 Celery broker test passed!")
        return True
        
    except Exception as e:
        logger.error(f"❌ Celery broker test failed: {str(e)}")
        return False

def main():
    """Main test function"""
    logger.info("🐳 Docker Redis Connection Test")
    logger.info("=" * 50)
    
    # Print environment info
    logger.info("🌍 Environment Variables:")
    logger.info(f"   CELERY_BROKER_URL: {os.environ.get('CELERY_BROKER_URL', 'Not set')}")
    logger.info(f"   CELERY_RESULT_BACKEND: {os.environ.get('CELERY_RESULT_BACKEND', 'Not set')}")
    logger.info(f"   FLASK_CONFIG: {os.environ.get('FLASK_CONFIG', 'Not set')}")
    
    # Test Redis connection
    redis_success = test_redis_connection()
    
    # Test Celery broker
    celery_success = test_celery_broker()
    
    # Final results
    logger.info("\n" + "=" * 50)
    logger.info("📊 TEST RESULTS")
    logger.info("=" * 50)
    logger.info(f"🔍 Redis Connection: {'✅ PASS' if redis_success else '❌ FAIL'}")
    logger.info(f"🔧 Celery Broker: {'✅ PASS' if celery_success else '❌ FAIL'}")
    
    if redis_success and celery_success:
        logger.info("🎉 ALL TESTS PASSED - Redis is ready for large-scale scanning!")
        return 0
    else:
        logger.error("💥 SOME TESTS FAILED - Check Redis configuration")
        return 1

if __name__ == '__main__':
    sys.exit(main())
