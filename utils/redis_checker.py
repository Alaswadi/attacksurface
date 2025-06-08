#!/usr/bin/env python3
"""
Redis Connection Checker for Attack Surface Management Application
Provides utilities to check Redis availability and handle fallback scenarios
"""

import logging
import redis
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

class RedisChecker:
    """Utility class to check Redis availability and manage connections"""
    
    def __init__(self, redis_url='redis://localhost:6379/0'):
        self.redis_url = redis_url
        self.is_available = False
        self.connection = None
        self.error_message = None
        
    def check_connection(self, timeout=3):
        """
        Check if Redis is available and can be connected to
        
        Args:
            timeout (int): Connection timeout in seconds
            
        Returns:
            bool: True if Redis is available, False otherwise
        """
        try:
            # Parse Redis URL
            parsed = urlparse(self.redis_url)
            
            # Create Redis connection
            self.connection = redis.Redis(
                host=parsed.hostname or 'localhost',
                port=parsed.port or 6379,
                db=int(parsed.path.lstrip('/')) if parsed.path else 0,
                password=parsed.password,
                socket_connect_timeout=timeout,
                socket_timeout=timeout,
                retry_on_timeout=False
            )
            
            # Test connection with ping
            response = self.connection.ping()
            
            if response:
                self.is_available = True
                self.error_message = None
                logger.info(f"✅ Redis connection successful: {self.redis_url}")
                return True
            else:
                self.is_available = False
                self.error_message = "Redis ping failed"
                logger.warning(f"❌ Redis ping failed: {self.redis_url}")
                return False
                
        except redis.ConnectionError as e:
            self.is_available = False
            self.error_message = f"Redis connection error: {str(e)}"
            logger.warning(f"❌ Redis connection failed: {str(e)}")
            return False
            
        except redis.TimeoutError as e:
            self.is_available = False
            self.error_message = f"Redis timeout: {str(e)}"
            logger.warning(f"❌ Redis timeout: {str(e)}")
            return False
            
        except Exception as e:
            self.is_available = False
            self.error_message = f"Unexpected Redis error: {str(e)}"
            logger.error(f"❌ Unexpected Redis error: {str(e)}")
            return False
    
    def get_status_info(self):
        """
        Get detailed status information about Redis connection
        
        Returns:
            dict: Status information including availability, error messages, etc.
        """
        return {
            'available': self.is_available,
            'redis_url': self.redis_url,
            'error_message': self.error_message,
            'connection_active': self.connection is not None
        }
    
    def get_redis_info(self):
        """
        Get Redis server information if available
        
        Returns:
            dict: Redis server info or None if not available
        """
        if not self.is_available or not self.connection:
            return None
            
        try:
            info = self.connection.info()
            return {
                'redis_version': info.get('redis_version'),
                'used_memory_human': info.get('used_memory_human'),
                'connected_clients': info.get('connected_clients'),
                'uptime_in_seconds': info.get('uptime_in_seconds')
            }
        except Exception as e:
            logger.error(f"Failed to get Redis info: {str(e)}")
            return None

def check_redis_availability(redis_url=None):
    """
    Quick function to check if Redis is available
    Uses environment variables for Docker compatibility

    Args:
        redis_url (str): Redis connection URL (optional, uses env vars if not provided)

    Returns:
        tuple: (is_available, error_message)
    """
    import os

    # Use environment variable if available (Docker), otherwise default to localhost
    if redis_url is None:
        redis_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')

    checker = RedisChecker(redis_url)
    is_available = checker.check_connection()
    return is_available, checker.error_message

def get_redis_status_message(redis_url=None):
    """
    Get a user-friendly status message about Redis availability
    Uses environment variables for Docker compatibility

    Args:
        redis_url (str): Redis connection URL (optional, uses env vars if not provided)

    Returns:
        dict: Status message with recommendations
    """
    import os

    # Use environment variable if available (Docker), otherwise default to localhost
    if redis_url is None:
        redis_url = os.environ.get('CELERY_BROKER_URL', 'redis://localhost:6379/0')

    is_available, error_message = check_redis_availability(redis_url)
    
    if is_available:
        return {
            'status': 'available',
            'message': '✅ Redis is running and ready for Celery tasks',
            'recommendation': 'Large-scale scanning with background tasks is available'
        }
    else:
        return {
            'status': 'unavailable',
            'message': f'❌ Redis is not available: {error_message}',
            'recommendation': 'Install and start Redis for background task processing, or use fallback mode for basic scanning'
        }

# Global Redis checker instance
redis_checker = None

def initialize_redis_checker(redis_url):
    """Initialize global Redis checker instance"""
    global redis_checker
    redis_checker = RedisChecker(redis_url)
    return redis_checker.check_connection()

def is_redis_available():
    """Check if Redis is available using global checker"""
    global redis_checker
    if redis_checker is None:
        return False
    return redis_checker.is_available

def get_redis_error():
    """Get Redis error message using global checker"""
    global redis_checker
    if redis_checker is None:
        return "Redis checker not initialized"
    return redis_checker.error_message
