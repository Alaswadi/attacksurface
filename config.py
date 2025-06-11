import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'

    # Database configuration with proper path handling
    @staticmethod
    def get_database_uri():
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            return database_url

        # Default SQLite path - ensure directory exists
        db_dir = os.path.join(os.getcwd(), 'data')
        os.makedirs(db_dir, exist_ok=True)
        return f'sqlite:///{os.path.join(db_dir, "attacksurface.db")}'

    SQLALCHEMY_DATABASE_URI = get_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Mail settings
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT') or 587)
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    
    # Celery Configuration (New Format)
    broker_url = os.environ.get('CELERY_BROKER_URL') or 'redis://localhost:6379/0'
    result_backend = os.environ.get('CELERY_RESULT_BACKEND') or 'redis://localhost:6379/0'

    # Development fallback settings
    REDIS_AVAILABLE = True  # Will be checked at runtime
    CELERY_FALLBACK_MODE = os.environ.get('CELERY_FALLBACK_MODE', 'false').lower() == 'true'

    # Additional Celery settings for large-scale scanning
    task_serializer = 'json'
    accept_content = ['json']
    result_serializer = 'json'
    timezone = 'UTC'
    enable_utc = True
    task_track_started = True
    task_time_limit = 3600  # 1 hour max per task
    task_soft_time_limit = 3300  # 55 minutes soft limit
    worker_prefetch_multiplier = 1  # Prevent worker overload
    task_acks_late = True  # Ensure task completion
    worker_disable_rate_limits = False
    
    # Pagination
    POSTS_PER_PAGE = 25
    
    # Security
    WTF_CSRF_ENABLED = True
    
class DevelopmentConfig(Config):
    DEBUG = True

    @staticmethod
    def get_database_uri():
        database_url = os.environ.get('DEV_DATABASE_URL')
        if database_url:
            return database_url

        # Development SQLite path
        db_dir = os.path.join(os.getcwd(), 'data')
        os.makedirs(db_dir, exist_ok=True)
        return f'sqlite:///{os.path.join(db_dir, "attacksurface_dev.db")}'

    SQLALCHEMY_DATABASE_URI = get_database_uri()

class ProductionConfig(Config):
    DEBUG = False

    @staticmethod
    def get_database_uri():
        database_url = os.environ.get('DATABASE_URL')
        if database_url:
            return database_url

        # Production SQLite path - Docker-friendly
        db_dir = '/app/data'
        os.makedirs(db_dir, exist_ok=True)
        return f'sqlite:///{os.path.join(db_dir, "attacksurface.db")}'

    SQLALCHEMY_DATABASE_URI = get_database_uri()

class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
