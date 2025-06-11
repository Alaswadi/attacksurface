#!/usr/bin/env python3
"""
Test SQLite connection and database setup
This script helps diagnose SQLite connection issues in Docker
"""

import os
import sys
import sqlite3

def test_sqlite_connection():
    """Test SQLite connection and setup"""
    try:
        print("🔄 Testing SQLite connection...")
        
        # Test 1: Check data directory
        data_dir = '/app/data'
        print(f"📁 Checking data directory: {data_dir}")
        
        if not os.path.exists(data_dir):
            print(f"❌ Data directory does not exist: {data_dir}")
            try:
                os.makedirs(data_dir, mode=0o755, exist_ok=True)
                print(f"✅ Created data directory: {data_dir}")
            except Exception as e:
                print(f"❌ Failed to create data directory: {e}")
                return False
        else:
            print(f"✅ Data directory exists: {data_dir}")
        
        # Test 2: Check directory permissions
        try:
            test_file = os.path.join(data_dir, 'test_write.tmp')
            with open(test_file, 'w') as f:
                f.write('test')
            os.remove(test_file)
            print(f"✅ Data directory is writable")
        except Exception as e:
            print(f"❌ Data directory is not writable: {e}")
            return False
        
        # Test 3: Test direct SQLite connection
        db_path = os.path.join(data_dir, 'test_connection.db')
        print(f"🔗 Testing direct SQLite connection: {db_path}")
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute('CREATE TABLE IF NOT EXISTS test (id INTEGER PRIMARY KEY, name TEXT)')
            cursor.execute('INSERT INTO test (name) VALUES (?)', ('test_connection',))
            conn.commit()
            
            cursor.execute('SELECT * FROM test')
            result = cursor.fetchone()
            print(f"✅ SQLite connection successful: {result}")
            
            conn.close()
            os.remove(db_path)  # Clean up
            
        except Exception as e:
            print(f"❌ Direct SQLite connection failed: {e}")
            return False
        
        # Test 4: Test Flask app database connection
        print("🔗 Testing Flask app database connection...")
        
        try:
            from app import create_app, db
            
            app = create_app()
            
            with app.app_context():
                print(f"📋 Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")
                
                # Test database connection
                db.create_all()
                print("✅ Flask database connection successful")
                
                # Test a simple query
                from sqlalchemy import text
                result = db.session.execute(text('SELECT 1 as test'))
                test_value = result.scalar()
                print(f"✅ Database query successful: {test_value}")
                
        except Exception as e:
            print(f"❌ Flask database connection failed: {e}")
            import traceback
            traceback.print_exc()
            return False
        
        print("🎉 All SQLite connection tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ SQLite connection test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def show_environment_info():
    """Show environment information for debugging"""
    print("🔍 Environment Information:")
    print(f"   Python version: {sys.version}")
    print(f"   Current working directory: {os.getcwd()}")
    print(f"   User ID: {os.getuid() if hasattr(os, 'getuid') else 'N/A'}")
    print(f"   Group ID: {os.getgid() if hasattr(os, 'getgid') else 'N/A'}")
    
    # Check environment variables
    env_vars = ['FLASK_CONFIG', 'DATABASE_URL', 'SECRET_KEY']
    for var in env_vars:
        value = os.environ.get(var, 'Not set')
        if var == 'SECRET_KEY' and value != 'Not set':
            value = f"{value[:10]}..." if len(value) > 10 else value
        print(f"   {var}: {value}")
    
    # Check file system
    paths_to_check = ['/app', '/app/data', '/app/logs']
    for path in paths_to_check:
        if os.path.exists(path):
            stat = os.stat(path)
            print(f"   {path}: exists (mode: {oct(stat.st_mode)[-3:]})")
        else:
            print(f"   {path}: does not exist")

if __name__ == "__main__":
    print("🚀 Running SQLite connection test...")
    print("=" * 50)
    
    show_environment_info()
    print("=" * 50)
    
    success = test_sqlite_connection()
    
    print("=" * 50)
    if success:
        print("🎉 SQLite connection test completed successfully!")
    else:
        print("💥 SQLite connection test failed!")
        sys.exit(1)
