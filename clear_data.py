#!/usr/bin/env python3
"""
Utility script to clear all data from the database
This script removes all assets, vulnerabilities, alerts, and scan results
while keeping user accounts intact.
"""

import os
import sys
from flask import Flask
from models import db, Asset, Vulnerability, Alert, ScanResult, Organization
from config import config

def create_app():
    """Create Flask app for database operations"""
    app = Flask(__name__)
    
    # Use development config by default
    config_name = os.environ.get('FLASK_CONFIG', 'development')
    app.config.from_object(config[config_name])
    
    # Initialize database
    db.init_app(app)
    
    return app

def clear_all_data():
    """Clear all data from the database except users"""
    app = create_app()
    
    with app.app_context():
        try:
            print("🔄 Clearing all data from database...")
            
            # Delete in order to respect foreign key constraints
            print("  - Deleting scan results...")
            ScanResult.query.delete()
            
            print("  - Deleting alerts...")
            Alert.query.delete()
            
            print("  - Deleting vulnerabilities...")
            Vulnerability.query.delete()
            
            print("  - Deleting assets...")
            Asset.query.delete()
            
            # Commit all deletions
            db.session.commit()
            
            print("✅ All data cleared successfully!")
            print("ℹ️  User accounts have been preserved")
            
        except Exception as e:
            print(f"❌ Error clearing data: {e}")
            db.session.rollback()
            sys.exit(1)

def clear_everything():
    """Clear everything including users (complete reset)"""
    app = create_app()
    
    with app.app_context():
        try:
            print("🔄 Clearing EVERYTHING from database...")
            
            # Delete all tables
            db.drop_all()
            
            # Recreate all tables
            db.create_all()
            
            print("✅ Database completely reset!")
            print("ℹ️  All tables recreated - you'll need to register a new user")
            
        except Exception as e:
            print(f"❌ Error resetting database: {e}")
            sys.exit(1)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Clear data from the database')
    parser.add_argument('--all', action='store_true', 
                       help='Clear everything including users (complete reset)')
    parser.add_argument('--data-only', action='store_true', 
                       help='Clear only assets, vulnerabilities, alerts (keep users)')
    
    args = parser.parse_args()
    
    if args.all:
        confirm = input("⚠️  This will delete EVERYTHING including users. Are you sure? (yes/no): ")
        if confirm.lower() == 'yes':
            clear_everything()
        else:
            print("Operation cancelled.")
    elif args.data_only:
        confirm = input("⚠️  This will delete all assets, vulnerabilities, and alerts. Continue? (yes/no): ")
        if confirm.lower() == 'yes':
            clear_all_data()
        else:
            print("Operation cancelled.")
    else:
        print("Usage:")
        print("  python clear_data.py --data-only    # Clear assets/vulnerabilities/alerts only")
        print("  python clear_data.py --all          # Complete database reset")
