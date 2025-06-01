#!/usr/bin/env python3
"""
Attack Surface Monitoring SaaS Application
Run script for development
"""

from app import create_app
from models import db

if __name__ == '__main__':
    app = create_app()
    
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Import and create sample data if no users exist
        from models import User
        if User.query.count() == 0:
            from app import create_sample_data
            create_sample_data()
            print("Sample data created!")
            print("Login with username: admin, password: password")
    
    print("Starting Attack Surface Monitoring application...")
    print("Access the application at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
