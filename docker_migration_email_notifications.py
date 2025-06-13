#!/usr/bin/env python3
"""
Docker-compatible migration script for email notification settings
This script adds the missing columns to the EmailNotificationSettings table in Docker environment
"""

import os
import sys
import sqlite3

def run_migration():
    """Run the email notification settings migration in Docker environment"""
    
    print("🔄 Starting Email Notification Settings Migration for Docker...")
    
    try:
        # Determine database path for Docker environment
        data_dir = '/app/data'
        db_path = os.path.join(data_dir, 'attacksurface.db')
        
        # Check if database exists
        if not os.path.exists(db_path):
            print(f"❌ Database file not found: {db_path}")
            print("🔄 Trying to initialize database first...")
            
            # Try to initialize database using Flask app context
            try:
                from app import create_app
                from models import db
                
                app = create_app()
                with app.app_context():
                    db.create_all()
                    print("✅ Database initialized successfully")
            except Exception as e:
                print(f"❌ Failed to initialize database: {str(e)}")
                return False
        
        print(f"📋 Using database: {db_path}")
        
        # Connect to SQLite database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if EmailNotificationSettings table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='email_notification_settings'
        """)
        
        if not cursor.fetchone():
            print("❌ EmailNotificationSettings table does not exist")
            print("🔄 Creating table using Flask models...")
            
            try:
                from app import create_app
                from models import db
                
                app = create_app()
                with app.app_context():
                    db.create_all()
                    print("✅ Tables created successfully")
            except Exception as e:
                print(f"❌ Failed to create tables: {str(e)}")
                return False
        
        # Get current table schema
        cursor.execute("PRAGMA table_info(email_notification_settings)")
        columns = [row[1] for row in cursor.fetchall()]
        print(f"📋 Current columns: {columns}")
        
        # Define new columns to add
        new_columns = [
            ('notification_email', 'VARCHAR(255)'),
            ('additional_recipients', 'TEXT'),
            ('alert_critical', 'BOOLEAN DEFAULT 1'),
            ('alert_high', 'BOOLEAN DEFAULT 1'),
            ('alert_medium', 'BOOLEAN DEFAULT 1'),
            ('alert_low', 'BOOLEAN DEFAULT 0'),
            ('alert_info', 'BOOLEAN DEFAULT 0')
        ]
        
        # Add missing columns
        columns_added = 0
        for column_name, column_type in new_columns:
            if column_name not in columns:
                print(f"➕ Adding column: {column_name}")
                try:
                    cursor.execute(f"""
                        ALTER TABLE email_notification_settings 
                        ADD COLUMN {column_name} {column_type}
                    """)
                    columns_added += 1
                except Exception as e:
                    print(f"❌ Failed to add column {column_name}: {str(e)}")
                    return False
            else:
                print(f"✅ Column {column_name} already exists")
        
        # Commit changes
        conn.commit()
        
        # Verify the migration
        cursor.execute("PRAGMA table_info(email_notification_settings)")
        updated_columns = [row[1] for row in cursor.fetchall()]
        print(f"📋 Updated columns: {updated_columns}")
        
        print(f"✅ Migration completed successfully! Added {columns_added} new columns.")
        
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def main():
    """Main function"""
    
    print("🚀 Docker Email Notification Settings Migration")
    print("=" * 60)
    
    success = run_migration()
    
    if success:
        print("\n🎉 Migration completed successfully!")
        print("The EmailNotificationSettings table now has all required fields:")
        print("  - notification_email (VARCHAR(255))")
        print("  - additional_recipients (TEXT)")
        print("  - alert_critical (BOOLEAN)")
        print("  - alert_high (BOOLEAN)")
        print("  - alert_medium (BOOLEAN)")
        print("  - alert_low (BOOLEAN)")
        print("  - alert_info (BOOLEAN)")
        print("\n✅ The consolidated notification settings should now work correctly!")
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
