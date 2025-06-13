#!/usr/bin/env python3
"""
Migration script to add new fields to EmailNotificationSettings table
"""

import sqlite3
import sys
import os

# Add the parent directory to the path so we can import models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def migrate_database(db_path):
    """Add new fields to EmailNotificationSettings table"""
    
    print(f"🔄 Starting migration for database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if the table exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='email_notification_settings'
        """)
        
        if not cursor.fetchone():
            print("❌ EmailNotificationSettings table does not exist. Please run init_db.py first.")
            return False
        
        # Get current table schema
        cursor.execute("PRAGMA table_info(email_notification_settings)")
        columns = [row[1] for row in cursor.fetchall()]
        print(f"📋 Current columns: {columns}")
        
        # Add new columns if they don't exist
        new_columns = [
            ('notification_email', 'VARCHAR(255)'),
            ('additional_recipients', 'TEXT'),
            ('alert_critical', 'BOOLEAN DEFAULT 1'),
            ('alert_high', 'BOOLEAN DEFAULT 1'),
            ('alert_medium', 'BOOLEAN DEFAULT 1'),
            ('alert_low', 'BOOLEAN DEFAULT 0'),
            ('alert_info', 'BOOLEAN DEFAULT 0')
        ]
        
        for column_name, column_type in new_columns:
            if column_name not in columns:
                print(f"➕ Adding column: {column_name}")
                cursor.execute(f"""
                    ALTER TABLE email_notification_settings 
                    ADD COLUMN {column_name} {column_type}
                """)
            else:
                print(f"✅ Column {column_name} already exists")
        
        # Commit changes
        conn.commit()
        print("✅ Migration completed successfully!")
        
        # Verify the changes
        cursor.execute("PRAGMA table_info(email_notification_settings)")
        updated_columns = [row[1] for row in cursor.fetchall()]
        print(f"📋 Updated columns: {updated_columns}")
        
        return True
        
    except Exception as e:
        print(f"❌ Migration failed: {str(e)}")
        return False
    finally:
        if 'conn' in locals():
            conn.close()

def main():
    """Run the migration"""
    
    # Default database path
    db_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'attacksurface_dev.db')
    
    # Check if custom path provided
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    
    if not os.path.exists(db_path):
        print(f"❌ Database file not found: {db_path}")
        print("Please run init_db.py first or provide correct database path")
        sys.exit(1)
    
    print("🚀 Email Notification Settings Migration")
    print("=" * 50)
    
    success = migrate_database(db_path)
    
    if success:
        print("\n✅ Migration completed successfully!")
        print("The EmailNotificationSettings table now has the new fields:")
        print("  - notification_email (VARCHAR(255))")
        print("  - additional_recipients (TEXT)")
        print("  - alert_critical (BOOLEAN)")
        print("  - alert_high (BOOLEAN)")
        print("  - alert_medium (BOOLEAN)")
        print("  - alert_low (BOOLEAN)")
        print("  - alert_info (BOOLEAN)")
    else:
        print("\n❌ Migration failed!")
        sys.exit(1)

if __name__ == "__main__":
    main()
