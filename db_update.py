"""
Database update script to fix the database schema issues
"""

import os
import sqlite3
from datetime import datetime

def backup_database():
    """Create a backup of the current database"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        if os.path.exists('eduportal.db'):
            os.system(f'copy eduportal.db eduportal_backup_{timestamp}.db')
            print(f"Backup created: eduportal_backup_{timestamp}.db")
        return True
    except Exception as e:
        print(f"Error creating backup: {e}")
        return False

def update_database_schema():
    """Add missing columns to the database"""
    try:
        # Connect to the database
        conn = sqlite3.connect('eduportal.db')
        cursor = conn.cursor()
        
        # Check columns in question table
        cursor.execute("PRAGMA table_info(question)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add time_limit column if it doesn't exist
        if 'time_limit' not in columns:
            print("Adding time_limit column to question table...")
            cursor.execute("ALTER TABLE question ADD COLUMN time_limit INTEGER DEFAULT 30")
            print("Added time_limit column with default value of 30")
        else:
            print("time_limit column already exists.")
        
        # Add exam_time_limit column if it doesn't exist
        if 'exam_time_limit' not in columns:
            print("Adding exam_time_limit column to question table...")
            cursor.execute("ALTER TABLE question ADD COLUMN exam_time_limit INTEGER DEFAULT 60")
            print("Added exam_time_limit column with default value of 60")
        else:
            print("exam_time_limit column already exists.")
        
        # Check if the notice table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='notice'")
        notice_table_exists = cursor.fetchone() is not None
        
        if notice_table_exists:
            # Check columns in notice table
            cursor.execute("PRAGMA table_info(notice)")
            notice_columns = [column[1] for column in cursor.fetchall()]
            
            # Add title column if it doesn't exist
            if 'title' not in notice_columns:
                print("Adding title column to notice table...")
                cursor.execute("ALTER TABLE notice ADD COLUMN title TEXT DEFAULT 'Untitled Notice'")
                print("Added title column with default value of 'Untitled Notice'")
            else:
                print("title column already exists in notice table.")
                
            # Add created_at column if it doesn't exist
            if 'created_at' not in notice_columns:
                print("Adding created_at column to notice table...")
                cursor.execute("ALTER TABLE notice ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                print("Added created_at column with default value of current timestamp")
            else:
                print("created_at column already exists in notice table.")
        else:
            print("Notice table does not exist. It will be created when the application runs.")
            
        # Commit the changes
        conn.commit()
        print("Database schema updated successfully!")
        
        # Close the connection
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating database schema: {e}")
        return False

if __name__ == "__main__":
    print("Database Update Utility")
    print("=======================")
    
    # Create a backup
    print("\nStep 1: Creating database backup...")
    if not backup_database():
        if input("Backup failed. Continue anyway? (y/n): ").lower() != 'y':
            print("Update canceled.")
            exit()
    
    # Update the schema
    print("\nStep 2: Updating database schema...")
    if update_database_schema():
        print("\nDatabase update completed successfully!")
        print("You can now run the application: python app.py")
    else:
        print("\nDatabase update failed.")
        print("Try restoring from backup before attempting to run the application.") 