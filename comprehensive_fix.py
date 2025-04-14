"""
Comprehensive fix script for EduPortal
- Fixes dependency issues
- Updates database schema
"""

import os
import sqlite3
import subprocess
import sys
import time
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

def fix_dependencies():
    """Fix dependency issues"""
    print("Fixing dependency issues...")
    try:
        packages_to_uninstall = [
            "flask", 
            "flask-login", 
            "werkzeug", 
            "flask-sqlalchemy", 
            "sqlalchemy"
        ]
        
        subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-y"] + packages_to_uninstall)
        print("Successfully uninstalled problematic packages")
        
        # Install core Flask components with compatible versions
        packages = [
            "SQLAlchemy==1.4.46",
            "Flask==2.0.1", 
            "Werkzeug==2.0.1", 
            "Flask-Login==0.5.0",
            "Flask-SQLAlchemy==2.5.1",
            "Flask-WTF==1.0.0",
            "Flask-Bcrypt==0.7.1"
        ]
        
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + packages)
        print("Successfully installed compatible versions!")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error fixing dependencies: {e}")
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
            
        # Commit the changes
        conn.commit()
        print("Database schema updated successfully!")
        
        # Close the connection
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating database schema: {e}")
        return False

def main():
    print("EduPortal Comprehensive Fix Utility")
    print("===================================")
    
    # Fix dependencies
    print("\nStep 1: Fixing dependencies...")
    if not fix_dependencies():
        if input("Dependency fix failed. Continue with database update? (y/n): ").lower() != 'y':
            print("Fix canceled.")
            return
    
    # Create a backup
    print("\nStep 2: Creating database backup...")
    if not backup_database():
        if input("Backup failed. Continue with database update? (y/n): ").lower() != 'y':
            print("Fix canceled.")
            return
    
    # Update the schema
    print("\nStep 3: Updating database schema...")
    if update_database_schema():
        print("\nFix completed successfully!")
        print("You can now run the application: python app.py")
    else:
        print("\nDatabase update failed.")
        print("Try restoring from backup before attempting to run the application.")

if __name__ == "__main__":
    main() 