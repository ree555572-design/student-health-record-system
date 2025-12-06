"""
Database Initialization Script
Run this script to create the SQLite database and tables
"""
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
from flask_wtf.csrf import CSRFProtect
import sqlite3
import os
import bcrypt

# Database file path
DATABASE = os.path.join(os.path.dirname(__file__), 'student_health.db')

def hash_password(password):
    """Hash password using bcrypt with salt"""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def create_tables():
    """Create all necessary tables"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Create users table for authentication
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                fullname TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'health_officer',
                advisory_class TEXT,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create students table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                studentLRN TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                class TEXT,
                dob DATE,
                address TEXT,
                parentContact TEXT,
                emergencyContact TEXT,
                height TEXT,
                weight TEXT,
                blood TEXT,
                pastIllnesses TEXT,
                allergies TEXT,
                conditions TEXT,
                vaccination TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create teachers table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS teachers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacherID TEXT UNIQUE NOT NULL,
                name TEXT NOT NULL,
                department TEXT,
                dob DATE,
                address TEXT,
                contact TEXT,
                height TEXT,
                weight TEXT,
                blood TEXT,
                pastIllnesses TEXT,
                allergies TEXT,
                conditions TEXT,
                vaccination TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create inventory table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL,
                category TEXT,
                quantity INTEGER DEFAULT 0,
                unit TEXT,
                status TEXT DEFAULT 'available',
                expiry_date DATE,
                reorder_level INTEGER DEFAULT 5,
                supplier TEXT,
                notes TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create health reminders table (for vaccination updates, checkups)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS health_reminders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_type TEXT NOT NULL,
                person_id INTEGER NOT NULL,
                reminder_type TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                due_date DATE,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create alerts table (for missing info, expiry dates, etc)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT DEFAULT 'normal',
                title TEXT NOT NULL,
                description TEXT,
                person_type TEXT,
                person_id INTEGER,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create missing information log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS missing_info_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                person_type TEXT NOT NULL,
                person_id INTEGER NOT NULL,
                field_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create emergency contacts quick access table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS emergency_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id INTEGER,
                teacher_id INTEGER,
                alert_message TEXT NOT NULL,
                alert_status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create audit log table for tracking all modifications
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                table_name TEXT NOT NULL,
                record_id INTEGER,
                old_values TEXT,
                new_values TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        
        # Create backup log table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS backup_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                backup_name TEXT NOT NULL,
                backup_path TEXT NOT NULL,
                backup_size INTEGER,
                backup_type TEXT DEFAULT 'manual',
                created_by INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(created_by) REFERENCES users(id)
            )
        """)
        
        # Reset all data tables - delete sample records (only from tables that exist)
        try:
            cursor.execute("DELETE FROM students")
            cursor.execute("DELETE FROM teachers")
            cursor.execute("DELETE FROM health_records")
            cursor.execute("DELETE FROM inventory")
            cursor.execute("DELETE FROM health_reminders")
            cursor.execute("DELETE FROM audit_log")
            cursor.execute("DELETE FROM backup_log")
        except sqlite3.OperationalError:
            pass  # Tables might not exist on first run
        
        # Reset users table and create strong super admin user
        cursor.execute("DELETE FROM users")
        
        # Strong credentials for super admin
        admin_username = "SuperAdmin2025"
        admin_password = "LyfjSHS@SecureAdmin#2025!Kxq7Mw9Pn"
        admin_fullname = "System Administrator"
        admin_email = "admin@lyfjshs.local"
        admin_hashed_password = hash_password(admin_password)
        
        # Create super admin user
        cursor.execute("""
            INSERT INTO users (username, password, fullname, email, role, is_active)
            VALUES (?, ?, ?, ?, 'super_admin', 1)
        """, (admin_username, admin_hashed_password, admin_fullname, admin_email))
        
        conn.commit()
        print("Tables created successfully")
        print("\n" + "="*60)
        print("SUPER ADMIN USER CREATED")
        print("="*60)
        print(f"Username: {admin_username}")
        print(f"Password: {admin_password}")
        print(f"Email: {admin_email}")
        print("="*60)
        print("IMPORTANT: Save these credentials securely!")
        print("="*60 + "\n")
        
        cursor.close()
        conn.close()
        
    except sqlite3.Error as e:
        print(f"Error creating tables: {e}")

def migrate_existing_database():
    """Migrate existing database to add new columns if they don't exist"""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        
        # Check if role column exists in users table
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if "role" not in columns:
            print("Migrating users table: Adding 'role' column...")
            cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'health_officer'")
            conn.commit()
            print("✓ Added 'role' column")
        
        if "is_active" not in columns:
            print("Migrating users table: Adding 'is_active' column...")
            cursor.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
            conn.commit()
            print("✓ Added 'is_active' column")
        
        # Check if audit_log table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
        if not cursor.fetchone():
            print("Creating audit_log table...")
            cursor.execute("""
                CREATE TABLE audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    username TEXT,
                    action TEXT NOT NULL,
                    table_name TEXT,
                    record_id INTEGER,
                    old_values TEXT,
                    new_values TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✓ Created audit_log table")
        
        # Check if backup_log table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='backup_log'")
        if not cursor.fetchone():
            print("Creating backup_log table...")
            cursor.execute("""
                CREATE TABLE backup_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    backup_name TEXT NOT NULL,
                    backup_path TEXT NOT NULL,
                    backup_size INTEGER,
                    backup_type TEXT,
                    created_by TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✓ Created backup_log table")
        
        # Check if inventory table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='inventory'")
        if not cursor.fetchone():
            print("Creating inventory table...")
            cursor.execute("""
                CREATE TABLE inventory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_name TEXT NOT NULL,
                    category TEXT,
                    quantity INTEGER DEFAULT 0,
                    unit TEXT,
                    status TEXT DEFAULT 'available',
                    expiry_date DATE,
                    reorder_level INTEGER DEFAULT 5,
                    supplier TEXT,
                    notes TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("✓ Created inventory table")
        
        cursor.close()
        conn.close()
        print("Database migration complete!")
        
    except sqlite3.Error as e:
        print(f"Error during migration: {e}")

if __name__ == "__main__":
    print("Initializing SQLite database...")
    print(f"Database will be created at: {DATABASE}")
    create_tables()
    migrate_existing_database()
    print("Database initialization complete!")
    print(f"Database file location: {os.path.abspath(DATABASE)}")
