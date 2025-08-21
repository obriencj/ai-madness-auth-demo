#!/usr/bin/env python3
"""
Database Migration Script for OAuth Provider Scope Field

This script adds the scope field to existing oauth_provider tables
and sets appropriate default values for Google and GitHub providers.
"""

import os
import sys
import psycopg2

def get_database_connection():
    """Get database connection from environment variables"""
    database_url = os.getenv('DATABASE_URL', 'postgresql://auth_user:auth_password@localhost:5432/auth_demo')
    
    try:
        conn = psycopg2.connect(database_url)
        return conn
    except psycopg2.Error as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)

def migrate_scope_field(conn):
    """Add scope field to oauth_provider table if it doesn't exist"""
    cursor = conn.cursor()
    
    try:
        # Check if scope column already exists
        cursor.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'oauth_provider' AND column_name = 'scope'
        """)
        
        if cursor.fetchone():
            print("✅ Scope column already exists in oauth_provider table")
            return True
        
        print("Adding scope column to oauth_provider table...")
        
        # Add scope column
        cursor.execute("ALTER TABLE oauth_provider ADD COLUMN scope VARCHAR(500)")
        
        # Set default scope values for existing providers
        cursor.execute("""
            UPDATE oauth_provider 
            SET scope = 'openid email profile' 
            WHERE name = 'google'
        """)
        
        cursor.execute("""
            UPDATE oauth_provider 
            SET scope = 'read:user user:email' 
            WHERE name = 'github'
        """)
        
        # Make scope column NOT NULL
        cursor.execute("ALTER TABLE oauth_provider ALTER COLUMN scope SET NOT NULL")
        
        conn.commit()
        print("✅ Successfully added scope column to oauth_provider table")
        print("✅ Set default scope values for Google and GitHub providers")
        return True
        
    except psycopg2.Error as e:
        print(f"❌ Error migrating scope field: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()

def main():
    print("🔄 OAuth Provider Scope Field Migration")
    print("=" * 50)
    print()
    
    print("This script will add the scope field to your oauth_provider table")
    print("and set appropriate default values for existing providers.")
    print()
    
    # Connect to database
    print("Connecting to database...")
    conn = get_database_connection()
    print("✅ Connected to database")
    print()
    
    # Run migration
    if migrate_scope_field(conn):
        print()
        print("🎉 Migration completed successfully!")
        print()
        print("Next steps:")
        print("1. Restart your backend application")
        print("2. The scope field is now fully managed in the database")
        print("3. You can update OAuth provider scopes through the admin API")
    else:
        print()
        print("❌ Migration failed. Please check the error messages above.")
        sys.exit(1)
    
    conn.close()

if __name__ == '__main__':
    main()
