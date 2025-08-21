#!/usr/bin/env python3
"""
OAuth Provider Configuration Script

This script helps you configure OAuth providers in the database.
Run this after setting up your OAuth applications in Google Cloud Console and GitHub.
"""

import os
import sys
import psycopg2
from getpass import getpass

def get_database_connection():
    """Get database connection from environment variables"""
    database_url = os.getenv('DATABASE_URL', 'postgresql://auth_user:auth_password@localhost:5432/auth_demo')
    
    try:
        conn = psycopg2.connect(database_url)
        return conn
    except psycopg2.Error as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)

def update_oauth_provider(conn, provider_name, client_id, client_secret):
    """Update OAuth provider credentials in the database"""
    cursor = conn.cursor()
    
    try:
        # First check if the scope field exists, if not, add it
        cursor.execute("""
            SELECT column_name FROM information_schema.columns 
            WHERE table_name = 'oauth_provider' AND column_name = 'scope'
        """)
        
        if not cursor.fetchone():
            print(f"Adding scope column to oauth_provider table...")
            cursor.execute("ALTER TABLE oauth_provider ADD COLUMN scope VARCHAR(500)")
            
            # Set default scope values for existing providers
            if provider_name == 'google':
                cursor.execute("""
                    UPDATE oauth_provider 
                    SET scope = 'openid email profile' 
                    WHERE name = 'google'
                """)
            elif provider_name == 'github':
                cursor.execute("""
                    UPDATE oauth_provider 
                    SET scope = 'read:user user:email' 
                    WHERE name = 'github'
                """)
            
            # Make scope column NOT NULL
            cursor.execute("ALTER TABLE oauth_provider ALTER COLUMN scope SET NOT NULL")
            print(f"✅ Added scope column to oauth_provider table")
        
        # Update the provider credentials
        cursor.execute("""
            UPDATE oauth_provider 
            SET client_id = %s, client_secret = %s 
            WHERE name = %s
        """, (client_id, client_secret, provider_name))
        
        if cursor.rowcount == 0:
            print(f"Provider '{provider_name}' not found in database. Make sure you've run the OAuth migration.")
            return False
        
        conn.commit()
        print(f"✅ Updated {provider_name} OAuth credentials")
        return True
        
    except psycopg2.Error as e:
        print(f"Error updating {provider_name} provider: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()

def main():
    print("🔐 OAuth Provider Configuration")
    print("=" * 40)
    print()
    
    # Check if required environment variables are set
    google_client_id = os.getenv('GOOGLE_CLIENT_ID')
    google_client_secret = os.getenv('GOOGLE_CLIENT_SECRET')
    github_client_id = os.getenv('GITHUB_CLIENT_ID')
    github_client_secret = os.getenv('GITHUB_CLIENT_SECRET')
    
    print("Current OAuth configuration:")
    print(f"  Google Client ID: {'✅ Set' if google_client_id else '❌ Not set'}")
    print(f"  Google Client Secret: {'✅ Set' if google_client_secret else '❌ Not set'}")
    print(f"  GitHub Client ID: {'✅ Set' if github_client_id else '❌ Not set'}")
    print(f"  GitHub Client Secret: {'✅ Set' if github_client_secret else '❌ Not set'}")
    print()
    
    if not any([google_client_id, google_client_secret, github_client_id, github_client_secret]):
        print("❌ No OAuth credentials found in environment variables.")
        print("Please set the following environment variables:")
        print("  - GOOGLE_CLIENT_ID")
        print("  - GOOGLE_CLIENT_SECRET")
        print("  - GITHUB_CLIENT_ID")
        print("  - GITHUB_CLIENT_SECRET")
        print()
        print("You can also run this script interactively to enter credentials manually.")
        print()
        
        # Interactive mode
        use_interactive = input("Would you like to enter credentials manually? (y/n): ").lower().strip()
        if use_interactive == 'y':
            print()
            print("Enter OAuth credentials manually:")
            print()
            
            # Google OAuth
            print("Google OAuth Setup:")
            google_client_id = input("Google Client ID: ").strip()
            google_client_secret = getpass("Google Client Secret: ").strip()
            print()
            
            # GitHub OAuth
            print("GitHub OAuth Setup:")
            github_client_id = input("GitHub Client ID: ").strip()
            github_client_secret = getpass("GitHub Client Secret: ").strip()
            print()
        else:
            print("Please set the environment variables and run this script again.")
            sys.exit(1)
    
    # Connect to database
    print("Connecting to database...")
    conn = get_database_connection()
    print("✅ Connected to database")
    print()
    
    # Update providers
    success_count = 0
    
    if google_client_id and google_client_secret:
        if update_oauth_provider(conn, 'google', google_client_id, google_client_secret):
            success_count += 1
    
    if github_client_id and github_client_secret:
        if update_oauth_provider(conn, 'github', github_client_id, github_client_secret):
            success_count += 1
    
    conn.close()
    
    print()
    print("=" * 40)
    if success_count > 0:
        print(f"✅ Successfully configured {success_count} OAuth provider(s)")
        print("You can now restart your application to use OAuth authentication.")
    else:
        print("❌ No OAuth providers were configured successfully.")
        print("Please check your credentials and try again.")
    
    print()
    print("Next steps:")
    print("1. Restart your application")
    print("2. Test OAuth login on the login/register pages")
    print("3. Check the OAUTH_SETUP.md file for troubleshooting")

if __name__ == '__main__':
    main()
