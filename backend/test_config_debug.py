#!/usr/bin/env python3
"""
Test script to debug the configuration service and GSSAPI realms.

This script will:
1. Check what's in the database
2. Test the configuration service
3. Show what's being returned

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import os
import sys
import requests

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set up environment
os.environ['FLASK_ENV'] = 'development'
os.environ['DATABASE_URL'] = 'postgresql://auth_user:auth_pass@localhost:5432/auth_demo'
os.environ['REDIS_URL'] = 'redis://localhost:6379/0'
os.environ['JWT_SECRET_KEY'] = 'test-secret-key'
os.environ['GSSAPI_MASTER_KEY'] = 'test-master-key'

def test_database_connection():
    """Test database connection and show GSSAPI realms."""
    print("=== Testing Database Connection ===")
    
    try:
        from gilla_auth.api.model import db, GSSAPIRealm
        
        # Initialize database
        db.init_app(None)
        
        with db.app.app_context():
            # Check if table exists
            try:
                realms = GSSAPIRealm.query.all()
                print(f"Found {len(realms)} GSSAPI realms in database:")
                for realm in realms:
                    print(f"  - ID: {realm.id}, Name: {realm.name}, Realm: {realm.realm}, Active: {realm.is_active}")
            except Exception as e:
                print(f"Error querying GSSAPI realms: {e}")
                
    except Exception as e:
        print(f"Error connecting to database: {e}")

def test_config_service():
    """Test the configuration service directly."""
    print("\n=== Testing Configuration Service ===")
    
    try:
        from gilla_auth.api.config import ConfigService
        
        # Get default config
        default_config = ConfigService.get_default_config()
        print("Default config:")
        print(f"  GSSAPI enabled: {default_config.get('auth', {}).get('gssapi_enabled')}")
        print(f"  OAuth enabled: {default_config.get('auth', {}).get('oauth_enabled')}")
        print(f"  GSSAPI realms: {default_config.get('gssapi_realms')}")
        print(f"  OAuth providers: {default_config.get('oauth_providers')}")
        
        # Get active config
        active_config = ConfigService.get_active_config()
        print("\nActive config:")
        print(f"  GSSAPI enabled: {active_config.get('auth', {}).get('gssapi_enabled')}")
        print(f"  OAuth enabled: {active_config.get('auth', {}).get('oauth_enabled')}")
        print(f"  GSSAPI realms: {active_config.get('gssapi_realms')}")
        print(f"  OAuth providers: {active_config.get('oauth_providers')}")
        
    except Exception as e:
        print(f"Error testing config service: {e}")

def test_public_config_endpoint():
    """Test the public config endpoint."""
    print("\n=== Testing Public Config Endpoint ===")
    
    try:
        response = requests.get('http://localhost:8000/api/v1/auth/config')
        print(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            config = data.get('config', {})
            print("Public config response:")
            print(f"  Auth keys: {list(config.get('auth', {}).keys())}")
            print(f"  GSSAPI enabled: {config.get('auth', {}).get('gssapi_enabled')}")
            print(f"  OAuth enabled: {config.get('auth', {}).get('oauth_enabled')}")
            print(f"  GSSAPI realms count: {len(config.get('gssapi_realms', []))}")
            print(f"  OAuth providers count: {len(config.get('oauth_providers', []))}")
        else:
            print(f"Error response: {response.text}")
            
    except Exception as e:
        print(f"Error testing public config endpoint: {e}")

if __name__ == '__main__':
    print("GSSAPI Configuration Debug Script")
    print("=" * 40)
    
    test_database_connection()
    test_config_service()
    test_public_config_endpoint()
    
    print("\n=== Debug Complete ===")

# The end.
