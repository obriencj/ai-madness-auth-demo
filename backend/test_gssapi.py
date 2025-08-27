#!/usr/bin/env python3
"""
Test script for GSSAPI authentication functionality.

This script demonstrates how to use the GSSAPI authentication endpoints.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import requests
import json

# Configuration
BASE_URL = "http://localhost:5000/api/v1/auth"
ADMIN_TOKEN = None  # Will be set after admin login

def test_gssapi_endpoints():
    """Test the GSSAPI authentication endpoints"""
    
    print("=== GSSAPI Authentication Test ===\n")
    
    # 1. Test getting available realms (should be empty initially)
    print("1. Testing GET /gssapi/realms")
    response = requests.get(f"{BASE_URL}/gssapi/realms")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.json()}\n")
    
    # 2. Test creating a GSSAPI realm (requires admin token)
    print("2. Testing POST /gssapi/realms (requires admin)")
    print("   Note: This requires admin authentication")
    
    # Example keytab data (base64 encoded placeholder)
    # In real usage, this would be the actual base64-encoded keytab file content
    example_keytab_data = "dGVzdCBrZXl0YWIgZGF0YQ=="  # "test keytab data" in base64
    
    realm_data = {
        "name": "test_realm",
        "realm": "TEST.REALM",
        "kdc_hosts": ["kdc1.test.realm", "kdc2.test.realm"],
        "admin_server": "kadmin.test.realm",
        "service_principal": "HTTP/auth.test.realm@TEST.REALM",
        "keytab_data": example_keytab_data,
        "default_realm": True,
        "is_active": True
    }
    
    print(f"   Realm data: {json.dumps(realm_data, indent=2)}")
    print("   To test this endpoint, you need to:")
    print("   1. Login as admin user")
    print("   2. Use the admin token in the Authorization header")
    print("   3. Send POST request with the realm data\n")
    
    # 3. Test GSSAPI authentication
    print("3. Testing POST /gssapi/authenticate")
    print("   Note: This requires a valid Kerberos principal")
    
    auth_data = {
        "principal_name": "testuser@TEST.REALM",
        "realm_name": "test_realm"  # Optional
    }
    
    print(f"   Auth data: {json.dumps(auth_data, indent=2)}")
    print("   To test this endpoint, you need to:")
    print("   1. Have a valid Kerberos ticket")
    print("   2. Send the principal name in the request")
    print("   3. The system will authenticate and create/link the user\n")
    
    # 4. Test getting GSSAPI accounts
    print("4. Testing GET /gssapi/accounts (requires user token)")
    print("   Note: This requires user authentication")
    print("   To test this endpoint, you need to:")
    print("   1. Login via GSSAPI or other method")
    print("   2. Use the user token in the Authorization header")
    print("   3. The system will return linked GSSAPI accounts\n")
    
    print("5. Testing GET /gssapi/cache/stats (requires admin token)")
    print("   Note: This requires admin authentication")
    print("   To test this endpoint, you need to:")
    print("   1. Login as admin user")
    print("   2. Use the admin token in the Authorization header")
    print("   3. The system will return cache statistics\n")
    
    print("6. Testing POST /gssapi/cache/clear (requires admin token)")
    print("   Note: This requires admin authentication")
    print("   To test this endpoint, you need to:")
    print("   1. Login as admin user")
    print("   2. Use the admin token in the Authorization header")
    print("   3. The system will clear all keytab caches\n")
    
    print("=== Test Summary ===")
    print("The GSSAPI endpoints are now available at:")
    print(f"  - {BASE_URL}/gssapi/authenticate")
    print(f"  - {BASE_URL}/gssapi/realms")
    print(f"  - {BASE_URL}/gssapi/realms/<id>")
    print(f"  - {BASE_URL}/gssapi/accounts")
    print(f"  - {BASE_URL}/gssapi/cache/stats")
    print(f"  - {BASE_URL}/gssapi/cache/clear")
    print("\nTo fully test these endpoints:")
    print("1. Ensure the database has the new GSSAPI tables")
    print("2. Login as admin to manage realms")
    print("3. Use a valid Kerberos ticket for authentication")
    print("4. Check that users are created/linked correctly")

if __name__ == "__main__":
    test_gssapi_endpoints()

# The end.
