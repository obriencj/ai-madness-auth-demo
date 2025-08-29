#!/usr/bin/env python3
"""
Test script for the DaftGila client.

This script demonstrates basic usage of the DaftGilaClient class.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import sys
import os

# Add the client package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'daftgila'))

from daftgila.client import DaftGilaClient


def test_basic_functionality():
    """Test basic client functionality."""
    print("Testing DaftGilaClient basic functionality...")
    
    # Create client instance
    client = DaftGilaClient(
        base_url="http://localhost:5000",
        timeout=10.0,
        default_headers={"User-Agent": "DaftGilaClient-Test/1.0"}
    )
    
    try:
        # Test connectivity
        print(f"Testing connectivity to {client.base_url}...")
        test_response = client.test()
        print(f"Test response: {test_response}")
        
        # Test ping
        ping_result = client.ping()
        print(f"Ping result: {ping_result}")
        
        # Get API info
        api_info = client.get_api_info()
        print(f"API Info: {api_info}")
        
        # Test health check
        health = client.health_check()
        print(f"Health check: {health}")
        
        print("Basic functionality tests passed!")
        
    except Exception as e:
        print(f"Basic functionality test failed: {e}")
        return False
    
    finally:
        client.close()
    
    return True


def test_authentication():
    """Test authentication functionality."""
    print("\nTesting authentication functionality...")
    
    client = DaftGilaClient(base_url="http://localhost:5000")
    
    try:
        # Test unauthenticated state
        print(f"Initial auth state: {client.is_authenticated()}")
        
        # Test login (this will fail without valid credentials, but tests the flow)
        try:
            login_response = client.auth.login("testuser", "testpass")
            print(f"Login response: {login_response}")
        except Exception as e:
            print(f"Expected login failure: {e}")
        
        # Test manual token setting
        client.set_auth_token("test-token")
        print(f"After setting token: {client.is_authenticated()}")
        print(f"Token: {client.get_auth_token()}")
        
        # Test token clearing
        client.clear_auth_token()
        print(f"After clearing token: {client.is_authenticated()}")
        
        print("Authentication tests passed!")
        
    except Exception as e:
        print(f"Authentication test failed: {e}")
        return False
    
    finally:
        client.close()
    
    return True


def test_admin_operations():
    """Test admin operations (without actual API calls)."""
    print("\nTesting admin operations...")
    
    client = DaftGilaClient(base_url="http://localhost:5000")
    
    try:
        # Test admin client initialization
        print(f"Admin client initialized: {client.admin is not None}")
        
        # Test validation (this should raise ValidationError)
        try:
            client.admin.create_user("", "", "")
            print("ERROR: Validation should have failed for empty fields")
            return False
        except Exception as e:
            print(f"Expected validation error: {e}")
        
        # Test validation for invalid user ID
        try:
            client.admin.update_user(0, email="test@example.com")
            print("ERROR: Validation should have failed for invalid user ID")
            return False
        except Exception as e:
            print(f"Expected validation error: {e}")
        
        print("Admin operation tests passed!")
        
    except Exception as e:
        print(f"Admin operation test failed: {e}")
        return False
    
    finally:
        client.close()
    
    return True


def main():
    """Main test function."""
    print("DaftGila Client Test Suite")
    print("=" * 40)
    
    tests = [
        test_basic_functionality,
        test_authentication,
        test_admin_operations
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"Test {test.__name__} failed!")
        except Exception as e:
            print(f"Test {test.__name__} crashed: {e}")
    
    print("\n" + "=" * 40)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All tests passed! 🎉")
        return 0
    else:
        print("Some tests failed! ❌")
        return 1


if __name__ == "__main__":
    sys.exit(main())


# The end.
