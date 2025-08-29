#!/usr/bin/env python3
"""
Example usage of the DaftGila client.

This script demonstrates practical usage patterns for the DaftGilaClient.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import sys
import os

# Add the client package to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'daftgila'))

from daftgila.client import DaftGilaClient


def example_basic_usage():
    """Example of basic client usage."""
    print("=== Basic Client Usage ===")
    
    # Create client instance
    client = DaftGilaClient(
        base_url="http://localhost:5000",
        timeout=30.0,
        default_headers={"User-Agent": "MyApp/1.0"}
    )
    
    try:
        # Test connectivity
        print("Testing API connectivity...")
        if client.ping():
            print("✅ API is reachable")
        else:
            print("❌ API is not reachable")
            return
        
        # Get API information
        api_info = client.get_api_info()
        print(f"API Base URL: {api_info['base_url']}")
        print(f"Timeout: {api_info['timeout']}s")
        print(f"SSL Verification: {api_info['verify_ssl']}")
        
    finally:
        client.close()


def example_authentication_flow():
    """Example of complete authentication flow."""
    print("\n=== Authentication Flow ===")
    
    client = DaftGilaClient(base_url="http://localhost:5000")
    
    try:
        # Step 1: Check if already authenticated
        if client.is_authenticated():
            print("Already authenticated!")
            return
        
        # Step 2: Attempt login
        print("Attempting login...")
        try:
            response = client.auth.login("admin", "admin123")
            
            if response.is_success:
                print("✅ Login successful!")
                print(f"User: {response.data['user']['username']}")
                print(f"Token: {response.data['access_token'][:20]}...")
                
                # Step 3: Access protected endpoint
                print("\nAccessing protected endpoint...")
                hello_response = client.hello()
                if hello_response.is_success:
                    print(f"✅ Hello endpoint: {hello_response.message}")
                else:
                    print(f"❌ Hello endpoint failed: {hello_response.message}")
                
                # Step 4: Logout
                print("\nLogging out...")
                logout_response = client.auth.logout()
                if logout_response.is_success:
                    print("✅ Logout successful")
                else:
                    print(f"❌ Logout failed: {logout_response.message}")
                    
            else:
                print(f"❌ Login failed: {response.message}")
                
        except Exception as e:
            print(f"❌ Login error: {e}")
    
    finally:
        client.close()


def example_admin_operations():
    """Example of admin operations."""
    print("\n=== Admin Operations ===")
    
    client = DaftGilaClient(base_url="http://localhost:5000")
    
    try:
        # First authenticate as admin
        print("Authenticating as admin...")
        login_response = client.auth.login("admin", "admin123")
        
        if not login_response.is_success:
            print(f"❌ Admin login failed: {login_response.message}")
            return
        
        print("✅ Admin login successful!")
        
        # Get all users
        print("\nFetching users...")
        users_response = client.admin.get_users()
        
        if users_response.is_success:
            users = users_response.data['users']
            print(f"✅ Found {len(users)} users:")
            for user in users:
                print(f"  - {user['username']} ({user['email']}) - Admin: {user['is_admin']}")
        else:
            print(f"❌ Failed to fetch users: {users_response.message}")
        
        # Get OAuth providers
        print("\nFetching OAuth providers...")
        oauth_response = client.admin.get_oauth_providers()
        
        if oauth_response.is_success:
            providers = oauth_response.data['oauth_providers']
            print(f"✅ Found {len(providers)} OAuth providers:")
            for provider in providers:
                print(f"  - {provider['name']} ({provider['client_id']})")
        else:
            print(f"❌ Failed to fetch OAuth providers: {oauth_response.message}")
        
        # Logout
        client.auth.logout()
        print("\n✅ Admin session ended")
        
    except Exception as e:
        print(f"❌ Admin operations error: {e}")
    
    finally:
        client.close()


def example_user_registration():
    """Example of user self-registration."""
    print("\n=== User Self-Registration ===")
    
    client = DaftGilaClient(base_url="http://localhost:5000")
    
    try:
        # Check if registration is allowed
        print("Checking registration availability...")
        
        # Attempt to register a new user
        print("Attempting user registration...")
        try:
            response = client.auth.register(
                username="newuser",
                email="newuser@example.com",
                password="securepass123"
            )
            
            if response.is_success:
                print("✅ User registration successful!")
                print(f"Username: {response.data['user']['username']}")
                print(f"Email: {response.data['user']['email']}")
            else:
                print(f"❌ Registration failed: {response.message}")
                
        except Exception as e:
            print(f"❌ Registration error: {e}")
    
    finally:
        client.close()


def example_oauth_flow():
    """Example of OAuth authentication flow."""
    print("\n=== OAuth Authentication Flow ===")
    
    client = DaftGilaClient(base_url="http://localhost:5000")
    
    try:
        # Get available OAuth providers
        print("Fetching OAuth providers...")
        providers_response = client.auth.get_oauth_providers()
        
        if providers_response.is_success:
            providers = providers_response.data['oauth_providers']
            print(f"✅ Found {len(providers)} OAuth providers:")
            
            for provider in providers:
                print(f"  - {provider['name']}")
                
                # Generate authorization URL
                auth_url = client.auth.oauth_authorize(
                    provider=provider['name'],
                    redirect_uri="http://localhost:8000/oauth/callback"
                )
                print(f"    Auth URL: {auth_url}")
        else:
            print(f"❌ Failed to fetch OAuth providers: {providers_response.message}")
    
    finally:
        client.close()


def example_error_handling():
    """Example of error handling patterns."""
    print("\n=== Error Handling Examples ===")
    
    client = DaftGilaClient(base_url="http://localhost:5000")
    
    try:
        # Example 1: Handle validation errors
        print("Testing validation error handling...")
        try:
            client.admin.create_user("", "", "")
        except Exception as e:
            print(f"✅ Caught validation error: {e}")
        
        # Example 2: Handle API errors
        print("\nTesting API error handling...")
        try:
            response = client.auth.login("nonexistent", "wrongpass")
            if response.is_error:
                print(f"✅ API returned error: {response.message} (Status: {response.status_code})")
        except Exception as e:
            print(f"✅ Caught exception: {e}")
        
        # Example 3: Handle connection errors
        print("\nTesting connection error handling...")
        bad_client = DaftGilaClient(base_url="http://nonexistent-server:9999")
        try:
            response = bad_client.test()
        except Exception as e:
            print(f"✅ Caught connection error: {e}")
        finally:
            bad_client.close()
    
    finally:
        client.close()


def main():
    """Main example function."""
    print("DaftGila Client Examples")
    print("=" * 50)
    
    examples = [
        example_basic_usage,
        example_authentication_flow,
        example_admin_operations,
        example_user_registration,
        example_oauth_flow,
        example_error_handling
    ]
    
    for example in examples:
        try:
            example()
            print("\n" + "-" * 50)
        except Exception as e:
            print(f"❌ Example {example.__name__} failed: {e}")
            print("\n" + "-" * 50)
    
    print("\nExamples completed!")


if __name__ == "__main__":
    main()


# The end.
