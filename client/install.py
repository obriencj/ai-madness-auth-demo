#!/usr/bin/env python3
"""
Simple installation script for the DaftGila client package.

This script tests the package installation and basic functionality.

Author: Christopher O'Brien <obriencj@gmail.com>
Assisted-By: Claude Sonnet 4 (AI Assistant)
License: GNU General Public License v3.0
"""

import sys
import os
import subprocess

def install_package():
    """Install the package in development mode."""
    print("Installing DaftGila client package...")
    
    try:
        # Install in development mode
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-e", "."
        ], capture_output=True, text=True, cwd=os.path.dirname(__file__))
        
        if result.returncode == 0:
            print("✅ Package installed successfully!")
            return True
        else:
            print(f"❌ Installation failed:")
            print(f"STDOUT: {result.stdout}")
            print(f"STDERR: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Installation error: {e}")
        return False


def test_import():
    """Test if the package can be imported."""
    print("\nTesting package import...")
    
    try:
        import daftgila.client
        print("✅ Package imported successfully!")
        
        # Test main class
        from daftgila.client import DaftGilaClient
        print("✅ DaftGilaClient class imported successfully!")
        
        # Test other components
        from daftgila.client import APIResponse, DaftGilaClientError
        print("✅ Additional classes imported successfully!")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False


def test_basic_functionality():
    """Test basic client functionality."""
    print("\nTesting basic functionality...")
    
    try:
        from daftgila.client import DaftGilaClient
        
        # Create client instance
        client = DaftGilaClient(base_url="http://localhost:5000")
        print("✅ Client instance created successfully!")
        
        # Test properties
        print(f"  Base URL: {client.base_url}")
        print(f"  Timeout: {client.timeout}s")
        print(f"  SSL Verify: {client.verify_ssl}")
        print(f"  Authenticated: {client.is_authenticated()}")
        
        # Test auth and admin clients
        print(f"  Auth client: {type(client.auth).__name__}")
        print(f"  Admin client: {type(client.admin).__name__}")
        
        client.close()
        print("✅ Client closed successfully!")
        
        return True
        
    except Exception as e:
        print(f"❌ Functionality test failed: {e}")
        return False


def main():
    """Main installation and test function."""
    print("DaftGila Client Package Installation & Test")
    print("=" * 50)
    
    # Install package
    if not install_package():
        print("Installation failed, aborting tests.")
        return 1
    
    # Test import
    if not test_import():
        print("Import test failed.")
        return 1
    
    # Test functionality
    if not test_basic_functionality():
        print("Functionality test failed.")
        return 1
    
    print("\n" + "=" * 50)
    print("🎉 All tests passed! Package is ready to use.")
    print("\nYou can now use the client like this:")
    print("  from daftgila.client import DaftGilaClient")
    print("  client = DaftGilaClient(base_url='http://localhost:5000')")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())


# The end.
