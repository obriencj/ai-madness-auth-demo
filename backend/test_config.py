"""
Test script to verify database configuration.
"""

import os
import sys

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_database_config():
    """Test that the database configuration is working."""
    try:
        # Test importing the app
        from app import app
        
        # Check if database URI is set
        db_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        if db_uri:
            print(f"✅ Database URI is set: {db_uri}")
        else:
            print("❌ Database URI is not set")
            return False
        
        # Check if database is initialized
        if hasattr(app, 'extensions') and 'sqlalchemy' in app.extensions:
            print("✅ SQLAlchemy is properly initialized")
        else:
            print("❌ SQLAlchemy is not initialized")
            return False
        
        # Check if auth_engine is configured
        if hasattr(app, 'auth_engine'):
            print("✅ Auth engine is configured")
        else:
            print("❌ Auth engine is not configured")
            return False
        
        print("✅ All configurations are working correctly!")
        return True
        
    except Exception as e:
        print(f"❌ Error during configuration test: {e}")
        return False

if __name__ == '__main__':
    success = test_database_config()
    sys.exit(0 if success else 1)

# The end.
