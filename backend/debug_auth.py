"""
Debug script to test password authentication.
"""

import os
import sys
import bcrypt

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_password_hashing():
    """Test password hashing methods."""
    print("Testing password hashing methods...")
    
    # Test the hash from the database
    stored_hash = '$2b$12$qS6c0mpobRVHTmk6brL7JuOeGghuI6wC2DeUFkUVgBa6t1/mYy43q'
    test_password = 'admin123'
    
    print(f"Stored hash: {stored_hash}")
    print(f"Test password: {test_password}")
    
    # Test bcrypt verification
    try:
        result = bcrypt.checkpw(
            test_password.encode('utf-8'), 
            stored_hash.encode('utf-8')
        )
        print(f"bcrypt.checkpw result: {result}")
        
        if result:
            print("✅ Password verification successful!")
        else:
            print("❌ Password verification failed!")
            
    except Exception as e:
        print(f"❌ Error during password verification: {e}")
    
    # Test creating a new hash
    try:
        new_hash = bcrypt.hashpw(
            test_password.encode('utf-8'), 
            bcrypt.gensalt()
        ).decode('utf-8')
        print(f"New hash created: {new_hash}")
        
        # Verify the new hash
        verify_new = bcrypt.checkpw(
            test_password.encode('utf-8'), 
            new_hash.encode('utf-8')
        )
        print(f"New hash verification: {verify_new}")
        
    except Exception as e:
        print(f"❌ Error creating new hash: {e}")

def test_user_model_methods():
    """Test User model password methods."""
    print("\nTesting User model methods...")
    
    try:
        # Import the User model
        from app.model import User
        
        # Create a test user
        test_user = User()
        test_user.username = 'test_user'
        test_user.email = 'test@example.com'
        test_user.password_hash = '$2b$12$qS6c0mpobRVHTmk6brL7JuOeGghuI6wC2DeUFkUVgBa6t1/mYy43q'
        
        # Test check_password method
        result = test_user.check_password('admin123')
        print(f"User.check_password('admin123'): {result}")
        
        # Test with wrong password
        wrong_result = test_user.check_password('wrong_password')
        print(f"User.check_password('wrong_password'): {wrong_result}")
        
        # Test setting a new password
        test_user.set_password('newpassword123')
        print(f"New password hash: {test_user.password_hash}")
        
        # Test the new password
        new_result = test_user.check_password('newpassword123')
        print(f"User.check_password('newpassword123'): {new_result}")
        
    except Exception as e:
        print(f"❌ Error testing User model: {e}")

def test_database_connection():
    """Test database connection and user lookup."""
    print("\nTesting database connection...")
    
    try:
        # This would require Flask and database setup
        print("Database connection test requires Flask environment")
        print("Run this in the Docker container or with proper Flask setup")
        
    except Exception as e:
        print(f"❌ Error testing database: {e}")

if __name__ == '__main__':
    print("=== Password Authentication Debug ===\n")
    
    test_password_hashing()
    test_user_model_methods()
    test_database_connection()
    
    print("\n=== Debug Complete ===")

# The end.
