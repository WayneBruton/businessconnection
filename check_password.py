"""
Check Password Script
-------------------
This script checks the stored password format for a user.
"""

import os
from dotenv import load_dotenv
from database import get_user_by_email
import bcrypt

# Load environment variables
load_dotenv()

def main():
    """Check a user's stored password format."""
    email = input("Enter user email: ")
    
    user = get_user_by_email(email)
    if not user:
        print(f"No user found with email: {email}")
        return
    
    password = user.get('password')
    print(f"User found: {user.get('email')}")
    print(f"Password type: {type(password)}")
    
    if isinstance(password, bytes):
        print(f"Password is stored as bytes (correct format)")
        print(f"First few bytes: {password[:20]}")
        
        # Check if it's a valid bcrypt hash
        if password.startswith(b'$2b$') or password.startswith(b'$2a$'):
            print("Password appears to be a valid bcrypt hash")
        else:
            print("WARNING: Password does not appear to be a valid bcrypt hash")
    else:
        print(f"WARNING: Password is not stored as bytes, but as {type(password)}")
        if isinstance(password, str):
            print(f"Password string: {password[:20]}...")
            
            # Try to convert to bytes
            try:
                bytes_password = password.encode('utf-8')
                print(f"Converted to bytes: {bytes_password[:20]}")
                
                # Check if it's a valid bcrypt hash after conversion
                if bytes_password.startswith(b'$2b$') or bytes_password.startswith(b'$2a$'):
                    print("After conversion, appears to be a valid bcrypt hash")
                else:
                    print("WARNING: After conversion, does not appear to be a valid bcrypt hash")
            except Exception as e:
                print(f"Error converting to bytes: {e}")
    
    # Test password verification
    test_password = input("Enter a password to test verification: ")
    try:
        # Ensure password is bytes
        if not isinstance(password, bytes):
            password = password.encode('utf-8')
        
        # Test verification
        result = bcrypt.checkpw(test_password.encode('utf-8'), password)
        print(f"Password verification result: {result}")
    except Exception as e:
        print(f"Error testing password verification: {e}")

if __name__ == "__main__":
    main()
