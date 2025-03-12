#!/usr/bin/env python3
"""
Fix Login Issues Script
----------------------
This script diagnoses and fixes login-related issues:
1. Fixes password format issues in the database
2. Ensures the verify_password function is working correctly
"""

import os
import sys
from dotenv import load_dotenv
import bcrypt
from pymongo import MongoClient
import certifi

# Load environment variables
load_dotenv()

# MongoDB connection with SSL certificate verification
client = MongoClient(os.getenv('MONGODB_URI'), tlsCAFile=certifi.where())
db = client[os.getenv('DB')]
users_collection = db['users']

def fix_password_formats():
    """Check and fix password formats in the database."""
    print("Checking and fixing password formats in the database...")
    
    # Get all users
    users = list(users_collection.find({}))
    
    fixed_count = 0
    already_correct = 0
    
    for user in users:
        user_id = user['_id']
        email = user.get('email', 'Unknown')
        password = user.get('password')
        
        print(f"\nChecking user: {email}")
        print(f"Password type: {type(password)}")
        
        if password is None:
            print(f"WARNING: User {email} has no password!")
            continue
        
        if isinstance(password, bytes):
            print(f"Password is already in bytes format (correct)")
            already_correct += 1
        else:
            print(f"Password is in {type(password)} format, converting to bytes")
            
            try:
                # Convert to bytes if it's a string
                if isinstance(password, str):
                    # Check if it looks like a bcrypt hash
                    if password.startswith('$2b$') or password.startswith('$2a$'):
                        bytes_password = password.encode('utf-8')
                        
                        # Update the user's password in the database
                        result = users_collection.update_one(
                            {'_id': user_id},
                            {'$set': {'password': bytes_password}}
                        )
                        
                        if result.modified_count > 0:
                            print(f"Fixed password format for user: {email}")
                            fixed_count += 1
                        else:
                            print(f"Failed to update password for user: {email}")
                    else:
                        print(f"WARNING: Password for {email} doesn't look like a bcrypt hash: {password[:10]}...")
                else:
                    print(f"WARNING: Unexpected password type for {email}: {type(password)}")
            except Exception as e:
                print(f"Error fixing password for {email}: {e}")
    
    print(f"\nSummary:")
    print(f"- Total users checked: {len(users)}")
    print(f"- Users with already correct password format: {already_correct}")
    print(f"- Users with fixed password format: {fixed_count}")

def test_verify_password():
    """Test the verify_password function with different password formats."""
    print("\nTesting verify_password function...")
    
    # Define a test function that mimics our verify_password function
    def verify_password(stored_password, provided_password):
        """Verify a stored password against one provided by user."""
        try:
            # Ensure stored_password is bytes
            if not isinstance(stored_password, bytes):
                print(f"Converting stored_password from {type(stored_password)} to bytes")
                stored_password = stored_password.encode('utf-8')
            
            # Encode the provided password
            encoded_password = provided_password.encode('utf-8')
            
            # Verify the password
            result = bcrypt.checkpw(encoded_password, stored_password)
            print(f"Password verification result: {result}")
            return result
        except Exception as e:
            print(f"Error verifying password: {e}")
            return False
    
    # Test with a bytes password (correct format)
    test_password = "password123"
    hashed_bytes = bcrypt.hashpw(test_password.encode('utf-8'), bcrypt.gensalt())
    
    print("\nTest 1: Bytes password (correct format)")
    print(f"Hashed password type: {type(hashed_bytes)}")
    verify_password(hashed_bytes, test_password)
    
    # Test with a string password (incorrect format)
    hashed_str = hashed_bytes.decode('utf-8')
    
    print("\nTest 2: String password (needs conversion)")
    print(f"Hashed password type: {type(hashed_str)}")
    verify_password(hashed_str, test_password)

if __name__ == "__main__":
    print("=== Login Issues Diagnostic and Fix Tool ===")
    
    # Fix password formats in the database
    fix_password_formats()
    
    # Test the verify_password function
    test_verify_password()
    
    print("\nDone! Please restart the Flask app to apply all changes.")
