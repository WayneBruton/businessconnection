"""
Test Login Script
----------------
This script tests the login functionality by directly accessing the database.
"""

import os
from pymongo import MongoClient
import bcrypt
from dotenv import load_dotenv
import certifi
from datetime import datetime
import getpass

# Load environment variables
load_dotenv()

# MongoDB connection with SSL certificate verification
client = MongoClient(os.getenv('MONGODB_URI'), tlsCAFile=certifi.where())
db = client[os.getenv('DB')]
users_collection = db['users']

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def test_login():
    """Test login functionality by directly checking the database."""
    print("\n===== LOGIN TEST =====")
    
    # Get credentials
    email = input("Enter your email: ")
    password = getpass.getpass("Enter your password: ")
    
    # Find user
    user = users_collection.find_one({'email': email})
    
    if user:
        print(f"User found: {user.get('email')}")
        print(f"User ID: {user.get('_id')}")
        
        # Check password
        if verify_password(user['password'], password):
            print("✅ Password verified successfully")
            print("Login would be successful")
            return True
        else:
            print("❌ Invalid password")
            return False
    else:
        print(f"❌ No user found with email: {email}")
        return False

def list_users():
    """List all users in the database."""
    print("\n===== USER LIST =====")
    users = list(users_collection.find())
    
    if users:
        print(f"Found {len(users)} users:")
        for user in users:
            print(f"- {user.get('email')} ({user.get('first_name')} {user.get('last_name')})")
    else:
        print("No users found in the database")

if __name__ == "__main__":
    print("MongoDB URI:", os.getenv('MONGODB_URI'))
    print("Database:", os.getenv('DB'))
    
    # Ask what to do
    print("\nWhat would you like to do?")
    print("1. Test login")
    print("2. List all users")
    choice = input("Enter choice (1 or 2): ")
    
    if choice == '1':
        test_login()
    elif choice == '2':
        list_users()
    else:
        print("Invalid choice")
