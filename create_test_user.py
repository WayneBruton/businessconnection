"""
Create Test User Script
----------------------
This script creates a test user with known credentials directly in the database.
"""

import os
from pymongo import MongoClient
import bcrypt
from dotenv import load_dotenv
import certifi
from datetime import datetime

# Load environment variables
load_dotenv()

# MongoDB connection with SSL certificate verification
client = MongoClient(os.getenv('MONGODB_URI'), tlsCAFile=certifi.where())
db = client[os.getenv('DB')]
users_collection = db['users']

def create_test_user():
    """Create a test user with known credentials."""
    # Define test user details
    email = "test@example.com"
    password = "password123"
    first_name = "Test"
    last_name = "User"
    business_name = "Test Business"
    
    # Check if user already exists
    existing_user = users_collection.find_one({"email": email})
    if existing_user:
        print(f"Test user already exists with ID: {existing_user['_id']}")
        return str(existing_user['_id'])
    
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    # Create the user document
    user = {
        'email': email,
        'password': hashed_password,
        'first_name': first_name,
        'last_name': last_name,
        'business_name': business_name,
        'enabled': True,
        'notify': True,
        'mobile_number': "123-456-7890",
        'office_number': "098-765-4321",
        'created_at': datetime.utcnow(),
        'updated_at': datetime.utcnow()
    }
    
    # Insert the user into the database
    result = users_collection.insert_one(user)
    user_id = str(result.inserted_id)
    
    print(f"Test user created successfully with ID: {user_id}")
    print(f"Login with:")
    print(f"Email: {email}")
    print(f"Password: {password}")
    
    return user_id

if __name__ == "__main__":
    create_test_user()
