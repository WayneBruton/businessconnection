"""
Check MongoDB Connection
-----------------------
This script checks if we can connect to the MongoDB database.
"""

import os
import time
from pymongo import MongoClient
from dotenv import load_dotenv
import certifi

# Load environment variables
load_dotenv()

def check_connection():
    """Check if we can connect to the MongoDB database."""
    print("\n===== CHECKING MONGODB CONNECTION =====")
    
    # Get MongoDB URI
    mongodb_uri = os.getenv('MONGODB_URI')
    db_name = os.getenv('DB')
    
    if not mongodb_uri:
        print("❌ MONGODB_URI environment variable is not set")
        return False
    
    if not db_name:
        print("❌ DB environment variable is not set")
        return False
    
    print(f"MongoDB URI: {mongodb_uri[:15]}...")
    print(f"Database name: {db_name}")
    
    try:
        # Try to connect to MongoDB
        print("Connecting to MongoDB...")
        start_time = time.time()
        client = MongoClient(mongodb_uri, tlsCAFile=certifi.where())
        
        # Check if we can access the database
        db = client[db_name]
        
        # List collections
        collections = db.list_collection_names()
        end_time = time.time()
        
        print(f"✅ Connected to MongoDB in {end_time - start_time:.2f} seconds")
        print(f"Collections: {', '.join(collections)}")
        
        # Check if users collection exists
        if 'users' in collections:
            # Count users
            users_count = db.users.count_documents({})
            print(f"Users count: {users_count}")
            
            # Get a sample user (without password)
            if users_count > 0:
                sample_user = db.users.find_one({}, {'password': 0})
                if sample_user:
                    print(f"Sample user: {sample_user.get('email')} ({sample_user.get('first_name')} {sample_user.get('last_name')})")
        
        return True
    except Exception as e:
        print(f"❌ Error connecting to MongoDB: {e}")
        return False

if __name__ == "__main__":
    check_connection()
