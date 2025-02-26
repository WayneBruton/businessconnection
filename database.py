import os
from pymongo import MongoClient
from dotenv import load_dotenv
import bcrypt
import jwt
from datetime import datetime, timedelta
import certifi

# Load environment variables
load_dotenv()

# MongoDB connection with SSL certificate verification
client = MongoClient(os.getenv('MONGODB_URI'), tlsCAFile=certifi.where())
db = client[os.getenv('DB')]
users_collection = db['users']
referrals_collection = db['referrals']

# Create unique index on email field
users_collection.create_index('email', unique=True)

def hash_password(password):
    """Hash a password for storing."""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt)

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password)

def create_user(email, password, first_name, last_name, business_name, enabled=True, notify=True):
    """Create a new user in the database."""
    try:
        hashed_password = hash_password(password)
        user = {
            'email': email,
            'password': hashed_password,
            'first_name': first_name,
            'last_name': last_name,
            'business_name': business_name,
            'enabled': enabled,
            'notify': notify,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        result = users_collection.insert_one(user)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error creating user: {e}")
        return None

def get_user_by_email(email):
    """Retrieve a user by email."""
    return users_collection.find_one({'email': email})

def get_user_by_id(user_id):
    """Retrieve a user by ID."""
    from bson.objectid import ObjectId
    return users_collection.find_one({'_id': ObjectId(user_id)})

def generate_jwt_token(user_id):
    """Generate a JWT token for a user."""
    payload = {
        'exp': datetime.utcnow() + timedelta(days=30),
        'iat': datetime.utcnow(),
        'sub': str(user_id)
    }
    return jwt.encode(
        payload,
        os.getenv('FLASK_SECRET_KEY'),
        algorithm='HS256'
    )

def decode_jwt_token(token):
    """Decode a JWT token and return the user ID."""
    try:
        payload = jwt.decode(
            token,
            os.getenv('FLASK_SECRET_KEY'),
            algorithms=['HS256']
        )
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return None  # Token expired
    except jwt.InvalidTokenError:
        return None  # Invalid token

def create_referral(from_user_id, from_business, to_business, to_name, contact_info, details):
    """Create a new referral in the database."""
    try:
        referral = {
            'from_user_id': from_user_id,
            'from_business': from_business,
            'to_business': to_business,
            'to_name': to_name,
            'contact_info': contact_info,
            'details': details,
            'date_created': datetime.utcnow(),
            'status': 'pending'  # pending, accepted, rejected, completed
        }
        result = referrals_collection.insert_one(referral)
        return str(result.inserted_id)
    except Exception as e:
        print(f"Error creating referral: {e}")
        return None

def get_referrals_by_user(user_id):
    """Get all referrals created by a user."""
    return list(referrals_collection.find({'from_user_id': user_id}).sort('date_created', -1))

def get_referral_by_id(referral_id):
    """Get a referral by its ID."""
    from bson.objectid import ObjectId
    return referrals_collection.find_one({'_id': ObjectId(referral_id)})
