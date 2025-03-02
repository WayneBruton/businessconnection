import os
from pymongo import MongoClient
from dotenv import load_dotenv
import bcrypt
import jwt
import os
from datetime import datetime, timedelta
import certifi
from datetime import date

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

def create_user(email, password, first_name, last_name, business_name, enabled=True, notify=True, mobile_number=None, office_number=None):
    """Create a new user in the database."""
    try:
        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Create the user document
        user = {
            'email': email,
            'password': hashed_password,
            'first_name': first_name,
            'last_name': last_name,
            'business_name': business_name,
            'enabled': enabled,
            'notify': notify,
            'mobile_number': mobile_number,
            'office_number': office_number,
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow()
        }
        
        # Insert the user into the database
        result = users_collection.insert_one(user)
        
        return str(result.inserted_id)
    except Exception as e:
        if isinstance(e, DuplicateKeyError):
            # Email already exists
            return None
        print(f"Error creating user: {e}")
        return None

def get_user_by_email(email):
    """Retrieve a user by email."""
    return users_collection.find_one({'email': email})

def get_user_by_id(user_id):
    """Retrieve a user by ID."""
    from bson.objectid import ObjectId
    return users_collection.find_one({'_id': ObjectId(user_id)})

def get_all_enabled_users():
    """Get all enabled users sorted by business name."""
    return list(users_collection.find({"enabled": True}).sort("business_name", 1))

def get_all_enabled_notifiable_users():
    """Get all enabled users where notify is true, sorted by business name."""
    return list(users_collection.find({"enabled": True, "notify": True}).sort("business_name", 1))

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

def create_referral(from_business, to_business, to_name, contact_info, referral_date, notes, status="pending", from_user_id=None):
    """Create a new referral."""
    print(f"Creating referral in database: from {from_business} to {to_business}")
    print(f"from_user_id: {from_user_id}")
    
    try:
        # Convert date object to string in ISO format
        if isinstance(referral_date, date):
            referral_date_str = referral_date.isoformat()
        else:
            referral_date_str = str(referral_date)
            
        referral = {
            "from_business": from_business,
            "to_business": to_business,
            "to_name": to_name,
            "contact_info": contact_info,
            "referral_date": referral_date_str,
            "notes": notes,
            "status": status,
            "from_user_id": from_user_id,
            "created_at": datetime.now(),
            "accept": True,          # New field: Whether the business accepts the referral
            "contacted": False,      # New field: Whether the business has contacted the referral
            "deal_accepted": "Pending"   # New field: Status of the deal (Pending, Accepted, Rejected)
        }
        
        print(f"Referral data: {referral}")
        
        result = referrals_collection.insert_one(referral)
        print(f"Insert result: {result.inserted_id}")
        return str(result.inserted_id) if result.inserted_id else None
    except Exception as e:
        print(f"Error creating referral: {e}")
        return None

def get_referrals_by_user(user_id):
    """Get all referrals for a user by their ID."""
    try:
        # Convert string ID to ObjectId if needed
        if isinstance(user_id, str):
            from bson.objectid import ObjectId
            user_id = ObjectId(user_id)
            
        # Find referrals where from_user_id matches the given user_id
        referrals = referrals_collection.find({"from_user_id": user_id}).sort("created_at", -1)
        
        # Convert ObjectId to string for each referral
        referrals_list = []
        for referral in referrals:
            referral['_id'] = str(referral['_id'])
            if 'from_user_id' in referral and referral['from_user_id']:
                referral['from_user_id'] = str(referral['from_user_id'])
            referrals_list.append(referral)
            
        return referrals_list
    except Exception as e:
        print(f"Error getting referrals by user: {e}")
        return []

def get_referral_by_id(referral_id):
    """Get a referral by its ID."""
    try:
        # Convert string ID to ObjectId if needed
        if isinstance(referral_id, str):
            from bson.objectid import ObjectId
            referral_id = ObjectId(referral_id)
            
        # Find the referral by ID
        referral = referrals_collection.find_one({"_id": referral_id})
        
        # Convert ObjectId to string
        if referral:
            referral['_id'] = str(referral['_id'])
            if 'from_user_id' in referral and referral['from_user_id']:
                referral['from_user_id'] = str(referral['from_user_id'])
        
        return referral
    except Exception as e:
        print(f"Error getting referral by ID: {e}")
        return None
