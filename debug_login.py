"""
Debug Login Script
-----------------
This script provides a simple Flask app to test login functionality.
"""

import os
from flask import Flask, request, jsonify, session
from pymongo import MongoClient
import bcrypt
from dotenv import load_dotenv
import certifi
import jwt
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Create a simple Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'debug-secret-key')

# MongoDB connection with SSL certificate verification
client = MongoClient(os.getenv('MONGODB_URI'), tlsCAFile=certifi.where())
db = client[os.getenv('DB')]
users_collection = db['users']

def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    try:
        print(f"Verifying password...")
        print(f"Stored password type: {type(stored_password)}")
        
        # Ensure stored_password is bytes
        if not isinstance(stored_password, bytes):
            print(f"WARNING: stored_password is not bytes, converting from {type(stored_password)}")
            if isinstance(stored_password, str):
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

def get_user_by_email(email):
    """Get a user by their email address."""
    try:
        # Find the user by email
        user = users_collection.find_one({"email": email})
        
        # Convert ObjectId to string
        if user:
            user['_id'] = str(user['_id'])
        
        return user
    except Exception as e:
        print(f"Error getting user by email: {e}")
        return None

def generate_jwt_token(user_id):
    """Generate a JWT token for a user."""
    try:
        payload = {
            'exp': datetime.utcnow() + timedelta(days=30),
            'iat': datetime.utcnow(),
            'sub': str(user_id)
        }
        secret_key = os.getenv('FLASK_SECRET_KEY', 'debug-secret-key')
        
        # Debug information
        print(f"Generating JWT token for user_id: {user_id}")
        print(f"Secret key length: {len(secret_key) if secret_key else 'None'}")
        
        token = jwt.encode(
            payload,
            secret_key,
            algorithm='HS256'
        )
        
        # Handle both string and bytes return types (depends on jwt version)
        if isinstance(token, bytes):
            token = token.decode('utf-8')
            
        print(f"Generated token: {token[:10]}...")
        return token
    except Exception as e:
        print(f"Error generating JWT token: {e}")
        return None

@app.route('/test_login', methods=['POST'])
def test_login():
    """Test login functionality."""
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    print(f"\n===== TEST LOGIN ATTEMPT =====")
    print(f"Email: {email}")
    
    if not email or not password:
        return jsonify({
            'success': False,
            'error': 'Email and password are required'
        })
    
    user = get_user_by_email(email)
    
    if not user:
        print(f"No user found with email: {email}")
        return jsonify({
            'success': False,
            'error': 'User not found'
        })
    
    print(f"User found: {user.get('email')}")
    print(f"User ID: {user.get('_id')}")
    
    if verify_password(user['password'], password):
        print("Password verified successfully")
        
        # Generate JWT token
        token = generate_jwt_token(str(user['_id']))
        
        if token:
            print(f"JWT token generated: {token[:10]}...")
            
            # Store user info in session
            session['user_id'] = str(user['_id'])
            session['email'] = user['email']
            
            print(f"Session set: user_id={session.get('user_id')}, email={session.get('email')}")
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user['_id'],
                    'email': user['email'],
                    'first_name': user.get('first_name', ''),
                    'last_name': user.get('last_name', ''),
                    'business_name': user.get('business_name', '')
                },
                'token': token
            })
        else:
            print("Failed to generate JWT token")
            return jsonify({
                'success': False,
                'error': 'Failed to generate authentication token'
            })
    else:
        print("Invalid password")
        return jsonify({
            'success': False,
            'error': 'Invalid password'
        })

@app.route('/')
def index():
    """Show a simple test form."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Test</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; }
            .form-group { margin-bottom: 15px; }
            label { display: block; margin-bottom: 5px; }
            input[type="text"], input[type="password"] { width: 100%; padding: 8px; box-sizing: border-box; }
            button { padding: 10px 15px; background-color: #4CAF50; color: white; border: none; cursor: pointer; }
            #result { margin-top: 20px; padding: 10px; border: 1px solid #ddd; display: none; }
            .success { background-color: #dff0d8; color: #3c763d; }
            .error { background-color: #f2dede; color: #a94442; }
        </style>
    </head>
    <body>
        <h1>Login Test</h1>
        <div class="form-group">
            <label for="email">Email:</label>
            <input type="text" id="email" name="email">
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password">
        </div>
        <button id="login-btn">Test Login</button>
        
        <div id="result"></div>
        
        <script>
            document.getElementById('login-btn').addEventListener('click', function() {
                const email = document.getElementById('email').value;
                const password = document.getElementById('password').value;
                
                if (!email || !password) {
                    showResult('Please enter both email and password', false);
                    return;
                }
                
                fetch('/test_login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        email: email,
                        password: password
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        showResult(`Login successful! User: ${data.user.first_name} ${data.user.last_name} (${data.user.email})`, true);
                    } else {
                        showResult(`Login failed: ${data.error}`, false);
                    }
                })
                .catch(error => {
                    showResult(`Error: ${error.message}`, false);
                });
            });
            
            function showResult(message, success) {
                const resultElement = document.getElementById('result');
                resultElement.textContent = message;
                resultElement.className = success ? 'success' : 'error';
                resultElement.style.display = 'block';
            }
        </script>
    </body>
    </html>
    """

if __name__ == '__main__':
    print("Starting debug login server...")
    print(f"MongoDB URI: {os.getenv('MONGODB_URI')[:15]}...")
    print(f"Database: {os.getenv('DB')}")
    print(f"Secret key length: {len(os.getenv('FLASK_SECRET_KEY', 'debug-secret-key'))}")
    app.run(debug=True, port=5016)
