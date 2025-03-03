import os
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from functools import wraps
from dotenv import load_dotenv
from forms import LoginForm, RegistrationForm, ReferralForm
from database import (
    create_user, get_user_by_email, verify_password, 
    generate_jwt_token, decode_jwt_token, get_user_by_id,
    create_referral, get_referrals_by_user, get_all_enabled_users, get_referral_by_id,
    get_all_enabled_notifiable_users, get_referrals_to_business, get_user_by_business_name, users_collection
)
from datetime import datetime
import requests 
from bson import ObjectId

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is logged in via session
        if 'user_id' in session:
            return f(*args, **kwargs)
        
        # Check if user has a valid JWT token in cookies
        token = request.cookies.get('jwt_token')
        if token:
            user_id = decode_jwt_token(token)
            if user_id:
                # Valid token, set session and continue
                user = get_user_by_id(user_id)
                if user:
                    session['user_id'] = user_id
                    session['email'] = user['email']
                    return f(*args, **kwargs)
        
        flash('Please log in to access this page', 'error')
        return redirect(url_for('login'))
    return decorated_function

def serialize_mongodb_doc(doc):
    """Helper function to serialize MongoDB documents for JSON"""
    serialized = {}
    for key, value in doc.items():
        if key == '_id' or isinstance(value, ObjectId):
            serialized[key] = str(value)
        elif isinstance(value, datetime):
            serialized[key] = value.isoformat()
        elif isinstance(value, bytes):
            serialized[key] = value.decode('utf-8', errors='replace')
        elif isinstance(value, dict):
            serialized[key] = serialize_mongodb_doc(value)
        elif isinstance(value, list):
            serialized[key] = [serialize_mongodb_doc(item) if isinstance(item, dict) else item for item in value]
        else:
            serialized[key] = value
    return serialized

@app.route('/')
def index():
    # Check if user is logged in via session
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    # Check if user has a valid JWT token in cookies
    token = request.cookies.get('jwt_token')
    if token:
        user_id = decode_jwt_token(token)
        if user_id:
            # Valid token, set session and redirect to dashboard
            user = get_user_by_id(user_id)
            if user:
                session['user_id'] = user_id
                session['email'] = user['email']
                return redirect(url_for('dashboard'))
    
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if user is already logged in
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    # Check if user has a valid JWT token in cookies
    token = request.cookies.get('jwt_token')
    if token:
        user_id = decode_jwt_token(token)
        if user_id:
            # Valid token, set session and redirect to dashboard
            user = get_user_by_id(user_id)
            if user:
                session['user_id'] = user_id
                session['email'] = user['email']
                return redirect(url_for('dashboard'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        
        user = get_user_by_email(email)
        
        if user and verify_password(user['password'], password):
            # Generate JWT token
            token = generate_jwt_token(str(user['_id']))
            
            # Store user info in session
            session['user_id'] = str(user['_id'])
            session['email'] = user['email']
            
            # Set JWT token in cookie
            response = redirect(url_for('dashboard'))
            response.set_cookie('jwt_token', token, max_age=30*24*60*60, httponly=True)  # 30 days
            
            flash('Login successful!', 'success')
            return response
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    # If user is already logged in, redirect to dashboard
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    # Check if user has a valid JWT token in cookies
    token = request.cookies.get('jwt_token')
    if token:
        user_id = decode_jwt_token(token)
        if user_id:
            # Valid token, set session and redirect to dashboard
            user = get_user_by_id(user_id)
            if user:
                session['user_id'] = user_id
                session['email'] = user['email']
                return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        first_name = form.first_name.data
        last_name = form.last_name.data
        business_name = form.business_name.data
        mobile_number = form.mobile_number.data
        office_number = form.office_number.data
        enabled = form.enabled.data
        notify = form.notify.data
        
        user_id = create_user(
            email=email, 
            password=password, 
            first_name=first_name, 
            last_name=last_name, 
            business_name=business_name, 
            enabled=enabled, 
            notify=notify,
            mobile_number=mobile_number,
            office_number=office_number
        )
        
        if user_id:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    """Dashboard page."""
    # Get user information
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    if not user:
        # If user not found, log them out
        return redirect(url_for('logout'))
    
    print(f"Request method: {request.method}")
    
    # Create forms
    referral_form = ReferralForm()
    
    # Get all enabled users with notify=True for the dropdown
    all_users = get_all_enabled_notifiable_users()
    # Filter out the current user and prepare choices
    business_choices = [(str(u['_id']), f"{u['business_name']} ({u['first_name']} {u['last_name']})") for u in all_users if str(u['_id']) != user_id]
    # Sort choices alphabetically by business name
    business_choices.sort(key=lambda x: x[1])
    
    # Set the choices for the dropdown
    referral_form.to_business.choices = business_choices
    
    # Pre-populate the from_business field
    referral_form.from_business.data = user['business_name']
    
    # Pre-populate the referral_date field with today's date
    from datetime import date
    referral_form.referral_date.data = date.today()
    
    # Get user's referrals
    referrals = get_referrals_by_user(user_id)
    print(f"User's sent referrals count: {len(referrals)}")
    for i, ref in enumerate(referrals):
        print(f"Sent referral {i+1}: {ref.get('from_business', 'Unknown')} -> {ref.get('to_business', 'Unknown')}")
    
    # Get referrals sent to the user's business
    print(f"Current user details: ID={user_id}, Name={user.get('first_name', '')} {user.get('last_name', '')}")
    print(f"Current user business name: '{user['business_name']}'")
    received_referrals = get_referrals_to_business(user['business_name'])
    print(f"Received referrals count: {len(received_referrals)}")
    for i, ref in enumerate(received_referrals):
        print(f"Received referral {i+1}: {ref.get('from_business', 'Unknown')} -> {ref.get('to_business', 'Unknown')}")
    
    # Get current date and time for the form
    now = datetime.now()
    
    print(f"Form submitted: {request.method == 'POST'}")
    print(f"Form valid: {referral_form.validate_on_submit()}")
    
    if request.method == 'POST':
        print(f"Form errors: {referral_form.errors}")
        print(f"Form data: {request.form}")
    
    if referral_form.validate_on_submit():
        print("Form validated successfully")
        # Get the to_business name from the selected ID
        to_business_id = referral_form.to_business.data
        to_business_user = get_user_by_id(to_business_id)
        to_business_name = to_business_user['business_name'] if to_business_user else ""
        
        print(f"Creating referral from {user['business_name']} to {to_business_name}")
        
        # Create the referral
        referral_id = create_referral(
            from_business=user['business_name'],
            to_business=to_business_name,
            to_name=referral_form.to_name.data,
            contact_info=referral_form.contact_info.data,
            referral_date=referral_form.referral_date.data,
            notes=referral_form.notes.data,
            from_user_id=user_id
        )
        
        print(f"Referral created with ID: {referral_id}")
        
        if referral_id:
            flash('Referral created successfully!', 'success')
            
            # Get the referral by ID
            referral = get_referral_by_id(referral_id)
            # print(f"Referral: {referral}")
            
            # Get the referrer referree information
            referrer_user = get_user_by_id(referral['from_user_id'])
            referree_user = get_user_by_business_name(referral['to_business'])
            # print(f"ReferrerXXXX: {referrer_user}")
            # print(f"ReferreeYYYY: {referree_user}")
            # Convert MongoDB document to JSON-serializable dict using the helper function
            serializable_referral = serialize_mongodb_doc(referral)
            
            # Also add the referrer and referee information - make sure they're serializable
            if referrer_user:
                serializable_referral['referrer'] = serialize_mongodb_doc(referrer_user)
            
            if referree_user:
                serializable_referral['referree'] = serialize_mongodb_doc(referree_user)
            
            url = "https://automation-contemplation.onrender.com/webhook/tbcrefs"
            # call the webhook and send the referral data
            response = requests.post(url, json=serializable_referral)
            print(f"Webhook response: {response.text}")
            
            # Redirect to the dashboard to ensure a fresh form
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to create referral. Please try again.', 'error')
    
    return render_template('dashboard.html', user=user, referral_form=referral_form, referrals=referrals, received_referrals=received_referrals, now=now)

@app.route('/logout')
def logout():
    # Clear session
    session.clear()
    
    # Clear JWT cookie
    response = redirect(url_for('login'))
    response.delete_cookie('jwt_token')
    
    flash('You have been logged out', 'success')
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5015)
