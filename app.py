import os
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify
from functools import wraps
from flask_wtf.csrf import CSRFProtect, generate_csrf
from dotenv import load_dotenv
from forms import LoginForm, RegistrationForm, ReferralForm, EditUserForm
from database import (
    create_user, get_user_by_email, verify_password, 
    generate_jwt_token, decode_jwt_token, get_user_by_id,
    create_referral, get_referrals_by_user, get_all_enabled_users, get_referral_by_id,
    get_all_enabled_notifiable_users, get_referrals_to_business, get_user_by_business_name, users_collection,
    referrals_collection, get_filtered_referrals_to_business
)
from datetime import datetime
import requests 
from bson import ObjectId
from werkzeug.security import generate_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'default-secret-key')

# Custom Jinja2 filters
def is_email(value):
    return '@' in value

def is_phone(value):
    # Remove all non-numeric characters
    digits_only = ''.join(c for c in value if c.isdigit())
    # Check if we have at least 7 digits (minimum for a phone number)
    return len(digits_only) >= 7

def format_phone_for_tel(value):
    # Remove spaces, dashes, parentheses, etc. for tel: link
    return ''.join(c for c in value if c.isdigit() or c == '+')

def format_phone_for_whatsapp(value):
    # Format phone number for WhatsApp
    # Remove all non-digit characters except the plus sign
    cleaned = ''.join(c for c in value if c.isdigit() or c == '+')
    # If the number starts with a plus sign, keep it as is
    # Otherwise, assume it's a local number and needs country code
    if cleaned.startswith('+'):
        return cleaned
    # If no country code, assume South Africa (+27)
    # and remove leading 0 if present
    elif cleaned.startswith('0'):
        return '+27' + cleaned[1:]
    else:
        return '+27' + cleaned

app.jinja_env.filters['is_email'] = is_email
app.jinja_env.filters['is_phone'] = is_phone
app.jinja_env.filters['format_phone_for_tel'] = format_phone_for_tel
app.jinja_env.filters['format_phone_for_whatsapp'] = format_phone_for_whatsapp

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure CSRF with longer timeout (24 hours instead of default 1 hour)
app.config['WTF_CSRF_TIME_LIMIT'] = 86400  # 24 hours in seconds

# Route to refresh CSRF token via AJAX
@app.route('/refresh-csrf-token', methods=['GET'])
def refresh_csrf_token():
    return jsonify({'csrf_token': generate_csrf()})

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

def ensure_deal_status(referrals):
    """Ensure all referrals have a deal_accepted value set."""
    for referral in referrals:
        if 'deal_accepted' not in referral or not referral['deal_accepted']:
            referral['deal_accepted'] = 'Pending'
    return referrals

def send_webhook_notification(referral, field, value):
    """Send a webhook notification for a referral status update."""
    if not referral:
        print("Cannot send webhook notification: Referral is None")
        return
    
    # Prepare data for webhook
    serializable_referral = serialize_mongodb_doc(referral)
    
    # Get the referrer and referee information
    referrer_user = get_user_by_id(referral['from_user_id'])
    referree_user = get_user_by_business_name(referral['to_business'])
    
    if referrer_user:
        serializable_referral['referrer'] = serialize_mongodb_doc(referrer_user)
    
    if referree_user:
        serializable_referral['referree'] = serialize_mongodb_doc(referree_user)
    
    # Add status update information
    serializable_referral['status_update'] = {
        'field': field,
        'value': value,
        'updated_at': datetime.now().isoformat()
    }
    
    # Send webhook notification
    url = "https://automation-contemplation.onrender.com/webhook/tbcrefs"
    # url = "https://automation-contemplation.onrender.com/webhook-test/tbcrefs"
    try:
        import json
        print("\n==== WEBHOOK PAYLOAD ====")
        payload_json = json.dumps(serializable_referral, indent=2)
        print(payload_json)
        print("=========================\n")
        
        # Add timeout to prevent hanging
        print(f"Sending webhook request to: {url}")
        
        # Send the webhook request with timeout
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'BusinessConnectionReferral/1.0'
        }
        response = requests.post(
            url, 
            json=serializable_referral,
            headers=headers,
            timeout=10  # 10 second timeout
        )
        
        print(f"Webhook response status: {response.status_code}")
        print(f"Webhook response headers: {response.headers}")
        print(f"Webhook response text: {response.text}")
        
        # Check if response is successful
        if response.status_code >= 200 and response.status_code < 300:
            print("Webhook notification sent successfully")
            return True
        else:
            print(f"Webhook notification failed with status code: {response.status_code}")
            return False
    except requests.exceptions.Timeout:
        print("Webhook request timed out after 10 seconds")
    except requests.exceptions.RequestException as e:
        print(f"Webhook request error: {e}")
    except Exception as e:
        print(f"Error sending webhook notification: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
    
    return False

def get_all_users():
    """Get all users from the database."""
    try:
        users = list(users_collection.find())
        return users
    except Exception as e:
        print(f"Error getting all users: {e}")
        return []

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
@login_required
def register():
    # Get user information
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    if not user:
        # If user not found, log them out
        return redirect(url_for('logout'))
    
    # Only allow Admin users to access the registration page
    if user['business_name'] != 'Admin':
        flash('You do not have permission to access the registration page', 'error')
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
            flash('User registration successful!', 'success')
            return redirect(url_for('admin_dashboard'))
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
    
    # If the user is Admin, redirect to admin dashboard
    if user['business_name'] == 'Admin':
        return redirect(url_for('admin_dashboard'))
    
    print(f"Request method: {request.method}")
    
    # Create forms
    referral_form = ReferralForm()
    
    # Get all enabled users with notify=True for the dropdown
    all_users = get_all_enabled_notifiable_users()
    # Filter out the current user and prepare choices
    business_choices = [(str(u['_id']), f"{u['business_name']} ({u['first_name']} {u['last_name']})") for u in all_users if str(u['_id']) != user_id]
    # Sort choices alphabetically by first name
    business_choices.sort(key=lambda x: x[1].split('(')[1].split()[0])
    
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
    
    # Get all referrals to the user's business
    all_received_referrals = get_referrals_to_business(user['business_name'])
    print(f"All received referrals count: {len(all_received_referrals)}")
    
    # Debug: Print all received referrals before filtering
    print("\n----- ALL RECEIVED REFERRALS BEFORE FILTERING -----")
    for i, ref in enumerate(all_received_referrals):
        print(f"Referral {i+1}: From {ref.get('from_business', 'Unknown')} to {ref.get('to_business', 'Unknown')}")
        print(f"  - ID: {ref.get('_id')}")
        print(f"  - Accept: {ref.get('accept')} (Type: {type(ref.get('accept')).__name__})")
        print(f"  - Deal Status: {ref.get('deal_accepted')} (Type: {type(ref.get('deal_accepted')).__name__})")
    print("-----------------------------------------------------\n")
    
    # Ensure all referrals have a deal_accepted value
    all_received_referrals = ensure_deal_status(all_received_referrals)
    
    # Filter referrals to only show where accept=True and deal_accepted is "Pending"
    received_referrals = []
    for ref in all_received_referrals:
        accept_value = ref.get('accept')
        deal_status = ref.get('deal_accepted')
        
        print(f"Checking referral {ref.get('_id')}: accept={accept_value}, deal_accepted={deal_status}")
        
        # Check if accept is True (could be boolean True or string "true")
        is_accepted = accept_value is True or (isinstance(accept_value, str) and accept_value.lower() == "true")
        
        # Check if deal_accepted is "Pending"
        is_pending = deal_status == "Pending" or not deal_status
        
        print(f"  - is_accepted: {is_accepted}, is_pending: {is_pending}")
        
        if is_accepted and is_pending:
            print(f"  - ADDING TO FILTERED LIST")
            received_referrals.append(ref)
        else:
            print(f"  - NOT ADDING TO FILTERED LIST")
    
    print(f"Filtered received referrals count: {len(received_referrals)}")
    
    # Debug: Print filtered referrals
    print("\n----- FILTERED RECEIVED REFERRALS -----")
    for i, ref in enumerate(received_referrals):
        print(f"Filtered Referral {i+1}: From {ref.get('from_business', 'Unknown')} to {ref.get('to_business', 'Unknown')}")
        print(f"  - ID: {ref.get('_id')}")
        print(f"  - Accept: {ref.get('accept')} (Type: {type(ref.get('accept')).__name__})")
        print(f"  - Deal Status: {ref.get('deal_accepted')} (Type: {type(ref.get('deal_accepted')).__name__})")
    print("----------------------------------------\n")
    
    # Ensure all referrals have a deal_accepted value
    referrals = ensure_deal_status(referrals)
    received_referrals = ensure_deal_status(received_referrals)
    
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
            from_user_id=user_id,
            referral_type=referral_form.referral_type.data
        )
        
        print(f"Referral created with ID: {referral_id}")
        
        if referral_id:
            flash('Referral created successfully!', 'success')
            
            # Get the referral by ID
            referral = get_referral_by_id(referral_id)
            # print(f"Referral: {referral}")
            
            # Get the referrer and referee information
            referrer_user = get_user_by_id(referral['from_user_id'])
            referree_user = get_user_by_business_name(referral['to_business'])
            # print(f"ReferrerXXXX: {referrer_user}")
            # print(f"ReferreeYYYY: {referree_user}")
            # Convert MongoDB document to JSON-serializable dict using the helper function
            serializable_referral = serialize_mongodb_doc(referral)
            # add new in field 
            serializable_referral['transaction_status'] = "New"
            
            # Also add the referrer and referee information - make sure they're serializable
            if referrer_user:
                serializable_referral['referrer'] = serialize_mongodb_doc(referrer_user)
            
            if referree_user:
                serializable_referral['referree'] = serialize_mongodb_doc(referree_user)
            
            # Send webhook notification
            try:
                send_webhook_notification(serializable_referral, 'created', True)
            except Exception as e:
                print(f"Error sending webhook notification: {e}")
            
            # Redirect to the dashboard to ensure a fresh form
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to create referral. Please try again.', 'error')
    
    # Generate CSRF token for AJAX requests
    csrf_token = generate_csrf()
    
    return render_template(
        'dashboard.html', 
        user=user, 
        referrals=referrals, 
        received_referrals=received_referrals,
        referral_form=referral_form,
        now=now, 
        csrf_token=csrf_token
    )

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Check if user is an Admin
    if not user or user.get('business_name') != 'Admin':
        flash('Access denied. You must be an Admin to view this page.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all users for the admin dashboard
    all_users = get_all_users()
    
    return render_template('admin_dashboard.html', user=user, all_users=all_users)

@app.route('/edit_user/<user_id>', methods=['GET', 'POST'])
@app.route('/edit_user', methods=['GET', 'POST'])
@login_required
def edit_user(user_id=None):
    admin_user_id = session.get('user_id')
    admin_user = get_user_by_id(admin_user_id)
    
    # Check if user is an Admin
    if not admin_user or admin_user.get('business_name') != 'Admin':
        flash('Access denied. You must be an Admin to edit users.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get all business names for the dropdown
    all_users = get_all_users()
    business_choices = [(user.get('business_name'), user.get('business_name')) for user in all_users]
    
    form = EditUserForm()
    form.business_name.choices = business_choices
    
    # If form is submitted
    if form.validate_on_submit():
        user_id = form.user_id.data
        
        # Get the user to update
        user_to_update = get_user_by_id(user_id)
        if not user_to_update:
            flash('User not found.', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Always use the existing business_name from the database
        business_name = user_to_update.get('business_name')
        
        # Prepare update data
        update_data = {
            'email': form.email.data,
            'first_name': form.first_name.data,
            'last_name': form.last_name.data,
            'business_name': business_name,  # Always use existing business_name
            'mobile_number': form.mobile_number.data,
            'office_number': form.office_number.data,
            'enabled': form.enabled.data,
            'notify': form.notify.data
        }
        
        # Update password if provided and not empty
        if form.password.data and form.password.data.strip():
            update_data['password'] = generate_password_hash(form.password.data)
        
        # Update user in database
        try:
            users_collection.update_one(
                {'_id': ObjectId(user_id)},
                {'$set': update_data}
            )
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            flash(f'Error updating user: {str(e)}', 'error')
    
    # If user_id is provided, populate form with user data
    if user_id:
        user_to_edit = get_user_by_id(user_id)
        if user_to_edit:
            form.user_id.data = str(user_to_edit.get('_id'))
            form.email.data = user_to_edit.get('email')
            form.first_name.data = user_to_edit.get('first_name')
            form.last_name.data = user_to_edit.get('last_name')
            form.business_name.data = user_to_edit.get('business_name')
            form.mobile_number.data = user_to_edit.get('mobile_number', '')
            form.office_number.data = user_to_edit.get('office_number', '')
            form.enabled.data = user_to_edit.get('enabled', True)
            form.notify.data = user_to_edit.get('notify', True)
    
    return render_template('edit_user.html', form=form)

@app.route('/get_user_data/<business_name>')
@login_required
def get_user_data(business_name):
    admin_user_id = session.get('user_id')
    admin_user = get_user_by_id(admin_user_id)
    
    # Check if user is an Admin
    if not admin_user or admin_user.get('business_name') != 'Admin':
        return jsonify({'success': False, 'error': 'Access denied. Admin only.'}), 403
    
    # Get user by business name
    user = get_user_by_business_name(business_name)
    if not user:
        return jsonify({'success': False, 'error': 'User not found.'}), 404
    
    # Prepare user data for JSON response
    user_data = {
        '_id': str(user.get('_id')),
        'email': user.get('email'),
        'first_name': user.get('first_name'),
        'last_name': user.get('last_name'),
        'business_name': user.get('business_name'),
        'mobile_number': user.get('mobile_number', ''),
        'office_number': user.get('office_number', ''),
        'enabled': user.get('enabled', True),
        'notify': user.get('notify', True)
    }
    
    return jsonify({'success': True, 'user': user_data})

@app.route('/refresh_referrals')
@login_required
def refresh_referrals():
    """Return the HTML for the referrals section."""
    # Get the current user
    user = get_current_user()
    if not user:
        return jsonify({'error': 'User not found'}), 401
    
    # Get the user's referrals
    referrals = get_referrals_by_user_id(user['_id'])
    
    # Get referrals sent to the user's business
    user_business = user.get('business_name', '')
    all_received_referrals = get_referrals_by_to_business(user_business)
    
    # Debug: Print all received referrals before filtering
    print("\n----- ALL RECEIVED REFERRALS BEFORE REFRESHING -----")
    for i, ref in enumerate(all_received_referrals):
        print(f"Referral {i+1}: From {ref.get('from_business', 'Unknown')} to {ref.get('to_business', 'Unknown')}")
        print(f"  - ID: {ref.get('_id')}")
        print(f"  - Accept: {ref.get('accept')} (Type: {type(ref.get('accept')).__name__})")
        print(f"  - Deal Status: {ref.get('deal_accepted')} (Type: {type(ref.get('deal_accepted')).__name__})")
    print("-----------------------------------------------------\n")
    
    # Ensure all referrals have a deal_accepted value
    all_received_referrals = ensure_deal_status(all_received_referrals)
    
    # Filter referrals to only show where accept=True and deal_accepted is "Pending"
    received_referrals = []
    for ref in all_received_referrals:
        accept_value = ref.get('accept')
        deal_status = ref.get('deal_accepted')
        
        print(f"Checking referral {ref.get('_id')}: accept={accept_value}, deal_accepted={deal_status}")
        
        # Check if accept is True (could be boolean True or string "true")
        is_accepted = accept_value is True or (isinstance(accept_value, str) and accept_value.lower() == "true")
        
        # Check if deal_accepted is "Pending"
        is_pending = deal_status == "Pending" or not deal_status
        
        print(f"  - is_accepted: {is_accepted}, is_pending: {is_pending}")
        
        if is_accepted and is_pending:
            print(f"  - ADDING TO FILTERED LIST")
            received_referrals.append(ref)
        else:
            print(f"  - NOT ADDING TO FILTERED LIST")
    
    print(f"Filtered received referrals count: {len(received_referrals)}")
    
    # Check if this is an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        # Render just the referrals section template
        return render_template(
            'referrals_section.html',
            user=user,
            referrals=referrals,
            received_referrals=received_referrals
        )
    
    # If not an AJAX request, redirect to dashboard
    return redirect(url_for('dashboard'))

@app.route('/update_referral_status', methods=['POST'])
@csrf.exempt
def update_referral_status():
    """Update the status of a referral."""
    try:
        print("Received request to update referral status")
        
        # Get the request data
        data = request.json
        print(f"Request data: {data}")
        referral_id = data.get('referral_id')
        field = data.get('field')
        value = data.get('value')
        
        print(f"Field: {field}, Value: {value}, Type: {type(value)}")
        
        # For boolean fields, make sure the value is properly converted
        if field in ['accept', 'contacted']:
            # Handle different types of input for boolean fields
            if isinstance(value, str):
                value = value.lower() == 'true'
            elif isinstance(value, int):
                value = bool(value)
            # Ensure it's a boolean
            value = bool(value)
            print(f"Converted value for {field}: {value}, Type: {type(value)}")
        
        # For deal_accepted field, ensure it's one of the valid values
        if field == 'deal_accepted':
            valid_values = ['Pending', 'Accepted', 'Rejected']
            if value not in valid_values:
                value = 'Pending'  # Default to Pending if invalid value
            print(f"Using value for {field}: {value}")
        
        if not referral_id or not field:
            return jsonify({'success': False, 'error': 'Missing required fields'})
        
        # Update the referral status without requiring authentication for now
        # This is a temporary fix - in production you should authenticate properly
        from bson.objectid import ObjectId
        
        # Get the original referral to see what changed
        original_referral = get_referral_by_id(referral_id)
        if not original_referral:
            return jsonify({'success': False, 'error': 'Referral not found'})
        
        print(f"Original {field} value: {original_referral.get(field)}")
        
        # Update the referral status
        result = referrals_collection.update_one(
            {'_id': ObjectId(referral_id)},
            {'$set': {field: value}}
        )
        
        print(f"Update result: {result.modified_count} document(s) modified")
        
        if result.modified_count > 0:
            # Send webhook notification for the status update
            referral = get_referral_by_id(referral_id)
            # add modifed as transaction_status to referral
            referral['transaction_status'] = "modified"
            if referral:
                send_webhook_notification(referral, field, value)
            
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Referral not found or not modified'})
    except Exception as e:
        print(f"Error updating referral status: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/history')
@login_required
def history():
    """History page showing all referrals where accept is false or deal_accepted is not 'Pending' when accept is true."""
    # Get user information
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    if not user:
        # If user not found, log them out
        return redirect(url_for('logout'))
    
    # If the user is Admin, redirect to admin dashboard
    if user['business_name'] == 'Admin':
        return redirect(url_for('admin_dashboard'))
    
    # Get all referrals to the user's business
    all_received_referrals = get_referrals_to_business(user['business_name'])
    
    # Ensure all referrals have a deal_accepted value
    all_received_referrals = ensure_deal_status(all_received_referrals)
    
    # Filter referrals to show only where accept is false or deal_accepted is not "Pending" when accept is true
    history_referrals = []
    for ref in all_received_referrals:
        accept_value = ref.get('accept')
        deal_status = ref.get('deal_accepted')
        
        # Check if accept is True (could be boolean True or string "true")
        is_accepted = accept_value is True or (isinstance(accept_value, str) and accept_value.lower() == "true")
        
        # Check if deal_accepted is "Pending"
        is_pending = deal_status == "Pending" or not deal_status
        
        # Add to history if accept is false OR (accept is true AND deal_accepted is not "Pending")
        if not is_accepted or (is_accepted and not is_pending):
            history_referrals.append(ref)
    
    # Generate CSRF token for AJAX requests
    csrf_token = generate_csrf()
    
    return render_template(
        'history.html', 
        user=user, 
        history_referrals=history_referrals,
        csrf_token=csrf_token
    )

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
