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
    referrals_collection, get_filtered_referrals_to_business, create_attendance_record, get_attendance_records,
    get_attendance_record_by_id, update_attendance_record, delete_attendance_record, get_attendance_record_by_date
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
    
    # Special case for specific businesses
    if referral['to_business'] in ["Easylife Kitchens-Tokai", "TLC Flooring"]:
        # Get all users from the same company
        same_company_users = []
        target_business = referral['to_business']
        
        # Get all users
        all_users = get_all_users()
        
        # Filter users from the same company
        for user in all_users:
            # Skip the current user
            if referree_user and user.get('_id') == referree_user.get('_id'):
                continue
                
            # Check if user is from the same company
            if user.get('business_name') == target_business:
                same_company_users.append(serialize_mongodb_doc(user))
        
        if same_company_users:
            serializable_referral['same_company_users'] = same_company_users
            print(f"Added {len(same_company_users)} other users from {target_business}")
    
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

def send_attendance_webhook(meeting_date, members):
    """Send a webhook notification when a new attendance record is created."""
    if not meeting_date or not members:
        print("Cannot send attendance webhook: Missing required data")
        return False
    
    try:
        # Prepare data for webhook
        webhook_data = {
            'meeting_date': meeting_date,
            'created_at': datetime.now().isoformat(),
            'members': []
        }
        
        # Add meeting_date to each member record
        for member in members:
            member_data = member.copy()  # Create a copy to avoid modifying the original
            member_data['meeting_date'] = meeting_date
            webhook_data['members'].append(member_data)
        
        # Send webhook notification
        # url = "https://automation-contemplation.onrender.com/webhook-test/attendance_create"
        url = "https://automation-contemplation.onrender.com/webhook/attendance_create"
        
        import json
        print("\n==== ATTENDANCE WEBHOOK PAYLOAD ====")
        payload_json = json.dumps(webhook_data, indent=2)
        print(payload_json)
        print("====================================\n")
        
        print(f"Sending attendance webhook request to: {url}")
        
        # Send the webhook request with timeout
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'BusinessConnectionAttendance/1.0'
        }
        
        response = requests.post(
            url,
            json=webhook_data,
            headers=headers,
            timeout=10  # 10 second timeout
        )
        
        print(f"Attendance webhook response status: {response.status_code}")
        print(f"Attendance webhook response text: {response.text}")
        
        # Check if response is successful
        if response.status_code >= 200 and response.status_code < 300:
            print("Attendance webhook notification sent successfully")
            return True
        else:
            print(f"Attendance webhook notification failed with status code: {response.status_code}")
            return False
            
    except requests.exceptions.Timeout:
        print("Attendance webhook request timed out after 10 seconds")
    except requests.exceptions.RequestException as e:
        print(f"Attendance webhook request error: {e}")
    except Exception as e:
        print(f"Error sending attendance webhook notification: {e}")
        print(f"Error type: {type(e).__name__}")
        
    return False

def send_attendance_change_webhook(meeting_date, business_name, status, notes):
    """Send a webhook notification when a single attendance item is changed."""
    if not meeting_date or not business_name:
        print("Cannot send attendance change webhook: Missing required data")
        return False
    
    try:
        # Prepare data for webhook
        webhook_data = {
            'meeting_date': meeting_date,
            'business_name': business_name,
            'status': status,
            'notes': notes,
            'changed_at': datetime.now().isoformat()
        }
        
        # Send webhook notification
        # url = "https://automation-contemplation.onrender.com/webhook-test/attendance_amend"
        url = "https://automation-contemplation.onrender.com/webhook/attendance_amend"
        
        import json
        print("\n==== ATTENDANCE CHANGE WEBHOOK PAYLOAD ====")
        payload_json = json.dumps(webhook_data, indent=2)
        print(payload_json)
        print("=========================================\n")
        
        print(f"Sending attendance change webhook request to: {url}")
        
        # Send the webhook request with timeout
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'BusinessConnectionAttendance/1.0'
        }
        
        response = requests.post(
            url,
            json=webhook_data,
            headers=headers,
            timeout=10  # 10 second timeout
        )
        
        print(f"Attendance change webhook response status: {response.status_code}")
        print(f"Attendance change webhook response text: {response.text}")
        print(f"Attendance change webhook response headers: {response.headers}")
        print(f"Attendance change webhook response content: {response.content}")
        
        # Check if response is successful
        if response.status_code >= 200 and response.status_code < 300:
            print("Attendance change webhook notification sent successfully")
            return True
        else:
            print(f"Attendance change webhook notification failed with status code: {response.status_code}")
            return False
            
    except requests.exceptions.Timeout:
        print("Attendance change webhook request timed out after 10 seconds")
    except requests.exceptions.RequestException as e:
        print(f"Attendance change webhook request error: {e}")
    except Exception as e:
        print(f"Error sending attendance change webhook notification: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        
    return False

def send_welcome_webhook(user_data):
    """Send a webhook notification for a new user registration."""
    if not user_data:
        print("Cannot send webhook notification: User data is None")
        return False
    
    # Create a more user-friendly format instead of raw MongoDB document
    friendly_user = {
        "name": {
            "first": user_data.get('first_name', ''),
            "last": user_data.get('last_name', ''),
            "full": f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip()
        },
        "business": user_data.get('business_name', ''),
        "contact": {
            "email": user_data.get('email', ''),
            "mobile": user_data.get('mobile_number', ''),
            "office": user_data.get('office_number', '')
        },
        "account": {
            "enabled": user_data.get('enabled', False),
            "notifications": user_data.get('notify', False),
            "created": datetime.now().isoformat()
        }
    }
    
    # Send webhook notification
    url = "https://automation-contemplation.onrender.com/webhook/welcome_new_user"
    try:
        import json
        import os
        from pathlib import Path
        
        print("\n==== WELCOME WEBHOOK PAYLOAD ====")
        payload_json = json.dumps(friendly_user, indent=2)
        print(payload_json)
        print("=================================\n")
        
        # Prepare file paths
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
        app_instructions_path = os.path.join(static_dir, 'App_Instructions.pdf')
        welcome_pack_path = os.path.join(static_dir, 'Welcome_pack.pdf')  # Fixing the typo in the filename
        
        # Check if files exist
        if not os.path.exists(app_instructions_path):
            print(f"Warning: App_Instructions.pdf not found at {app_instructions_path}")
        if not os.path.exists(welcome_pack_path):
            print(f"Warning: Welcome_pack.pdf not found at {welcome_pack_path}")
        
        # Prepare multipart form data
        files = {}
        if os.path.exists(app_instructions_path):
            files['App_Instructions.pdf'] = (
                'App_Instructions.pdf',
                open(app_instructions_path, 'rb'),
                'application/pdf'
            )
        if os.path.exists(welcome_pack_path):
            files['Welcome_pack.pdf'] = (
                'Welcome_pack.pdf',
                open(welcome_pack_path, 'rb'),
                'application/pdf'
            )
        
        # Add timeout to prevent hanging
        print(f"Sending welcome webhook request to: {url}")
        
        # Prepare the user data as part of the form
        data = {
            'user_data': json.dumps(friendly_user)
        }
        
        # Send the webhook request with timeout
        headers = {
            'User-Agent': 'BusinessConnectionReferral/1.0'
        }
        
        response = requests.post(
            url, 
            data=data,
            files=files,
            headers=headers,
            timeout=10  # 10 second timeout
        )
        
        # Close file handles
        for file_tuple in files.values():
            if len(file_tuple) > 1 and hasattr(file_tuple[1], 'close'):
                file_tuple[1].close()
        
        print(f"Welcome webhook response status: {response.status_code}")
        print(f"Welcome webhook response headers: {response.headers}")
        print(f"Welcome webhook response text: {response.text}")
        
        # Check if response is successful
        if response.status_code >= 200 and response.status_code < 300:
            print("Welcome webhook notification sent successfully")
            return True
        else:
            print(f"Welcome webhook notification failed with status code: {response.status_code}")
            # Try to provide more detailed error information
            try:
                error_data = response.json()
                print(f"Error details: {json.dumps(error_data, indent=2)}")
            except:
                print(f"Response content: {response.text[:500]}")  # Limit to first 500 chars in case of large response
            
            # Log the error to the console for debugging
            print(f"Full webhook payload that caused the error: {json.dumps(friendly_user, indent=2)}")
            return False
    except requests.exceptions.Timeout:
        print("Welcome webhook request timed out after 10 seconds")
    except requests.exceptions.RequestException as e:
        print(f"Welcome webhook request error: {e}")
    except Exception as e:
        print(f"Error sending welcome webhook notification: {e}")
        print(f"Error type: {type(e).__name__}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        
        # Close file handles if exception occurs
        if 'files' in locals() and isinstance(files, dict):
            for file_tuple in files.values():
                if len(file_tuple) > 1 and hasattr(file_tuple[1], 'close'):
                    try:
                        file_tuple[1].close()
                    except:
                        pass
    
    return False

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
            send_welcome_webhook(get_user_by_id(user_id))
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
    
    # Ensure all referrals have a deal_accepted value
    referrals = ensure_deal_status(referrals)
    
    # Filter sent referrals to only show pending ones (similar to received referrals)
    active_sent_referrals = []
    for ref in referrals:
        accept_value = ref.get('accept')
        deal_status = ref.get('deal_accepted')
        
        print(f"Checking sent referral {ref.get('_id')}: accept={accept_value}, deal_accepted={deal_status}")
        
        # Check if accept is True (could be boolean True or string "true")
        is_accepted = accept_value is True or (isinstance(accept_value, str) and accept_value.lower() == "true")
        
        # Check if deal_accepted is "Pending"
        is_pending = deal_status == "Pending" or not deal_status
        
        print(f"  - is_accepted: {is_accepted}, is_pending: {is_pending}")
        
        if is_accepted and is_pending:
            print(f"  - ADDING TO ACTIVE SENT REFERRALS LIST")
            
            # Add recipient business contact information
            recipient = get_user_by_business_name(ref.get('to_business', ''))
            if recipient:
                ref['recipient_email'] = recipient.get('email', '')
                ref['recipient_mobile'] = recipient.get('mobile_number', '')
                ref['recipient_office'] = recipient.get('office_number', '')
            
            active_sent_referrals.append(ref)
        else:
            print(f"  - NOT ADDING TO ACTIVE SENT REFERRALS LIST (will be in history)")
    
    print(f"Filtered active sent referrals count: {len(active_sent_referrals)}")
    
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
            
            # Add sender business contact information
            sender = get_user_by_business_name(ref.get('from_business', ''))
            if sender:
                ref['sender_email'] = sender.get('email', '')
                ref['sender_mobile'] = sender.get('mobile_number', '')
                ref['sender_office'] = sender.get('office_number', '')
                
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
    
    # Get current date and time for the form
    now = datetime.now()
    
    print(f"Form submitted: {request.method == 'POST'}")
    print(f"Form valid: {referral_form.validate_on_submit()}")
    
    if request.method == 'POST':
        print(f"Form errors: {referral_form.errors}")
        print(f"Form data: {request.form}")
    
    if referral_form.validate_on_submit():
        print("Form validated successfully")
        
        # Check if the referral type is visitor
        if referral_form.referral_type.data == 'visitor':
            # For visitor referrals, set to_business to Admin
            admin_user = get_user_by_business_name('Admin')
            to_business_name = 'Admin'
            print(f"Visitor referral detected, setting to_business to Admin")
        else:
            # For internal and external referrals, use the selected business
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
    
    # Handle form submission for visitor referrals
    if request.method == 'POST' and request.form.get('referral_type') == 'visitor':
        # Find Admin user to set as to_business for visitor referrals
        admin_user = next((u for u in get_all_enabled_users() if u['business_name'] == 'Admin'), None)
        if admin_user:
            # Set the to_business field to Admin's ID for validation
            request.form = request.form.copy()  # Make request.form mutable
            request.form['to_business'] = str(admin_user['_id'])
    
    # Generate CSRF token for AJAX requests
    csrf_token = generate_csrf()
    
    return render_template(
        'dashboard.html', 
        user=user, 
        referrals=active_sent_referrals, 
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
            'notify': form.notify.data,
            '5_minute_talk': form.five_minute_talk.data,
            '10_minute_talk': form.ten_minute_talk.data
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
            form.five_minute_talk.data = user_to_edit.get('5_minute_talk', '')
            form.ten_minute_talk.data = user_to_edit.get('10_minute_talk', '')
    
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
        'notify': user.get('notify', True),
        '5_minute_talk': user.get('5_minute_talk', ''),
        '10_minute_talk': user.get('10_minute_talk', '')
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
            valid_values = ['Pending', 'Accepted', 'Unsuccessful']
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
    history_received_referrals = []
    for ref in all_received_referrals:
        accept_value = ref.get('accept')
        deal_status = ref.get('deal_accepted')
        
        # Check if accept is True (could be boolean True or string "true")
        is_accepted = accept_value is True or (isinstance(accept_value, str) and accept_value.lower() == "true")
        
        # Check if deal_accepted is "Pending"
        is_pending = deal_status == "Pending" or not deal_status
        
        # Add to history if accept is false OR (accept is true AND deal_accepted is not "Pending")
        if not is_accepted or (is_accepted and not is_pending):
            history_received_referrals.append(ref)
    
    # Get all sent referrals
    all_sent_referrals = get_referrals_by_user(user_id)
    all_sent_referrals = ensure_deal_status(all_sent_referrals)
    
    # Filter sent referrals to include ones that are rejected or not pending
    history_sent_referrals = []
    for ref in all_sent_referrals:
        accept_value = ref.get('accept')
        deal_status = ref.get('deal_accepted')
        
        # Check if accept is True (could be boolean True or string "true")
        is_accepted = accept_value is True or (isinstance(accept_value, str) and accept_value.lower() == "true")
        
        # Check if deal_accepted is "Pending"
        is_pending = deal_status == "Pending" or not deal_status
        
        # Add to history if accept is false OR (accept is true AND deal_accepted is not "Pending")
        if not is_accepted or (is_accepted and not is_pending):
            history_sent_referrals.append(ref)
    
    # Generate CSRF token for AJAX requests
    csrf_token = generate_csrf()
    
    return render_template(
        'history.html', 
        user=user, 
        history_received_referrals=history_received_referrals,
        history_sent_referrals=history_sent_referrals,
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

@app.route('/update_talks', methods=['POST'])
@login_required
def update_talks():
    """Update user's 5-minute and 10-minute talks."""
    try:
        # Get data from request
        data = request.get_json()
        
        # Get user ID from session (current user)
        current_user_id = session.get('user_id')
        
        # Get the talk contents
        five_minute_talk = data.get('five_minute_talk', '')
        ten_minute_talk = data.get('ten_minute_talk', '')
        
        # Update the user in the database
        from bson.objectid import ObjectId
        result = users_collection.update_one(
            {'_id': ObjectId(current_user_id)},
            {'$set': {
                '5_minute_talk': five_minute_talk,
                '10_minute_talk': ten_minute_talk,
                'updated_at': datetime.now()
            }}
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'No changes were made.'})
            
    except Exception as e:
        print(f"Error updating talks: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/attendance', methods=['GET'])
@login_required
def attendance():
    """
    Display attendance records and provide interface for tracking attendance.
    """
    # Get the current user
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Only admins can view this page
    if not user or user.get('business_name') != 'Admin':
        flash('Access denied. You must be an Admin to view this page.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get attendance records
    attendance_records = get_attendance_records()
    
    # Get all users for attendance form
    all_users = get_all_enabled_users()
    
    return render_template(
        'attendance.html',
        user=user,
        attendance_records=attendance_records,
        all_users=all_users
    )

@app.route('/create_attendance', methods=['POST'])
@login_required
def create_attendance():
    """
    Create a new attendance record.
    """
    # Get the current user
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Only admins can create attendance records
    if not user or user.get('business_name') != 'Admin':
        return jsonify({'success': False, 'message': 'Access denied. Admin only.'}), 403
    
    try:
        # Get form data
        meeting_date = request.form.get('meeting_date')
        
        # Check if date is valid
        if not meeting_date:
            return jsonify({'success': False, 'message': 'Meeting date is required'}), 400
            
        # Check if a record already exists for this date
        existing_record = get_attendance_record_by_date(meeting_date)
        if existing_record:
            # Redirect to edit the existing record
            flash('An attendance record for this date already exists. You can edit it below.', 'info')
            return redirect(url_for('edit_attendance', attendance_id=str(existing_record['_id'])))
        
        # Get all users and their attendance status
        members = []
        all_users = get_all_enabled_users()
        
        for user_data in all_users:
            business_name = user_data.get('business_name')
            business_id = str(user_data.get('_id'))
            
            # Get status for this user
            status = request.form.get(f'status_{business_id}', 'absent')
            
            # Get notes for this user if any
            notes = request.form.get(f'notes_{business_id}', '')
            
            # Debug output
            print(f"Processing attendance for {business_name} - Status: {status}")
            
            # Add to members list
            members.append({
                'business_name': business_name,
                'status': status,
                'notes': notes
            })
        
        # Create the attendance record
        record_id = create_attendance_record(meeting_date, members)
        
        if record_id:
            flash('Attendance record created successfully', 'success')
            send_attendance_webhook(meeting_date, members)
            return redirect(url_for('attendance', date=meeting_date))
        else:
            flash('Failed to create attendance record', 'error')
            return redirect(url_for('attendance'))
            
    except Exception as e:
        print(f"Error creating attendance record: {e}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('attendance'))

@app.route('/edit_attendance/<attendance_id>', methods=['GET'])
@login_required
def edit_attendance(attendance_id):
    """
    Display form to edit an attendance record.
    """
    # Get the current user
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Only admins can edit attendance records
    if not user or user.get('business_name') != 'Admin':
        flash('Access denied. You must be an Admin to view this page.', 'error')
        return redirect(url_for('dashboard'))
    
    # Get the attendance record
    record = get_attendance_record_by_id(attendance_id)
    
    if not record:
        flash('Attendance record not found', 'error')
        return redirect(url_for('attendance'))
    
    # Get all users for the form
    all_users = get_all_enabled_users()
    
    return render_template(
        'edit_attendance.html',
        user=user,
        record=record,
        all_users=all_users
    )

@app.route('/update_attendance/<attendance_id>', methods=['POST'])
@login_required
def update_attendance(attendance_id):
    """
    Update an existing attendance record.
    """
    # Get the current user
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Only admins can update attendance records
    if not user or user.get('business_name') != 'Admin':
        flash('Access denied. You must be an Admin to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get form data
        meeting_date = request.form.get('meeting_date')
        
        # Check if date is valid
        if not meeting_date:
            flash('Meeting date is required', 'error')
            return redirect(url_for('edit_attendance', attendance_id=attendance_id))
        
        # Get all users and their attendance status
        members = []
        all_users = get_all_enabled_users()
        
        for user_data in all_users:
            business_name = user_data.get('business_name')
            business_id = str(user_data.get('_id'))
            
            # Get status for this user
            status = request.form.get(f'status_{business_id}', 'absent')
            
            # Get notes for this user if any
            notes = request.form.get(f'notes_{business_id}', '')
            
            # Debug output
            print(f"Processing attendance for {business_name} - Status: {status}")
            
            # Add to members list
            members.append({
                'business_name': business_name,
                'status': status,
                'notes': notes
            })
        
        # Update the record
        success = update_attendance_record(attendance_id, meeting_date, members)
        
        if success:
            flash('Attendance record updated successfully', 'success')
            send_attendance_webhook(meeting_date, members)
            # Force a redirect to reload all data from the database
            return redirect(url_for('attendance', date=meeting_date))
        else:
            flash('Failed to update attendance record', 'error')
            
        return redirect(url_for('attendance'))
            
    except Exception as e:
        print(f"Error updating attendance record: {e}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('edit_attendance', attendance_id=attendance_id))

@app.route('/delete_attendance/<attendance_id>', methods=['POST'])
@login_required
def delete_attendance(attendance_id):
    """
    Delete an attendance record.
    """
    # Get the current user
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Only admins can delete attendance records
    if not user or user.get('business_name') != 'Admin':
        flash('Access denied. You must be an Admin to perform this action.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete the record
        success = delete_attendance_record(attendance_id)
        
        if success:
            flash('Attendance record deleted successfully', 'success')
        else:
            flash('Failed to delete attendance record', 'error')
            
        return redirect(url_for('attendance'))
            
    except Exception as e:
        print(f"Error deleting attendance record: {e}")
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('attendance'))

@app.route('/check_attendance_date', methods=['GET'])
@login_required
def check_attendance_date():
    """
    API endpoint to check if an attendance record exists for a specific date.
    If it exists, return the record data.
    """
    # Get the current user
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Only admins can access attendance data
    if not user or user.get('business_name') != 'Admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Get the date from query parameters
        date_param = request.args.get('date')
        if not date_param:
            return jsonify({'success': False, 'message': 'Date parameter is required'}), 400
        
        # Check if a record exists for this date
        record = get_attendance_record_by_date(date_param)
        
        if record:
            # Convert ObjectId to string for JSON serialization
            record['_id'] = str(record['_id'])
            
            # Format other fields as needed
            if isinstance(record.get('meeting_date'), datetime):
                record['meeting_date'] = record['meeting_date'].strftime('%Y-%m-%d')
            
            # Ensure we're sending the complete data and validate member status values
            for member in record.get('members', []):
                # Make sure status is present and valid
                if 'status' not in member or not member['status']:
                    member['status'] = 'absent'  # Default if missing
                
                # Log each member's status for debugging
                print(f"Member: {member.get('business_name')} - Status: {member.get('status')}")
            
            return jsonify({
                'success': True,
                'exists': True,
                'record': record,
                'timestamp': datetime.now().timestamp()  # Add timestamp to prevent caching
            })
        else:
            return jsonify({
                'success': True,
                'exists': False,
                'timestamp': datetime.now().timestamp()  # Add timestamp to prevent caching
            })
            
    except Exception as e:
        print(f"Error checking attendance date: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/update_attendance_item', methods=['POST'])
@csrf.exempt
@login_required
def update_attendance_item():
    """
    API endpoint to update a single attendance item in real-time.
    This allows for immediate updates when a dropdown or note is changed.
    """
    # Get the current user
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Only admins can update attendance data
    if not user or user.get('business_name') != 'Admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Print the raw request data for debugging
        print("Raw request data:", request.data)
        data = request.get_json()
        print("Parsed JSON data:", data)
        
        # Required fields
        meeting_date = data.get('meeting_date')
        business_name = data.get('business_name')
        status = data.get('status')
        notes = data.get('notes', '')
        
        print(f"Updating attendance for {business_name} on {meeting_date}: status={status}, notes={notes}")
        
        if not meeting_date or not business_name or not status:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400
        
        # Check if a record exists for this date
        record = get_attendance_record_by_date(meeting_date)
        
        if record:
            # Update existing record
            record_id = str(record['_id'])
            members = record.get('members', [])
            
            # Find the member to update
            member_updated = False
            for member in members:
                if member.get('business_name') == business_name:
                    # Update the member data
                    member['status'] = status
                    member['notes'] = notes
                    member_updated = True
                    print(f"Found and updated member {business_name}")
                    break
            
            if not member_updated:
                # Member not found, add them
                members.append({
                    'business_name': business_name,
                    'status': status,
                    'notes': notes
                })
                print(f"Added new member {business_name} to record")
            
            # Update the record
            success = update_attendance_record(record_id, meeting_date, members)
            
            if success:
                print(f"Successfully updated attendance record {record_id}")
                webhook_result = send_attendance_change_webhook(meeting_date, business_name, status, notes)
                print(f"Webhook result for {business_name} update: {webhook_result}")
                return jsonify({
                    'success': True,
                    'message': 'Attendance updated successfully',
                    'webhook_sent': webhook_result,
                    'timestamp': datetime.now().timestamp()
                })
            else:
                print(f"Failed to update attendance record {record_id}")
                return jsonify({'success': False, 'message': 'Failed to update attendance'}), 500
        else:
            # Create new record with this member
            members = [{
                'business_name': business_name,
                'status': status,
                'notes': notes
            }]
            
            # Get all users to add with default values
            all_users = get_all_enabled_users()
            for user_data in all_users:
                user_business_name = user_data.get('business_name')
                
                # Skip the one we're already updating
                if user_business_name == business_name:
                    continue
                
                # Add with default 'present' status
                members.append({
                    'business_name': user_business_name,
                    'status': 'present',
                    'notes': ''
                })
            
            # Create the new record
            record_id = create_attendance_record(meeting_date, members)
            
            if record_id:
                print(f"Created new attendance record {record_id} for date {meeting_date}")
                webhook_result = send_attendance_change_webhook(meeting_date, business_name, status, notes)
                print(f"Webhook result for {business_name} update: {webhook_result}")
                return jsonify({
                    'success': True,
                    'message': 'New attendance record created',
                    'record_id': str(record_id),
                    'webhook_sent': webhook_result,
                    'timestamp': datetime.now().timestamp()
                })
            else:
                print("Failed to create new attendance record")
                return jsonify({'success': False, 'message': 'Failed to create attendance record'}), 500
            
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Error updating attendance item: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/test_attendance_webhook', methods=['GET'])
@login_required
def test_attendance_webhook():
    """
    A test endpoint to manually trigger the attendance webhook for testing.
    """
    # Get the current user
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    # Only admins can test webhooks
    if not user or user.get('business_name') != 'Admin':
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        # Test data
        test_date = datetime.now().strftime('%Y-%m-%d')
        test_business = "Test Business"
        test_status = "present"
        test_notes = "Test webhook note"
        
        # Call the webhook functions
        print("Testing attendance change webhook...")
        change_result = send_attendance_change_webhook(test_date, test_business, test_status, test_notes)
        
        # Call the full attendance webhook with multiple members
        print("Testing full attendance webhook...")
        members = [
            {
                'business_name': 'Test Business 1',
                'status': 'present',
                'notes': 'Test note 1'
            },
            {
                'business_name': 'Test Business 2',
                'status': 'absent',
                'notes': 'Test note 2'
            }
        ]
        full_result = send_attendance_webhook(test_date, members)
        
        return jsonify({
            'success': True,
            'change_webhook_result': change_result,
            'full_webhook_result': full_result,
            'message': 'Webhooks tested',
            'timestamp': datetime.now().timestamp()
        })
    except Exception as e:
        import traceback
        print(f"Error testing webhooks: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5015)
