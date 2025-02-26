import os
from flask import Flask, render_template, redirect, url_for, flash, request, session
from functools import wraps
from dotenv import load_dotenv
from forms import LoginForm, RegistrationForm, ReferralForm
from database import (
    create_user, get_user_by_email, verify_password, 
    generate_jwt_token, decode_jwt_token, get_user_by_id,
    create_referral, get_referrals_by_user
)
from datetime import datetime

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
        enabled = form.enabled.data
        notify = form.notify.data
        
        user_id = create_user(email, password, first_name, last_name, business_name, enabled, notify)
        
        if user_id:
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html', form=form)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    # Get user from database
    user_id = session.get('user_id')
    user = get_user_by_id(user_id)
    
    if not user:
        # If user not found, log them out
        return redirect(url_for('logout'))
    
    # Initialize referral form
    referral_form = ReferralForm()
    
    # Handle referral form submission
    if request.method == 'POST' and referral_form.validate_on_submit():
        to_business = referral_form.to_business.data
        to_name = referral_form.to_name.data
        contact_info = referral_form.contact_info.data
        details = referral_form.details.data
        
        # Create referral
        referral_id = create_referral(
            from_user_id=user_id,
            from_business=user['business_name'],
            to_business=to_business,
            to_name=to_name,
            contact_info=contact_info,
            details=details
        )
        
        if referral_id:
            flash('Referral submitted successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to submit referral. Please try again.', 'error')
    
    # Get user's referrals
    referrals = get_referrals_by_user(user_id)
    
    # Get current date and time for the form
    now = datetime.now()
    
    return render_template('dashboard.html', user=user, referral_form=referral_form, referrals=referrals, now=now)

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
    app.run(debug=True, host='0.0.0.0', port=5004)
