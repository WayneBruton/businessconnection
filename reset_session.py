"""
Reset Session Script
-------------------
This script creates a simple Flask route that clears all session data and cookies,
then redirects to the login page with a fresh session.
"""

from flask import Flask, redirect, url_for, session, make_response

app = Flask(__name__)
app.secret_key = 'temporary-secret-key'

@app.route('/reset')
def reset_session():
    """Clear all session data and cookies, then redirect to login page."""
    # Clear the session
    session.clear()
    
    # Create a response that redirects to login
    response = make_response(redirect('/login'))
    
    # Delete all cookies
    response.delete_cookie('jwt_token')
    response.delete_cookie('session')
    
    # Add a message
    return response

if __name__ == '__main__':
    print("Starting session reset server on port 5016...")
    print("Open http://localhost:5016/reset in your browser to reset your session.")
    app.run(debug=True, port=5016)
