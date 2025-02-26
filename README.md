# Business Connection Referral System

A Flask-based web application with user authentication and MongoDB integration.

## Features

- User authentication (login/register)
- Mobile-friendly responsive design
- Secure password storage with bcrypt encryption
- JWT token-based authentication
- MongoDB integration

## User Model

The application stores the following user information:
- Email (used as username)
- Password (encrypted)
- First Name
- Last Name
- Business Name
- JWT token (for authentication)

## Setup Instructions

1. Install dependencies:
```
pip install -r requirements.txt
```

2. Make sure your `.env` file contains the following variables:
```
MONGODB_URI="your-mongodb-connection-string"
FLASK_SECRET_KEY="your-secret-key"
DB="your-database-name"
```

3. Run the application:
```
python app.py
```

4. Access the application at http://localhost:5000

## Project Structure

- `app.py`: Main application file with routes
- `database.py`: Database connection and operations
- `forms.py`: Form validation using Flask-WTF
- `templates/`: HTML templates
  - `login.html`: Login page
  - `register.html`: Registration page
  - `dashboard.html`: User dashboard
- `static/css/`: CSS stylesheets
  - `style.css`: Main stylesheet

## Security Features

- Password hashing using bcrypt
- CSRF protection with Flask-WTF
- JWT token authentication
- Session-based authentication
