from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from database import get_user_by_email

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email address")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required")
    ])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email address"),
        Length(min=5, max=100, message="Email must be between 5 and 100 characters")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(message="Password is required"),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(message="Please confirm your password"),
        EqualTo('password', message="Passwords must match")
    ])
    first_name = StringField('First Name', validators=[
        DataRequired(message="First name is required"),
        Length(min=2, max=50, message="First name must be between 2 and 50 characters")
    ])
    last_name = StringField('Last Name', validators=[
        DataRequired(message="Last name is required"),
        Length(min=2, max=50, message="Last name must be between 2 and 50 characters")
    ])
    business_name = StringField('Business Name', validators=[
        DataRequired(message="Business name is required"),
        Length(min=2, max=100, message="Business name must be between 2 and 100 characters")
    ])
    enabled = BooleanField('Enable Account', default=True)
    notify = BooleanField('Receive Notifications', default=True)
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = get_user_by_email(email.data)
        if user:
            raise ValidationError('Email already registered. Please use a different email or login.')

class ReferralForm(FlaskForm):
    to_business = StringField('Business Name', validators=[
        DataRequired(message="Business name is required"),
        Length(min=2, max=100, message="Business name must be between 2 and 100 characters")
    ])
    to_name = StringField('Contact Person Name', validators=[
        DataRequired(message="Contact person name is required"),
        Length(min=2, max=100, message="Name must be between 2 and 100 characters")
    ])
    contact_info = StringField('Contact Information (Email or Phone)', validators=[
        DataRequired(message="Contact information is required"),
        Length(min=5, max=100, message="Contact information must be between 5 and 100 characters")
    ])
    details = StringField('Referral Details', validators=[
        DataRequired(message="Referral details are required"),
        Length(min=10, max=500, message="Details must be between 10 and 500 characters")
    ])
    submit = SubmitField('Submit Referral')
