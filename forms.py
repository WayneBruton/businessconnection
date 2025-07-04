import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField, DateField, TextAreaField, HiddenField, RadioField
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
    mobile_number = StringField('Mobile Number', validators=[
        Length(max=20, message="Mobile number must be less than 20 characters")
    ])
    office_number = StringField('Office Number', validators=[
        Length(max=20, message="Office number must be less than 20 characters")
    ])
    enabled = BooleanField('Enable Account', default=True)
    notify = BooleanField('Receive Notifications', default=True)
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = get_user_by_email(email.data)
        if user:
            raise ValidationError('Email already registered. Please use a different email or login.')

class EditUserForm(FlaskForm):
    """Form for editing an existing user."""
    user_id = HiddenField('User ID')
    email = StringField('Email', validators=[
        DataRequired(message="Email is required"),
        Email(message="Please enter a valid email address"),
        Length(min=5, max=100, message="Email must be between 5 and 100 characters")
    ])
    password = PasswordField('New Password', validators=[
        Length(min=8, message="Password must be at least 8 characters long")
    ], description="Leave blank to keep current password")
    confirm_password = PasswordField('Confirm New Password', validators=[
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
    business_name = SelectField('Business Name')
    mobile_number = StringField('Mobile Number', validators=[
        Length(max=20, message="Mobile number must be less than 20 characters")
    ])
    office_number = StringField('Office Number', validators=[
        Length(max=20, message="Office number must be less than 20 characters")
    ])
    enabled = BooleanField('Enable Account')
    notify = BooleanField('Receive Notifications')
    five_minute_talk = StringField('5-Minute Talk', validators=[
        Length(max=2000, message="5-minute talk must be less than 2000 characters")
    ])
    ten_minute_talk = StringField('10-Minute Talk', validators=[
        Length(max=5000, message="10-minute talk must be less than 5000 characters")
    ])
    submit = SubmitField('Update User')
    
    def validate_password(self, field):
        # Skip validation if the field is empty (meaning keep the current password)
        if not field.data:
            field.errors = []
            return False
        return True
        
    def validate_business_name(self, field):
        # Skip validation for business_name since it's disabled in the form
        # and we're handling it separately in the route
        field.errors = []
        return True

class ReferralForm(FlaskForm):
    """Form for creating a new referral."""
    from_business = StringField('From Business', render_kw={'readonly': True})
    to_business = SelectField('To Business', validators=[
        DataRequired(message="Business is required")
    ])
    referral_date = DateField('Referral Date', render_kw={'readonly': True})
    referral_type = RadioField('Referral Type', choices=[('internal', 'Internal'), ('external', 'External'), ('visitor', 'Visitor')], validators=[
        DataRequired(message="Please select a referral type")
    ])
    to_name = StringField('Referral Person Name', validators=[
        DataRequired(message="Referral person name is required"),
        Length(min=2, max=100, message="Name must be between 2 and 100 characters")
    ])
    contact_info = StringField('Contact Information (Email or Phone ### ### ####)', validators=[
            DataRequired(message="Contact information is required"),
            Length(min=5, max=100, message="Contact information must be between 5 and 100 characters")
        ])
        
    def validate_contact_info(self, field):
        value = field.data
        # Check if it's an email
        if '@' in value:
            email_validator = Email(message="Please enter a valid email address")
            try:
                email_validator(self, field)
            except ValidationError:
                raise ValidationError("Please enter a valid email address or phone number in format ### ### ####")
        # Check if it's a phone number
        else:
            # Remove any non-digit characters
            digits = re.sub(r'\D', '', value)
            # Check if it's exactly 10 digits and format as ### ### ####
            if len(digits) != 10 or not digits.isdigit():
                raise ValidationError("Phone number must be 10 digits (e.g., 123 456 7890)")
            # Reformat the phone number to the desired format
            formatted_phone = f"{digits[:3]} {digits[3:6]} {digits[6:]}"
            field.data = formatted_phone
    notes = TextAreaField('Notes', validators=[
        Length(max=500, message="Notes must be less than 500 characters")
    ])
    submit = SubmitField('Submit Referral')
