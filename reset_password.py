"""
Reset Password Script
--------------------
This script resets a user's password for debugging purposes.
"""

import os
from dotenv import load_dotenv
from database import reset_user_password

# Load environment variables
load_dotenv()

def main():
    """Reset a user's password."""
    email = input("Enter user email: ")
    new_password = input("Enter new password: ")
    
    if reset_user_password(email, new_password):
        print(f"Password for {email} has been reset successfully.")
    else:
        print(f"Failed to reset password for {email}.")

if __name__ == "__main__":
    main()
