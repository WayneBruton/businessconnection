#!/usr/bin/env python3
"""
Fix Password Verification Script
--------------------------------
This script updates the verify_password function in database.py to handle both string and bytes password formats.
"""

import os
import re

# Path to the database.py file
database_file = 'database.py'

# Read the current content of the file
with open(database_file, 'r') as f:
    content = f.read()

# Define the current verify_password function pattern
current_function_pattern = r'def verify_password\(stored_password, provided_password\):\s+"""Verify a stored password against one provided by user."""\s+return bcrypt\.checkpw\(provided_password\.encode\(\'utf-8\'\), stored_password\)'

# Define the new verify_password function
new_function = '''def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user."""
    try:
        # Ensure stored_password is bytes
        if not isinstance(stored_password, bytes):
            stored_password = stored_password.encode('utf-8')
        
        # Encode the provided password
        encoded_password = provided_password.encode('utf-8')
        
        # Verify the password
        return bcrypt.checkpw(encoded_password, stored_password)
    except Exception as e:
        print(f"Error verifying password: {e}")
        return False'''

# Replace the function
updated_content = re.sub(current_function_pattern, new_function, content)

# Write the updated content back to the file
with open(database_file, 'w') as f:
    f.write(updated_content)

print("Updated verify_password function in database.py")
