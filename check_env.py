"""
Check Environment Variables
--------------------------
This script checks if the required environment variables are set.
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# List of required environment variables
required_vars = [
    'MONGODB_URI',
    'DB',
    'FLASK_SECRET_KEY',
    'FLASK_APP'
]

print("Checking environment variables...")
print("-" * 40)

all_present = True

for var in required_vars:
    value = os.getenv(var)
    if value:
        # Show first few characters for sensitive values
        if var == 'MONGODB_URI' or var == 'FLASK_SECRET_KEY':
            masked_value = value[:10] + "..." if len(value) > 10 else value
            print(f"✅ {var}: {masked_value}")
        else:
            print(f"✅ {var}: {value}")
    else:
        print(f"❌ {var}: Not set")
        all_present = False

print("-" * 40)
if all_present:
    print("All required environment variables are set!")
else:
    print("Some required environment variables are missing!")
