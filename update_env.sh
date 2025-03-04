#!/bin/bash
# Script to update the .env file with a secure secret key

# Generate a secure random key
SECURE_KEY=$(openssl rand -base64 32)

# Update the .env file
sed -i '' "s/FLASK_SECRET_KEY=\"your-secret-key-here\"/FLASK_SECRET_KEY=\"$SECURE_KEY\"/" .env

echo "Secret key updated successfully!"
echo "Please restart your Flask application for the changes to take effect."
