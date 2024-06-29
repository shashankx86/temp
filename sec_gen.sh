#!/bin/bash

# Generate a new refresh secret
NEW_REFRESH_SECRET=$(openssl rand -base64 32)

# Define the .env file path
ENV_FILE=".env"

# Ensure the .env file exists
if [ ! -f "$ENV_FILE" ]; then
    echo ".env file does not exist. Creating a new one."
    touch "$ENV_FILE"
fi

# Use sed to find and replace the REFRESH_SECRET
if grep -q "^REFRESH_SECRET=" "$ENV_FILE"; then
    # If REFRESH_SECRET exists, replace it
    sed -i "s/^REFRESH_SECRET=.*/REFRESH_SECRET=$NEW_REFRESH_SECRET/" "$ENV_FILE"
else
    # If REFRESH_SECRET does not exist, add it
    echo "REFRESH_SECRET=$NEW_REFRESH_SECRET" >> "$ENV_FILE"
fi

echo ".env file has been updated with a new REFRESH_SECRET."
