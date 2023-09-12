import requests
import csv
import json

# Your API key and firewall IP
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='
FIREWALL_IP = '10.0.4.253'

# CSV file containing tag information
CSV_FILE = 'tag_mappings.csv'

# URL for adding tags
TAG_URL = f'https://{FIREWALL_IP}/restapi/v10.1/Objects/Tags?location=vsys&vsys=vsys1'

# Set up headers with basic auth and specify Content-Type as JSON
headers = {
    'Authorization': api_key,
    'Content-Type': 'application/json'  # Set the Content-Type to JSON
}

# Function to send a POST request to add a tag
def add_tag(tag_name, color):
    # Updated URL with the tag name
    tag_url = f'{TAG_URL}&name={tag_name}'

    payload = {
        "entry": {
            "@name": tag_name,
            "color": color
        }
    }
    print(payload)
    response = requests.post(tag_url, json=payload, headers=headers, verify=False)
    if response.status_code == 200:
        print(f"Tag '{tag_name}' added successfully.")
    else:
        print(f"Failed to add tag '{tag_name}'. Status code: {response.status_code}")

# Load tag data from CSV and add tags
with open(CSV_FILE) as csvfile:
    reader = csv.DictReader(csvfile)
    print(reader)

    for row in reader:
        # Check for 'Tag' column with or without leading/trailing whitespaces
        tag_name = row.get('Tag', '').strip()
        color = row.get('Color', '').strip()
        print(tag_name, color)
        if tag_name:
            add_tag(tag_name, color)

print("Tag addition complete!")
