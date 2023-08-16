import subprocess
import requests
import socket

# Set firewall IP and API key
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='
headers = {'Authorization': api_key}

# Define API endpoints
address_objects_endpoint = 'https://10.0.4.253/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1'

# Fetch address objects from the firewall
address_response = requests.get(address_objects_endpoint, headers=headers, verify=False)
if address_response.status_code == 200:
    address_objects = address_response.json()['result']['entry']
else:
    print(f"Failed to fetch address objects. Status code: {address_response.status_code}")
    address_objects = []

# Function to resolve DNS name using ping -a command
def resolve_dns_name(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception as e:
        print(f"Error resolving DNS name for IP {ip}: {e}")
        return None

# Update address objects with resolved DNS names
for obj in address_objects:
    if 'ip-netmask' in obj and '@name' in obj:
        ip = obj['ip-netmask']
        if '/' in ip:  # Remove prefix length (/24, /32, /any) if present
            ip = ip.split('/')[0]
        resolved_name = resolve_dns_name(ip)
        if resolved_name:
            description = resolved_name
            update_data = {
                "entry": {
                    "@name": obj['@name'],
                    "@location": "vsys",
                    "@vsys": "vsys1",
                    "ip-netmask": ip,
                    "description": description
                }
            }
            update_url = f"https://10.0.4.253/restapi/v10.1/Objects/Addresses?name={obj['@name']}&location=vsys&vsys=vsys1"
            response = requests.put(update_url, headers=headers, json=update_data, verify=False)
            if response.status_code == 200:
                print(f"Updated description for address object '{obj['@name']}' with resolved DNS name '{resolved_name}'.")
            else:
                print(f"Failed to update address object '{obj['@name']}'. Status code: {response.status_code}")
        else:
            print(f"Failed to resolve DNS name for IP '{ip}'.")
