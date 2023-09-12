import requests
import csv
import ipaddress

api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='
FIREWALL_IP = '10.0.4.253'

ADDRESS_URL = f'https://{FIREWALL_IP}/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1'
CSV_FILE = 'interface_mappings.csv'

# Set up basic auth
headers = {'Authorization': api_key}

# Get address objects
response = requests.get(ADDRESS_URL, headers=headers, verify=False)

if 'result' in response.json():
    address_objects = response.json()['result']['entry']
else:
    address_objects = response.json()

# Build dict of IP and IP range to tag from CSV
ip_mappings = {}
with open(CSV_FILE) as csvfile:
    reader = csv.reader(csvfile)
    next(reader)  # Skip the header row
    for row in reader:
        ip_or_range = row[0]
        tag = row[1]

        # Check if it's an IP range
        if '/' in ip_or_range:
            ip_network = ipaddress.ip_network(ip_or_range, strict=False)
            for ip in ip_network:
                ip_mappings[str(ip)] = tag
        else:
            ip_mappings[ip_or_range] = tag

# Update address object tags
for obj in address_objects:
    if 'ip-netmask' in obj:
        ip_netmask = obj['ip-netmask']
        if ip_netmask in ip_mappings:
            new_tag = ip_mappings[ip_netmask]
            print(f"Updating {obj['@name']} with tag {new_tag}")
            obj['tag'] = {'member': [new_tag]}

# Update the address objects on the firewall
update_response = requests.put(ADDRESS_URL, json={'entry': address_objects}, headers=headers, verify=False)

if update_response.status_code == 200:
    print("Address object tags updated successfully.")
else:
    print(f"Failed to update address objects. Status code: {update_response.status_code}")
    print("Response content:")
    print(update_response.content.decode())
