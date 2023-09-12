import requests
import csv
import ipaddress
import json

api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='
FIREWALL_IP = '10.0.4.253'
ADDRESS_URL = f'https://{FIREWALL_IP}/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1'

CSV_FILE = 'interface_mappings.csv'

# Set up headers with basic auth and specify Content-Type as JSON
headers = {
    'Authorization': api_key,
    'Content-Type': 'application/json'  # Set the Content-Type to JSON
}

# Get existing address objects
response = requests.get(ADDRESS_URL, headers=headers, verify=False)

if 'result' in response.json():
    address_objects = response.json()['result']['entry']
else:
    address_objects = response.json()

# Load IP networks and tags from CSV
ip_tags = {}

with open(CSV_FILE) as csvfile:
    reader = csv.DictReader(csvfile)

    for row in reader:
        ip_network_str = row['Address']
        tag = row['Tags']

        # Check if it's an IP range
        if '-' in ip_network_str:
            ip_start, ip_end = ip_network_str.split('-')
            ip_range = ipaddress.summarize_address_range(ipaddress.IPv4Address(ip_start), ipaddress.IPv4Address(ip_end))

            for ip_network in ip_range:
                for obj in address_objects:
                    if 'ip-netmask' in obj:
                        obj_ip = ipaddress.IPv4Address(obj['ip-netmask'].split('/')[0])
                        if obj_ip in ip_network:
                            new_tag = tag
                            print(f"Updating {obj['@name']} with tag {new_tag}")
                            obj_to_update = {
                                "@name": obj['@name'],
                                "ip-netmask": obj['ip-netmask'],
                                "tag": {"member": [new_tag]}
                            }

                            # Check if the object exists in the address_objects list
                            if obj['@name'] in [a['@name'] for a in address_objects]:
                                update_response = requests.put(
                                    ADDRESS_URL,
                                    params={"name": obj['@name']},
                                    json={'entry': [obj_to_update]},  # Use a list for entry
                                    headers=headers,
                                    verify=False
                                )

                                if update_response.status_code == 200:
                                    print(f"Updated address object {obj['@name']}")
                                else:
                                    print(f"Failed to update {obj['@name']}. Status code: {update_response.status_code}")
                            else:
                                print(f"Object {obj['@name']} not found on the firewall.")

        else:
            ip_network = ipaddress.IPv4Network(ip_network_str, strict=False)

            for obj in address_objects:
                if 'ip-netmask' in obj:
                    obj_ip = ipaddress.IPv4Address(obj['ip-netmask'].split('/')[0])
                    if obj_ip in ip_network:
                        new_tag = tag
                        print(f"Updating {obj['@name']} with tag {new_tag}")
                        obj_to_update = {
                            "@name": obj['@name'],
                            "ip-netmask": obj['ip-netmask'],
                            "tag": {"member": [new_tag]}
                        }

                        # Check if the object exists in the address_objects list
                        if obj['@name'] in [a['@name'] for a in address_objects]:
                            update_response = requests.put(
                                ADDRESS_URL,
                                params={"name": obj['@name']},
                                json={'entry': [obj_to_update]},  # Use a list for entry
                                headers=headers,
                                verify=False
                            )

                            if update_response.status_code == 200:
                                print(f"Updated address object {obj['@name']}")
                            else:
                                print(f"Failed to update {obj['@name']}. Status code: {update_response.status_code}")
                        else:
                            print(f"Object {obj['@name']} not found on the firewall.")

print("Address object update complete!")
