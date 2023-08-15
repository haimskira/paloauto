import requests
import ipaddress

# Set firewall IP and API key
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='
headers = {'Authorization': api_key}

# Define API endpoints
endpoints = {
    'security_rules': 'https://10.0.4.253/restapi/v10.1/Policies/SecurityRules?location=vsys&vsys=vsys1',
    'address_objects': 'https://10.0.4.253/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1',
    'predefined_services': 'https://10.0.4.253/restapi/v10.1/Objects/Services?location=predefined&vsys=vsys1',
    'vsys_services': 'https://10.0.4.253/restapi/v10.1/Objects/Services?location=vsys&vsys=vsys1',
    'interfaces': 'https://10.0.4.253/restapi/v10.1/Network/AggregateEthernetInterfaces',
    'zones': 'https://10.0.4.253/restapi/v10.1/Network/Zones?location=vsys&vsys=vsys1'
}


# Function to fetch security rules from the firewall
def get_security_rules():
    policy_response = requests.get(endpoints['security_rules'], headers=headers, verify=False)
    if policy_response.status_code == 200:
        return policy_response.json()['result']['entry']
    else:
        print(f" get_security_rules ELSE - Failed to fetch security rules. Status code: {policy_response.status_code}")
        return []

# Function to fetch address objects from the firewall
def get_address_objects():
    address_response = requests.get(endpoints['address_objects'], headers=headers, verify=False)
    if address_response.status_code == 200:
        return address_response.json()['result']['entry']
    else:
        print(f"get_address_objects ELSE - Failed to fetch address objects. Status code: {address_response.status_code}")
        return []

# Function to fetch service objects from the firewall
def get_service_objects():
    predefined_service_response = requests.get(endpoints['predefined_services'], headers=headers, verify=False)
    vsys_service_response = requests.get(endpoints['vsys_services'], headers=headers, verify=False)
    
    service_objects = []

    if predefined_service_response.status_code == 200:
        predefined_services = predefined_service_response.json()['result']['entry']
        service_objects.extend(predefined_services)

    if vsys_service_response.status_code == 200:
        vsys_services = vsys_service_response.json()['result']['entry']
        service_objects.extend(vsys_services)

    return service_objects

# Function to fetch interface information from the firewall
def get_interface_info():
    interface_response = requests.get(endpoints['interfaces'], headers=headers, verify=False)
    if interface_response.status_code == 200:
        return interface_response.json()['result']['entry']
    else:
        print(f"get_interface_info ELSE - Failed to fetch interface information. Status code: {interface_response.status_code}")
        return []

# Function to fetch zone information from the firewall
def get_zone_info():
    zone_response = requests.get(endpoints['zones'], headers=headers, verify=False)
    if zone_response.status_code == 200:
        return zone_response.json()['result']['entry']
    else:
        print(f"get_zone_info ELSE - Failed to fetch zone information. Status code: {zone_response.status_code}")
        return []

# Function to find the zone for a given IP based on interface configurations
def find_zone_for_ip(ip, interfaces, zones):
    for interface in interfaces:
        if 'layer3' in interface and 'units' in interface['layer3']:
            units = interface['layer3']['units']['entry']
            for unit in units:
                if 'ip' in unit and 'entry' in unit['ip'] and len(unit['ip']['entry']) > 0:
                    interface_ip = unit['ip']['entry'][0]['@name']
                    if '/' in interface_ip:  # Handle IP subnet
                        subnet = ipaddress.IPv4Network(interface_ip, strict=False)
                        if ipaddress.IPv4Address(ip) in subnet:
                            interface_name = unit['@name']
                            for zone in zones:
                                if 'network' in zone and 'layer3' in zone['network'] and 'member' in zone['network']['layer3']:
                                    if interface_name in zone['network']['layer3']['member']:
                                        return zone['@name']
    return None

def find_address_object_name(ip, address_objects):
    for obj in address_objects:
        if 'ip-netmask' in obj and obj['ip-netmask'] == ip:
            return obj['@name']
    return None

def match_rule(rules, objects, services, source_ip, destination_ip, user_service):
    found_policy = False
    for rule in rules:
        if 'source' in rule and 'member' in rule['source'] and \
           'destination' in rule and 'member' in rule['destination'] and \
           'service' in rule and 'member' in rule['service']:
            source_members = rule['source']['member']
            destination_members = rule['destination']['member']
            service_members = rule['service']['member']

            if source_ip in [obj['ip-netmask'] for obj in objects if '@name' in obj and obj['@name'] in source_members] and \
                destination_ip in [obj['ip-netmask'] for obj in objects if '@name' in obj and obj['@name'] in destination_members]:
                for service_member in service_members:
                    if any(service_member in srv['@name'] for srv in services):
                        print(f"Rule '{rule['@name']}' contains source IP '{source_ip}', destination IP '{destination_ip}', and matches service '{user_service}'.")
                        if 'to' in rule and 'member' in rule['to'] and 'from' in rule and 'member' in rule['from']:
                            zones_to = rule['to']['member']
                            zones_from = rule['from']['member']
                            print(f"Source Zones: {', '.join(zones_from)}")
                            print(f"Destination Zones: {', '.join(zones_to)}")
                        found_policy = True
                        break

    return found_policy

def get_service_key_by_value(service_value, service_objects):
    for service in service_objects:
        if 'protocol' in service and 'tcp' in service['protocol']:
            ports = service['protocol']['tcp']['port'].split(',')
            for port in ports:
                if int(port) == service_value:
                    return service['@name']
    return None


def get_address_object_by_ip(ip, address_objects):
    for obj in address_objects:
        if 'ip-netmask' in obj and obj['ip-netmask'] == ip:
            return obj['@name']
    return None

def post_security_rule(policy_name, source_zone, destination_zone, user_source_ip, user_destination_ip, user_service_value):

    existing_rule = match_rule(rules, address_objects, service_objects, user_source_ip, user_destination_ip, user_service_value)

    if existing_rule:
        print(f"post_security_rule if existing_rule - Rule with source IP '{user_source_ip}', destination IP '{user_destination_ip}', and matching service value '{user_service_value}' already exists:")
        print(existing_rule)
        return

    source_ip_object = get_address_object_by_ip(user_source_ip, address_objects)
    destination_ip_object = get_address_object_by_ip(user_destination_ip, address_objects)

    if source_ip_object is None:
        print(f"post_security_rule if source_ip_object is None - No address object found for source IP '{user_source_ip}'.")
        return

    if destination_ip_object is None:
        print(f"post_security_rule if destination_ip_object is None - No address object found for destination IP '{user_destination_ip}'.")
        return

    service_key = get_service_key_by_value(user_service_value, service_objects)
    if service_key is None:
        print(f"post_security_rule if service_key is None - Service object with value '{user_service_value}' not found.")
        return

    rule_data = {
        "entry": {
            "@name": policy_name,
            "@location": "vsys",
            "@vsys": "vsys1",
            "from": {"member": [source_zone]},
            "to": {"member": [destination_zone]},
            "source": {"member": [source_ip_object]},
            "destination": {"member": [destination_ip_object]},
            "service": {"member": [service_key]},
            "application": {"member": [user_application] if user_application != "any" else ["any"]},
            "action": "allow"
        }
    }
    print("\nNew rule details:")
    print("Rule Name:", policy_name)
    print("From Zone:", source_zone)
    print("To Zone:", destination_zone)
    print("Source IP:", user_source_ip)
    print("Destination IP:", user_destination_ip)
    print("Service:", service_key)
    print("Application:", user_application)
    print("Action: allow")
    print("\nRule Data:")
    print(rule_data)
    confirm = input("\nDo you want to post this rule? (yes/no): ").lower()
    if confirm == "yes":
        post_url = f"https://{firewall_ip}/restapi/v10.1/Policies/SecurityRules?name={policy_name}&location=vsys&vsys=vsys1"
        response = requests.post(post_url, headers=headers, json=rule_data, verify=False)

        if response.status_code == 200:
            print("New rule added successfully.")
        else:
            print(f"Failed to add new rule. Status code: {response.status_code}")
    else:
        print("Rule creation canceled.")


######################################################################################################################################

policy_name = "new_rule1"
user_source_ip = "1.1.1.1"
user_destination_ip = "8.8.8.8"
user_service_value = 80
user_application = "any"
# policy_name = input("Enter the policy name: ")
# user_source_ip = input("Enter source IP: ")
# user_destination_ip = input("Enter destination IP: ")
# user_service_value = int(input("Enter service port: "))
# user_application = input("Enter the application value for the new rule (enter 'any' if not specified): ")


# Fetch interface and zone information  security rules, address objects, and service objects
rules = get_security_rules()
interfaces = get_interface_info()
zones = get_zone_info()
address_objects = get_address_objects()
service_objects = get_service_objects()

# Find and print the zone for the source and destination IPs
source_zone = find_zone_for_ip(user_source_ip, interfaces, zones)
destination_zone = find_zone_for_ip(user_destination_ip, interfaces, zones)

if destination_zone is None:
    destination_zone = "untrust"

found_policy = match_rule(rules, address_objects, service_objects, user_source_ip, user_destination_ip, user_service_value)

# Post a new security rule if no match was found
if not found_policy:
    post_security_rule(policy_name, source_zone, destination_zone, user_source_ip, user_destination_ip, user_service_value)
