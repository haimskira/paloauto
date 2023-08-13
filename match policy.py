import requests

def get_security_rules():
    policy_response = requests.get(endpoints['security_rules'], headers=headers, verify=False)
    if policy_response.status_code == 200:
        return policy_response.json()['result']['entry']
    else:
        print(f"Failed to fetch security rules. Status code: {policy_response.status_code}")
        return []

def get_address_objects():
    address_response = requests.get(endpoints['address_objects'], headers=headers, verify=False)
    if address_response.status_code == 200:
        return address_response.json()['result']['entry']
    else:
        print(f"Failed to fetch address objects. Status code: {address_response.status_code}")
        return []

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


def the_rule(rules, objects, services, source_ip, destination_ip, user_service):
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

    if not found_policy:
        print(f"No security rule found containing source IP '{source_ip}', destination IP '{destination_ip}', and matching service '{user_service}'.")

firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='
headers = {'Authorization': api_key}

# API endpoints
endpoints = {
    'security_rules': 'https://10.0.4.253/restapi/v10.1/Policies/SecurityRules?location=vsys&vsys=vsys1',
    'address_objects': 'https://10.0.4.253/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1',
    'predefined_services': 'https://10.0.4.253/restapi/v10.1/Objects/Services?location=predefined&vsys=vsys1',
    'vsys_services': 'https://10.0.4.253/restapi/v10.1/Objects/Services?location=vsys&vsys=vsys1',
}

user_source_ip = input("Enter the source IP address: ")
user_destination_ip = input("Enter the destination IP address: ")
user_service = input("Enter the service: ")

rules = get_security_rules()
address_objects = get_address_objects()
service_objects = get_service_objects()

the_rule(rules, address_objects, service_objects, user_source_ip, user_destination_ip, user_service)