import requests
import ipaddress

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

def get_interface_info():
    interface_response = requests.get(endpoints['interfaces'], headers=headers, verify=False)
    if interface_response.status_code == 200:
        return interface_response.json()['result']['entry']
    else:
        print(f"Failed to fetch interface information. Status code: {interface_response.status_code}")
        return []


def get_zone_info():
    zone_response = requests.get(endpoints['zones'], headers=headers, verify=False)
    if zone_response.status_code == 200:
        return zone_response.json()['result']['entry']
    else:
        print(f"Failed to fetch zone information. Status code: {zone_response.status_code}")
        return []


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
    'interfaces': 'https://10.0.4.253/restapi/v10.1/Network/AggregateEthernetInterfaces',
    'zones': 'https://10.0.4.253/restapi/v10.1/Network/Zones?location=vsys&vsys=vsys1'
}

user_source_ip = "1.1.1.1"
user_destination_ip = "8.8.8.8"
user_service = "80"

# Find and print the zone for the source and destination IPs
interfaces = get_interface_info()
zones = get_zone_info()

source_zone = find_zone_for_ip(user_source_ip, interfaces, zones)
destination_zone = find_zone_for_ip(user_destination_ip, interfaces, zones)
print(f"Source IP '{user_source_ip}' is in zone '{source_zone}'")
print(f"Destination IP '{user_destination_ip}' is in zone '{destination_zone}'")


rules = get_security_rules()
address_objects = get_address_objects()
service_objects = get_service_objects()
interfaces = get_interface_info()
zones = get_zone_info()

the_rule(rules, address_objects, service_objects, user_source_ip, user_destination_ip, user_service)
