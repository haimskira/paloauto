import requests

class PaloAuto:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.endpoints = {
            'security_rules': f'https://{firewall_ip}/restapi/v10.1/Policies/SecurityRules?location=vsys&vsys=vsys1',
            'address_objects': f'https://{firewall_ip}/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1',
            'predefined_services': f'https://{firewall_ip}/restapi/v10.1/Objects/Services?location=predefined&vsys=vsys1',
            'vsys_services': f'https://{firewall_ip}/restapi/v10.1/Objects/Services?location=vsys&vsys=vsys1',
            'interfaces': f'https://{firewall_ip}/restapi/v10.1/Network/AggregateEthernetInterfaces',
            'zones': f'https://{firewall_ip}/restapi/v10.1/Network/Zones?location=vsys&vsys=vsys1'
        }
        self.headers = {'Authorization': api_key}
        self.base_url = f'https://{firewall_ip}/restapi/v10.1'

    def get_security_rules(self):
        policy_response = requests.get(self.endpoints['security_rules'], headers=self.headers, verify=False)
        if policy_response.status_code == 200:
            return policy_response.json()['result']['entry']
        else:
            print(f"Failed to fetch security rules. Status code: {policy_response.status_code}")
            return []

    def get_address_objects(self):
        address_response = requests.get(self.endpoints['address_objects'], headers=self.headers, verify=False)
        if address_response.status_code == 200:
            return address_response.json()['result']['entry']
        else:
            print(f"Failed to fetch address objects. Status code: {address_response.status_code}")
            return []

    def delete_address_object(self, object_name):
        delete_url = f"{self.base_url}/Objects/Addresses?location=vsys&vsys=vsys1&name={object_name}"
        response = requests.delete(delete_url, headers=self.headers, verify=False)
        if response.status_code == 200:
            print(f"Address object '{object_name}' deleted successfully.")
        else:
            print(f"Failed to delete address object '{object_name}'. Status code: {response.status_code}")

# Example usage
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='

palo_auto = PaloAuto(firewall_ip, api_key)

# Get security rules and address objects
security_rules = palo_auto.get_security_rules()
address_objects = palo_auto.get_address_objects()

# Extract used address object names from security rules
used_object_names = set()
for rule in security_rules:
    for member in rule['destination']['member']:
        used_object_names.add(member)
    for member in rule['source']['member']:
        used_object_names.add(member)

# Delete unused address objects
for obj in address_objects:
    object_name = obj['@name']
    if object_name not in used_object_names:
        palo_auto.delete_address_object(object_name)
