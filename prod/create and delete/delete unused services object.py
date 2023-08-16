import requests

class PaloAuto:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.endpoints = {
            'security_rules': f'https://{firewall_ip}/restapi/v10.1/Policies/SecurityRules?location=vsys&vsys=vsys1',
            'predefined_services': f'https://{firewall_ip}/restapi/v10.1/Objects/Services?location=predefined&vsys=vsys1',
            'vsys_services': f'https://{firewall_ip}/restapi/v10.1/Objects/Services?location=vsys&vsys=vsys1',
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
    
    def get_service_objects(self):
        predefined_service_response = requests.get(self.endpoints['predefined_services'], headers=self.headers, verify=False)
        vsys_service_response = requests.get(self.endpoints['vsys_services'], headers=self.headers, verify=False)

        service_objects = []

        if predefined_service_response.status_code == 200:
            predefined_services = predefined_service_response.json()['result']['entry']
            service_objects.extend(predefined_services)

        if vsys_service_response.status_code == 200:
            vsys_services = vsys_service_response.json()['result']['entry']
            service_objects.extend(vsys_services)

        return service_objects
        
    def delete_service_object(self, object_name):
        delete_url = f"{self.base_url}/Objects/Services?location=vsys&vsys=vsys1&name={object_name}"
        response = requests.delete(delete_url, headers=self.headers, verify=False)
        if response.status_code == 200:
            print(f"Service object '{object_name}' deleted successfully.")
        else:
            print(f"Failed to delete service object '{object_name}'. Status code: {response.status_code}")

# Example usage
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='

palo_auto = PaloAuto(firewall_ip, api_key)

# Get security rules and service objects
security_rules = palo_auto.get_security_rules()
service_objects = palo_auto.get_service_objects()

# Extract used service object names from security rules
used_service_names = set()
for rule in security_rules:
    for member in rule['service']['member']:
        used_service_names.add(member)

# Delete unused service objects
for obj in service_objects:
    object_name = obj['@name']
    if object_name not in used_service_names:
        palo_auto.delete_service_object(object_name)
