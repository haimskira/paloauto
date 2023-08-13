
from urllib import response
import requests
from django.http import JsonResponse
   
def get_security_rules():
    firewall_ip = '10.0.4.253'
    endpoint = f'https://{firewall_ip}/restapi/v10.1/Policies/SecurityRules?location=vsys&vsys=vsys1'
    api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='
    headers = {'Authorization': api_key}
    response = requests.get(endpoint, headers=headers, verify=False)

    response = requests.get(api_endpoint, headers=headers, verify=False)

if response.status_code == 200:
    rules_data = response.json()['result']

    for rule in rules_data:
        rule_name = rule['@name']
        source_zone = rule['from']['member'][0] if 'from' in rule else 'N/A'
        destination_zone = rule['to']['member'][0] if 'to' in rule else 'N/A'
        source_ip = rule['source']['member'][0] if 'source' in rule else 'N/A'
        destination_ip = rule['destination']['member'][0] if 'destination' in rule else 'N/A'
        interface = 'N/A'  # You need to implement the logic to match zones to interfaces
        action = rule['action']

        print(f"Rule: {rule_name}")
        print(f"Source Zone: {source_zone}")
        print(f"Destination Zone: {destination_zone}")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")
        print(f"Interface: {interface}")
        print(f"Action: {action}")
        print("-" * 30)

else:
    print("Error: Failed to retrieve policy rules")

if __name__ == '__main__':
    get_security_rules()
