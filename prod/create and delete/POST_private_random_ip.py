import requests
import random

class PaloAuto:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
        self.base_url = f'https://{firewall_ip}/restapi/v10.1'

    def post_address_object(self, address_name, ip_range):
        address_data = {
            "entry": {
                "@name": address_name,
                "ip-netmask": ip_range
            }
        }
        post_url = f"{self.base_url}/Objects/Addresses?location=vsys&vsys=vsys1&name={address_name}"
        response = requests.post(post_url, headers=self.headers, json=address_data, verify=False)
        if response.status_code == 200:
            print(f"Address object '{address_name}' created successfully.")
        else:
            print(f"Failed to create address object '{address_name}'. Status code: {response.status_code}")

    def generate_random_private_ip(self):
        # first_octet = 10
        # second_octet = random.randint(0, 255)
        # third_octet = random.randint(0, 255)
        # fourth_octet = random.randint(1, 254)
        first_octet = 1
        second_octet = 1
        third_octet = 1
        fourth_octet = random.randint(1, 254)
        return f"{first_octet}.{second_octet}.{third_octet}.{fourth_octet}"

# Example usage
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='

palo_auto = PaloAuto(firewall_ip, api_key)

# Create 10 random address objects with /24 prefixes
for _ in range(10):
    ip_address = palo_auto.generate_random_private_ip()
    address_name = ip_address.replace('.', '-')  # Replace dots with hyphens for the name
    ip_range = ip_address + "/32"
    palo_auto.post_address_object(address_name, ip_range)
