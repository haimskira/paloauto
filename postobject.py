import requests

class PaloAuto:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
        self.base_url = f'https://{firewall_ip}/restapi/v10.1'

    def post_service_object(self, service_name, ports):
        service_data = {
            "entry": {
                "@name": service_name,
                "protocol": {
                    "tcp": {"port": ports}
                }
            }
        }
        post_url = f"{self.base_url}/Objects/Services?location=vsys&vsys=vsys1"
        response = requests.post(post_url, headers=self.headers, json=service_data, verify=False)
        if response.status_code == 200:
            print(f"Service object '{service_name}' created successfully.")
        else:
            print(f"Failed to create service object '{service_name}'. Status code: {response.status_code}")

    def post_address_object(self, address_name, ip_range):
        address_data = {
            "entry": {
                "@name": address_name,
                "ip-netmask": ip_range
            }
        }
        post_url = f"{self.base_url}/Objects/Addresses?location=vsys&vsys=vsys1"
        response = requests.post(post_url, headers=self.headers, json=address_data, verify=False)
        if response.status_code == 200:
            print(f"Address object '{address_name}' created successfully.")
        else:
            print(f"Failed to create address object '{address_name}'. Status code: {response.status_code}")

# Example usage
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='

palo_auto = PaloAuto(firewall_ip, api_key)

# Create a TCP service object for port 80
palo_auto.post_service_object("web-service", "80")

# Create a UDP service object for port 123
palo_auto.post_service_object("ntp-service", "udp/123")

# Create an address object for a specific IP
palo_auto.post_address_object("server-1", "10.0.1.1/32")

# Create an address object for an IP range
palo_auto.post_address_object("ip-range", "192.168.1.1-192.168.1.255")

# Create an address object for a subnet
palo_auto.post_address_object("subnet", "172.16.0.0/16")
