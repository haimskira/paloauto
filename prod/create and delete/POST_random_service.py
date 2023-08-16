import requests
import random

class PaloAuto:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
        self.base_url = f'https://{firewall_ip}/restapi/v10.1'

    def post_service_object(self, service_name, protocol, port_range):
        service_data = {
            "entry": {
                "@name": service_name,
                "protocol": {
                    protocol: {"port": port_range}
                }
            }
        }
        post_url = f"{self.base_url}/Objects/Services?location=vsys&vsys=vsys1&name={service_name}"
        response = requests.post(post_url, headers=self.headers, json=service_data, verify=False)
        if response.status_code == 200:
            print(f"Service object '{service_name}' created successfully.")
        else:
            print(f"Failed to create service object '{service_name}'. Status code: {response.status_code}")

    def generate_random_port(self):
        return random.randint(1, 65535)
    
    def generate_random_port_range(self):
        start_port = random.randint(1, 65535)
        end_port = random.randint(start_port, 65535)
        return f"{start_port}-{end_port}"

    def generate_service_name(self, protocol, port):
        return f"{protocol.upper()}_{port}"

# Example usage
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='

palo_auto = PaloAuto(firewall_ip, api_key)

# Create 10 random TCP service objects with random port ranges
for _ in range(10):
    protocol = "tcp"
    port_range = palo_auto.generate_random_port_range()
    service_name = palo_auto.generate_service_name(protocol, port_range)
    palo_auto.post_service_object(service_name, protocol, port_range)

# Create 10 random UDP service objects with random port ranges
for _ in range(10):
    protocol = "udp"
    port_range = palo_auto.generate_random_port_range()
    service_name = palo_auto.generate_service_name(protocol, port_range)
    palo_auto.post_service_object(service_name, protocol, port_range)

# Create 10 random TCP service objects with individual ports
for _ in range(10):
    protocol = "tcp"
    port = palo_auto.generate_random_port()
    service_name = palo_auto.generate_service_name(protocol, port)
    palo_auto.post_service_object(service_name, protocol, str(port))

# Create 10 random UDP service objects with individual ports
for _ in range(10):
    protocol = "udp"
    port = palo_auto.generate_random_port()
    service_name = palo_auto.generate_service_name(protocol, port)
    palo_auto.post_service_object(service_name, protocol, str(port))
