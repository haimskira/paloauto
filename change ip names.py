import requests

class PaloAuto:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
        self.base_url = f'https://{firewall_ip}/restapi/v10.1'

    def get_address_objects(self):
        get_url = f"{self.base_url}/Objects/Addresses?location=vsys&vsys=vsys1"
        response = requests.get(get_url, headers=self.headers, verify=False)
        if response.status_code == 200:
            return response.json()['result']['entry']
        else:
            print(f"Failed to fetch address objects. Status code: {response.status_code}")
            return []

    def update_address_object_name(self, object_id, new_name):
        update_data = {
            "entry": {
                "@name": new_name
            }
        }
        update_url = f"{self.base_url}/Objects/Addresses/{object_id}?location=vsys&vsys=vsys1&name={new_name}"
        response = requests.put(update_url, headers=self.headers, json=update_data, verify=False)
        if response.status_code == 200:
            print(f"Address object '{object_id}' updated successfully with new name '{new_name}'.")
        else:
            print(f"Failed to update address object '{object_id}'. Status code: {response.status_code}")

    def update_address_objects_with_ip_ranges(self):
        address_objects = self.get_address_objects()
        for obj in address_objects:
            if 'ip-netmask' in obj:
                ip_value = obj['ip-netmask']
                new_name = ip_value.replace(".", "-")
                self.update_address_object_name(obj['@name'], new_name)
            elif 'ip-range' in obj:
                ip_range_value = obj['ip-range']
                ip_range_parts = ip_range_value.split("-")
                start_ip, end_ip = ip_range_parts[0], ip_range_parts[1]
                new_name = f"range-{start_ip.replace('.', '-')}-{end_ip.replace('.', '-')}"
                self.update_address_object_name(obj['@name'], new_name)

# Example usage
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='

palo_auto = PaloAuto(firewall_ip, api_key)
palo_auto.update_address_objects_with_ip_ranges()
