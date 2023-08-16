import requests
import ipaddress

class PaloAuto:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.headers = {'Authorization': api_key}
        self.endpoints = {
            'security_rules': f'https://{firewall_ip}/restapi/v10.1/Policies/SecurityRules?location=vsys&vsys=vsys1',
            'address_objects': f'https://{firewall_ip}/restapi/v10.1/Objects/Addresses?location=vsys&vsys=vsys1',
            'predefined_services': f'https://{firewall_ip}/restapi/v10.1/Objects/Services?location=predefined&vsys=vsys1',
            'vsys_services': f'https://{firewall_ip}/restapi/v10.1/Objects/Services?location=vsys&vsys=vsys1',
            'interfaces': f'https://{firewall_ip}/restapi/v10.1/Network/AggregateEthernetInterfaces',
            'zones': f'https://{firewall_ip}/restapi/v10.1/Network/Zones?location=vsys&vsys=vsys1'
        }
        self.rules = self.get_security_rules()
        self.interfaces = self.get_interface_info()
        self.zones = self.get_zone_info()
        self.address_objects = self.get_address_objects()
        self.service_objects = self.get_service_objects()

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

    def get_interface_info(self):
        interface_response = requests.get(self.endpoints['interfaces'], headers=self.headers, verify=False)
        if interface_response.status_code == 200:
            return interface_response.json()['result']['entry']
        else:
            print(f"Failed to fetch interface information. Status code: {interface_response.status_code}")
            return []

    def get_zone_info(self):
        zone_response = requests.get(self.endpoints['zones'], headers=self.headers, verify=False)
        if zone_response.status_code == 200:
            return zone_response.json()['result']['entry']
        else:
            print(f"Failed to fetch zone information. Status code: {zone_response.status_code}")
            return []

    def find_zone_for_ip(self, ip):
        for interface in self.interfaces:
            if 'layer3' in interface and 'units' in interface['layer3']:
                units = interface['layer3']['units']['entry']
                for unit in units:
                    if 'ip' in unit and 'entry' in unit['ip'] and len(unit['ip']['entry']) > 0:
                        interface_ip = unit['ip']['entry'][0]['@name']
                        if '/' in interface_ip:
                            subnet = ipaddress.IPv4Network(interface_ip, strict=False)
                            if ipaddress.IPv4Address(ip) in subnet:
                                interface_name = unit['@name']
                                for zone in self.zones:
                                    if 'network' in zone and 'layer3' in zone['network'] and 'member' in zone['network']['layer3']:
                                        if interface_name in zone['network']['layer3']['member']:
                                            return zone['@name']
        return None
    
    def find_address_object_name(self, ip):
        print(f"Searching for address object with IP: {ip}")
                # Check if the input IP contains a range
        if '-' in ip:
            ip_range = ip.split('-')
            start_ip, end_ip = ip_range[0], ip_range[1]
            start_octets = start_ip.split('.')
            end_octets = end_ip.split('.')
            start_prefix = '.'.join(start_octets[:-1])
            end_prefix = '.'.join(end_octets[:-1])
            start_num = int(start_octets[-1])
            end_num = int(end_octets[-1]) + 1  # Add 1 to include the last IP in the range
            ip_addresses = [f"{start_prefix}.{i}" for i in range(start_num, end_num)]
            for object_ip in ip_addresses:
                for obj in self.address_objects:
                    object_ip_range = obj.get('ip-range', None)
                    if object_ip_range and object_ip in object_ip_range:
                        return obj['@name']
            raise ValueError(f"No address object found for IP range: {ip}")
        
        # Handle single IP address
        for obj in self.address_objects:
            object_ip = obj['ip-netmask'].split('/')[0]
            print(f"Checking address object with IP: {object_ip}")
            print(f"Value of ip argument: {ip}")
            if object_ip == ip:
                return obj['@name']
        raise ValueError(f"No address object found for IP: {ip}")

    def match_rule(self, source_ip, destination_ip, user_service):
        found_policy = False
        for rule in self.rules:
            if 'source' in rule and 'member' in rule['source'] and \
               'destination' in rule and 'member' in rule['destination'] and \
               'service' in rule and 'member' in rule['service']:

                source_members = rule['source']['member']
                destination_members = rule['destination']['member']
                service_members = rule['service']['member']

                source_ips = [self.get_ip_from_member(member) for member in source_members]
                destination_ips = [self.get_ip_from_member(member) for member in destination_members]

                if self.is_ip_in_list(source_ip, source_ips) and self.is_ip_in_list(destination_ip, destination_ips):
                    for service_member in service_members:
                        if any(service_member in srv['@name'] for srv in self.service_objects):
                            print(f"Rule '{rule['@name']}' contains source IP '{source_ip}', destination IP '{destination_ip}', and matches service '{user_service}'.")
                            if 'to' in rule and 'member' in rule['to'] and 'from' in rule and 'member' in rule['from']:
                                zones_to = rule['to']['member']
                                zones_from = rule['from']['member']
                                # print(f"Source Zones: {', '.join(zones_from)}")
                                # print(f"Destination Zones: {', '.join(zones_to)}")
                            found_policy = True
                            break
        return found_policy

    def get_ip_from_member(self, member):
        for obj in self.address_objects:
            if '@name' in obj and obj['@name'] == member:
                if 'ip-netmask' in obj:
                    return obj['ip-netmask']
                elif 'ip-range' in obj:
                    return obj['ip-range']
        return ""

    def is_ip_in_list(self, ip, ip_list):
        for ip_item in ip_list:
            if '/' in ip_item:  # Check subnet
                if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(ip_item, strict=False):
                    return True
            elif '-' in ip_item:  # Check range
                start_ip, end_ip = ip_item.split('-')
                if ipaddress.IPv4Address(start_ip) <= ipaddress.IPv4Address(ip) <= ipaddress.IPv4Address(end_ip):
                    return True
            elif ip == ip_item:  # Check single IP
                return True
        return False


    def get_service_key_by_value(self, service_value):
        for service in self.service_objects:
            if 'protocol' in service:
                protocol = service['protocol']
                if 'tcp' in protocol and 'port' in protocol['tcp']:
                    ports = protocol['tcp']['port'].split(',')
                    for port in ports:
                        if '-' in port:
                            start_port, end_port = map(int, port.split('-'))
                            if start_port <= service_value <= end_port:
                                return service['@name']
                        elif int(port) == service_value:
                            return service['@name']
                if 'udp' in protocol and 'port' in protocol['udp']:
                    ports = protocol['udp']['port'].split(',')
                    for port in ports:
                        if '-' in port:
                            start_port, end_port = map(int, port.split('-'))
                            if start_port <= service_value <= end_port:
                                return service['@name']
                        elif int(port) == service_value:
                            return service['@name']
        return None

    def post_security_rule(self, policy_name, source_zone, destination_zone, user_source_ip, user_destination_ip, user_service_value, user_application):
        existing_rule = self.match_rule(user_source_ip, user_destination_ip, user_service_value)

        if existing_rule:
            print(f"Rule with source IP '{user_source_ip}', destination IP '{user_destination_ip}', and matching service value '{user_service_value}' already exists:")
            print(existing_rule)
            return
        source_ip_object = self.find_address_object_name(user_source_ip)
        destination_ip_object = self.find_address_object_name(user_destination_ip)
        # source_ip_object = self.get_address_object_by_ip(user_source_ip)
        # destination_ip_object = self.get_address_object_by_ip(user_destination_ip)

        if source_ip_object is None:
            print(f"No address object found for source IP '{user_source_ip}'.")
            return

        if destination_ip_object is None:
            print(f"No address object found for destination IP '{user_destination_ip}'.")
            return

        service_key = self.get_service_key_by_value(user_service_value)
        if service_key is None:
            print(f"Service object with value '{user_service_value}' not found.")
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

        confirm = input("\nDo you want to post this rule? (yes/no): ").lower()
        if confirm == "yes":
            post_url = f"https://{self.firewall_ip}/restapi/v10.1/Policies/SecurityRules?name={policy_name}&location=vsys&vsys=vsys1"
            response = requests.post(post_url, headers=self.headers, json=rule_data, verify=False)

            if response.status_code == 200:
                print("New rule added successfully.")
            else:
                print(f"Failed to add new rule. Status code: {response.status_code}")
        else:
            print("Rule creation canceled.")

# Example usage
firewall_ip = '10.0.4.253'
api_key = 'Basic cmVzdHVzZXI6QWExMjM0NTY='
policy_name = "new_rule4"
user_source_ip = "10.0.1.1"
user_destination_ip = "8.8.8.8"
user_service_value = 80
user_application = "any"

# policy_name = input("Enter the policy name: ")
# user_source_ip = input("Enter source IP: ")
# user_destination_ip = input("Enter destination IP: ")
# user_service_value = int(input("Enter service port: "))
# user_application = input("Enter the application value for the new rule (enter 'any' if not specified): ")


palo_auto = PaloAuto(firewall_ip, api_key)
source_zone = palo_auto.find_zone_for_ip(user_source_ip)

destination_zone = palo_auto.find_zone_for_ip(user_destination_ip)
if destination_zone or source_zone is None:
    destination_zone = "untrust"
    source_zone = "untrust"
found_policy = palo_auto.match_rule(user_source_ip, user_destination_ip, user_service_value)

if not found_policy:
    palo_auto.post_security_rule(policy_name, source_zone, destination_zone, user_source_ip, user_destination_ip, user_service_value, user_application)
