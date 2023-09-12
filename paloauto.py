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
        # dna_gateways = self.get_dna_gateways()
        # if any(ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(gw) for gw in dna_gateways):
        #     return "USERS"
        for interface in self.interfaces:
            if 'layer3' in interface and 'units' in interface['layer3']:
                units = interface['layer3']['units']['entry']
                for unit in units:
                    if 'ip' in unit and 'entry' in unit['ip'] and len(unit['ip']['entry']) > 0:
                        interface_ip = unit['ip']['entry'][0]['@name']
                        if '/' in interface_ip:
                            interface_ip_parts = interface_ip.split('/')  # Split IP and prefix length
                            subnet = ipaddress.IPv4Network(interface_ip_parts[0], strict=False)
                
                            if '-' in ip:
                                ip_range = ip.split('-')
                                start_ip, end_ip = ip_range[0], ip_range[1]
                                start_subnet = ipaddress.IPv4Network(start_ip, strict=False)
                                end_subnet = ipaddress.IPv4Network(end_ip, strict=False)
                                if start_subnet.overlaps(subnet) or end_subnet.overlaps(subnet):
                                    interface_name = unit['@name']
                                    for zone in self.zones:
                                        if 'network' in zone and 'layer3' in zone['network'] and 'member' in zone['network']['layer3']:
                                            if interface_name in zone['network']['layer3']['member']:
                                                return zone['@name']
                            elif '/' in ip:
                                input_subnet = ipaddress.IPv4Network(ip, strict=False)
                                if input_subnet.overlaps(subnet):
                                    interface_name = unit['@name']
                                    for zone in self.zones:
                                        if 'network' in zone and 'layer3' in zone['network'] and 'member' in zone['network']['layer3']:
                                            if interface_name in zone['network']['layer3']['member']:
                                                return zone['@name']
                            else:
                                input_ip = ipaddress.IPv4Address(ip)
                                if input_ip in subnet:
                                    interface_name = unit['@name']
                                    for zone in self.zones:
                                        if 'network' in zone and 'layer3' in zone['network'] and 'member' in zone['network']['layer3']:
                                            if interface_name in zone['network']['layer3']['member']:
                                                return zone['@name']
        return None

    
    # def get_dna_gateways(self):
    #     dna_gateways = []
    #     auth_token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MGVjNGU0ZjRjYTdmOTIyMmM4MmRhNjYiLCJhdXRoU291cmNlIjoiaW50ZXJuYWwiLCJ0ZW5hbnROYW1lIjoiVE5UMCIsInJvbGVzIjpbIjVlOGU4OTZlNGQ0YWRkMDBjYTJiNjQ4ZSJdLCJ0ZW5hbnRJZCI6IjVlOGU4OTZlNGQ0YWRkMDBjYTJiNjQ4NyIsImV4cCI6MTY5MjIwODc2NywiaWF0IjoxNjkyMjA1MTY3LCJqdGkiOiI0NzgyN2YyZS05YzQwLTQ0MGItYjhiNi02YmFlZDc4YjY0ODkiLCJ1c2VybmFtZSI6ImRldm5ldHVzZXIifQ.QWQlScGLSkRzdJvbG5ygk4xYaSLccY6Hw4r7adP1ESFfLJZZzkt335punV5-H3u7LNbkLTYn-HhU4PaFhp3mO0i79__MGosHWDkRGfVv74q22kaGYuU33OAICXHt_RW1EPNlAh68_halN6M4wj8OlYEMq--LPU1ESMHV2et0FT_S2yq6aUODhz9UM9-CxLznza3toeG658I3UWiPgoizPPj3T_2gFGVVPS30loYOzNWE1KMDMi22h-u6bMgXvjIRUU0VolqdvUYNdaQjZ7y3mxuKido0Gog43AvgqrXnBP2Jjifu46EkS8cnXpeWHcs8O9FsHOSjArveRkHSrEFx2Q'
    #     url = 'https://sandboxdnac.cisco.com/dna/intent/api/v1/global-pool'
    #     response = requests.get(url, headers={'X-Auth-Token': auth_token}, verify=False)

    #     if response.status_code == 200:
    #         global_pools = response.json().get('response', [])
    #         for pool in global_pools:
    #             gateways = pool.get('gateways', [])
    #             dna_gateways.extend(gateways)
    #             print(gateways)
    #     else:
    #         print(f"Failed to fetch DNA gateways. Status code: {response.status_code}")

    #     return dna_gateways
    
    def find_address_object_name(self, ip):
        print(f"Searching for address object with IP: {ip}")
    
        if '/' in ip:  # Handle IP address with prefix
            input_ip, prefix = ip.split('/')
            prefix_length = int(prefix)
            input_ip = ipaddress.IPv4Address(input_ip)
            for obj in self.address_objects:
                if 'ip-netmask' in obj:
                    try:
                        object_ip, object_prefix = obj['ip-netmask'].split('/')
                        if input_ip == ipaddress.IPv4Address(object_ip) and prefix_length == int(object_prefix):
                            return obj['@name']
                    except ValueError:
                        pass
            raise ValueError(f"No address object found for IP: {ip}")
    
        if '-' in ip:  # Handle IP address range
            ip_range = ip.split('-')
            start_ip, end_ip = ip_range[0], ip_range[1]
            for obj in self.address_objects:
                if 'ip-range' in obj:
                    try:
                        obj_start_ip, obj_end_ip = obj['ip-range'].split('-')
                        if start_ip == obj_start_ip and end_ip == obj_end_ip:
                            return obj['@name']
                    except ValueError:
                        pass
            raise ValueError(f"No address object found for IP range: {ip}")
    
        # Handle single IP address
        for obj in self.address_objects:
            if 'ip-netmask' in obj:
                try:
                    object_ip = obj['ip-netmask'].split('/')[0]
                    if object_ip == ip:
                        return obj['@name']
                except ValueError:
                    pass
            elif 'ip-range' in obj:
                try:
                    obj_start_ip, obj_end_ip = obj['ip-range'].split('-')
                    if obj_start_ip <= ip <= obj_end_ip:
                        return obj['@name']
                except ValueError:
                    pass
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
            if found_policy:
                break  # Exit the loop if a matching policy is found
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
        if '/' in ip:  # Subnet IP
            ip_network = ipaddress.IPv4Network(ip, strict=False)
            for list_ip in ip_list:
                if '/' in list_ip:
                    list_network = ipaddress.IPv4Network(list_ip, strict=False)
                    if ip_network.overlaps(list_network):
                        return True
        elif '-' in ip:  # IP Range
            ip_range = ip.split('-')
            start_ip, end_ip = ip_range[0], ip_range[1]
            start_ip_obj = ipaddress.IPv4Address(start_ip)
            end_ip_obj = ipaddress.IPv4Address(end_ip)
            for list_ip in ip_list:
                if '-' in list_ip:
                    list_range = list_ip.split('-')
                    list_start_ip, list_end_ip = list_range[0], list_range[1]
                    list_start_ip_obj = ipaddress.IPv4Address(list_start_ip)
                    list_end_ip_obj = ipaddress.IPv4Address(list_end_ip)
                    if start_ip_obj <= list_end_ip_obj and end_ip_obj >= list_start_ip_obj:
                        return True
        else:  # Single IP
            input_ip = ipaddress.IPv4Address(ip)
            for list_ip in ip_list:
                if '/' not in list_ip and '-' not in list_ip:
                    if input_ip == ipaddress.IPv4Address(list_ip):
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
policy_name = "new_ru"
user_source_ip = "10.150.0.0/24"
user_destination_ip = "10.145.76.144/32"
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

if destination_zone is None:
    destination_zone = "untrust"

if source_zone is None:
    source_zone = "untrust"

found_policy = palo_auto.match_rule(user_source_ip, user_destination_ip, user_service_value)

if not found_policy:
    palo_auto.post_security_rule(policy_name, source_zone, destination_zone, user_source_ip, user_destination_ip, user_service_value, user_application)
