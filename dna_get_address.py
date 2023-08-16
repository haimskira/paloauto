import requests

class DnaCenter:
    def __init__(self, base_url, auth_token):
        self.base_url = base_url
        self.headers = {'x-auth-token': auth_token}
        self.endpoints = {
            'global_pool': f'{base_url}/dna/intent/api/v1/global-pool'
        }

    def get_global_pool(self):
        response = requests.get(self.endpoints['global_pool'], headers=self.headers, verify=False)
        if response.status_code == 200:
            data = response.json()
            if 'response' in data:
                return [pool['gateways'] for pool in data['response']]
            else:
                print("No 'response' key found in the JSON.")
        else:
            print(f"Failed to fetch global pool. Status code: {response.status_code}")
        return []

# Example usage

base_url = 'https://sandboxdnac.cisco.com'
auth_token = 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI2MGVjNGU0ZjRjYTdmOTIyMmM4MmRhNjYiLCJhdXRoU291cmNlIjoiaW50ZXJuYWwiLCJ0ZW5hbnROYW1lIjoiVE5UMCIsInJvbGVzIjpbIjVlOGU4OTZlNGQ0YWRkMDBjYTJiNjQ4ZSJdLCJ0ZW5hbnRJZCI6IjVlOGU4OTZlNGQ0YWRkMDBjYTJiNjQ4NyIsImV4cCI6MTY5MjIwODc2NywiaWF0IjoxNjkyMjA1MTY3LCJqdGkiOiI0NzgyN2YyZS05YzQwLTQ0MGItYjhiNi02YmFlZDc4YjY0ODkiLCJ1c2VybmFtZSI6ImRldm5ldHVzZXIifQ.QWQlScGLSkRzdJvbG5ygk4xYaSLccY6Hw4r7adP1ESFfLJZZzkt335punV5-H3u7LNbkLTYn-HhU4PaFhp3mO0i79__MGosHWDkRGfVv74q22kaGYuU33OAICXHt_RW1EPNlAh68_halN6M4wj8OlYEMq--LPU1ESMHV2et0FT_S2yq6aUODhz9UM9-CxLznza3toeG658I3UWiPgoizPPj3T_2gFGVVPS30loYOzNWE1KMDMi22h-u6bMgXvjIRUU0VolqdvUYNdaQjZ7y3mxuKido0Gog43AvgqrXnBP2Jjifu46EkS8cnXpeWHcs8O9FsHOSjArveRkHSrEFx2Q'
dna_center = DnaCenter(base_url, auth_token)
global_pool = dna_center.get_global_pool()
print(global_pool)