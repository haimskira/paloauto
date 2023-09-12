import base64

username = "restuser"
password = "Aa123456"
credentials = f"{username}:{password}"
encoded_credentials = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')

print(encoded_credentials)


import base64

encoded_api_key = 'cmVzdHVzZXI6QWExMjM0NTY='
decoded_bytes = base64.b64decode(encoded_api_key)
decoded_api_key = decoded_bytes.decode('utf-8')

print(decoded_api_key)
