# Palo Alto Address Object Resolver

The Palo Alto Address Object Resolver is a Python script designed to update the descriptions of address objects in a Palo Alto firewall configuration with their resolved DNS names. This script uses the firewall's REST API to fetch address objects and updates their descriptions based on their IP addresses.

## Prerequisites

Before using this script, make sure you have the following:

1. Python 3.x installed.
2. A Palo Alto firewall accessible over the network.
3. API key for authentication with the firewall.

## Usage

1. Open the script `address_object_resolver.py` in a text editor.
2. Modify the `firewall_ip` and `api_key` variables to match your firewall's IP address and API key.
3. Run the script using the following command:

python address_object_resolver.py


## Script Details

The script performs the following steps:

1. Fetches address objects from the firewall using the provided API endpoint.
2. Resolves the DNS name for each address object's IP address using the `socket.gethostbyaddr` method.
3. Updates the description of each address object with its resolved DNS name using the firewall's REST API.

## Output

The script provides feedback on the progress and results of the update process. It prints messages indicating whether an address object's description was successfully updated or if an error occurred.

## Disclaimer

This script interacts with a Palo Alto firewall's configuration using its API. Use it responsibly and ensure you have proper authorization to make changes to your firewall's configuration.
