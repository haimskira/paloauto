# Firewall Policy Matcher

This script is designed to help you match and analyze security policies on a firewall based on source and destination IPs, as well as services. It uses the provided inputs to fetch security rules, addresses, services, and interface information from a firewall and then matches them against the provided criteria.

## Prerequisites

- Python 3.x
- Required Python libraries (you can install them using `pip`):
  - requests
  - ipaddress

## Getting Started

1. Clone or download this repository to your local machine.
2. Navigate to the repository's directory in your terminal.

## Usage

### Configuration

1. Open the `match_policy.py` file in a text editor.
2. Modify the following user inputs according to your requirements:
   - `user_source_ip`: Source IP address for matching.
   - `user_destination_ip`: Destination IP address for matching.
   - `user_service`: Service (port) for matching.

### Running the Script

1. Open your terminal and navigate to the repository's directory.
2. Run the script using the command:
python match_policy.py


The script will fetch security rules, address objects, service objects, interface information, and zone information from the firewall. It will then match the provided criteria against the retrieved data and print the results.

## API Endpoints

You'll need to provide the appropriate API endpoints in the `endpoints` dictionary of the `match_policy.py` script. These endpoints should correspond to your firewall's configuration.

## Important Notes

- The script provides comments for each function and important block of code. Make sure to read and understand the code before running it.
- This script assumes that you have the necessary permissions and access to the firewall's API.

## License

This project is licensed under the [MIT License](LICENSE).

