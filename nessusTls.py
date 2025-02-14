import xml.etree.ElementTree as ET
from typing import Set, Dict
from dataclasses import dataclass
import sys

# ANSI escape codes for colours
GREEN = '\033[32m'
RESET = '\033[0m'

@dataclass
class VulnerabilityInstance:
    ip_address: str
    port: str

    def __hash__(self):
        return hash((self.ip_address, self.port))

    def __eq__(self, other):
        if not isinstance(other, VulnerabilityInstance):
            return False
        return self.ip_address == other.ip_address and self.port == self.port

def get_ssl_plugin_ids() -> Set[str]:
    """Returns a set of Nessus plugin IDs related to SSL/TLS issues."""
    return {
        '15901', '20007', '31705', '35291', '42873', '45411', '51192', 
        '57582', '60108', '60119', '62565', '65821', '69551', '70544', 
        '73404', '78479', '83875', '84089', '90317', '91572', '95715', '104743'
    }

def parse_nessus_file(file_path: str) -> Set[VulnerabilityInstance]:
    """
    Parses a .nessus file and returns a set of unique IP:port combinations 
    affected by SSL/TLS issues.
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        ssl_plugins = get_ssl_plugin_ids()
        vulnerable_instances = set()

        # Parse through all ReportHost elements
        for report_host in root.findall('.//ReportHost'):
            ip_address = report_host.get('name')
            
            # Look for ReportItem elements that match our plugin IDs
            for report_item in report_host.findall('.//ReportItem'):
                plugin_id = report_item.get('pluginID')
                
                if plugin_id in ssl_plugins:
                    port = report_item.get('port')
                    vulnerable_instances.add(VulnerabilityInstance(ip_address, port))

        return vulnerable_instances

    except ET.ParseError as e:
        print(f"Error parsing XML file: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)

def write_output(vulnerable_instances: Set[VulnerabilityInstance], output_file: str):
    """Writes the vulnerable instances to a file in IP:port format."""
    try:
        with open(output_file, 'w') as f:
            for instance in sorted(vulnerable_instances, key=lambda x: (x.ip_address, x.port)):
                f.write(f"{instance.ip_address}:{instance.port}\n")
    except IOError as e:
        print(f"Error writing to output file: {e}", file=sys.stderr)
        sys.exit(1)

def main():
    if len(sys.argv) != 3:
        print("Usage: python script.py <input_nessus_file> <output_file>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]

    # Parse the .nessus file and get unique vulnerable instances
    vulnerable_instances = parse_nessus_file(input_file)
    
    # Write the results to the output file
    write_output(vulnerable_instances, output_file)
    
    print(f"Found {len(vulnerable_instances)} unique vulnerable hosts. Results written to {output_file}")
    print(f"\n{GREEN}Run testssl.sh against the identified hosts using the following command:")
    print(f"testssl.sh -iL {output_file} --parallel --csv --html{RESET}")

if __name__ == "__main__":
    main()
