import argparse
from netaddr import IPNetwork, IPAddress
import requests
from requests.exceptions import RequestException

def load_ip_lists():
    """Load deny and allow lists from files"""
    denylists = []
    allowlists = []
    cloudproviders = []
    
    # Load denylist
    with open('denylistips.txt', 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                cidr, *comment = line.split('#', 1)
                denylists.append(cidr.strip())

    # Load allowlist
    with open('allowlistips.txt', 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                cidr, *comment = line.split('#', 1)
                allowlists.append(cidr.strip())
                
    # Load cloud providers list
    with open('cloudproviderslist.txt', 'r') as f:
        for line in f:
            if line.strip() and not line.startswith('#'):
                cidr, *comment = line.split('#', 1)
                cloudproviders.append((cidr.strip(), comment[0].strip() if comment else "Unknown Provider"))
                
    return denylists, allowlists, cloudproviders

def validate_ip(ip_addr, denylists, allowlists, cloudproviders):
    """Check if IP is valid (not in denylist and/or in allowlist) and check cloud provider"""
    ip = IPAddress(ip_addr)
    messages = []
    
    # First check if IP is in denylist
    for denied_range in denylists:
        if ip in IPNetwork(denied_range):
            return False, [f"IP {ip_addr} found in denied range {denied_range}"]
            
    # Then check if IP is in allowlist
    for allowed_range in allowlists:
        if ip in IPNetwork(allowed_range):
            messages.append(f"IP {ip_addr} found in allowed range {allowed_range}")
            
    # Check if IP belongs to a cloud provider
    for cidr, provider in cloudproviders:
        if ip in IPNetwork(cidr):
            messages.append(f"IP belongs to cloud provider: {provider}")
            
    if messages:
        return True, messages
            
    # If not in either list, consider it suspicious
    return False, [f"IP {ip_addr} not found in allow list"]

def check_connection(domain, port, protocol='http'):
    try:
        url = f'{protocol}://{domain}{":" + str(port) if port else ""}'
        response = requests.get(url, timeout=5)
        return True, response.status_code
    except RequestException:
        return False, None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip_address', required=True, help='IP Address to Check')
    args = parser.parse_args()

    # Load IP lists
    denylists, allowlists, cloudproviders = load_ip_lists()
    
    try:
        # Validate IP directly
        is_valid, messages = validate_ip(args.ip_address, denylists, allowlists, cloudproviders)
        print(f"\n[*] Checking IP: {args.ip_address}")
        for message in messages:
            print(f"[*] {message}")
        
        if not is_valid:
            print("[!] Warning: IP address is potentially dangerous")
            return
            
    except ValueError as e:
        print(f"[!] Invalid IP address format: {args.ip_address}")
        return

if __name__ == "__main__":
    main()
