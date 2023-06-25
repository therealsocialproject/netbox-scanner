import os
import nmap
import pynetbox
import requests
import socket

# Disable SSL Warnings
requests.packages.urllib3.disable_warnings()

# Disable SSL Verification
os.environ['PYTHONHTTPSVERIFY'] = '0'

# Initiate the port scanner
nm = nmap.PortScanner()

# Scan the subnet for hosts for example 192.168.1.0/24
nm.scan(hosts='192.168.1.0/24', arguments='-sn')

# Get a list of all hosts that are up
hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
for host, status in hosts_list:
    print(f'{host} is {status}')

# Enter your Netbox url and token
netbox = pynetbox.api(url='https://example.com', token='TOKENHERE', ssl_verify=False)

# Add each host to NetBox
for host, status in hosts_list:
    if status == 'up':
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except socket.herror:
            hostname = host  # Use the IP if the hostname couldn't be resolved

        device_data = {
            "name": hostname,
            "device_type": 1,  # device type ID
            "device_role": 1,  # device role ID
            "site": 1,  # site ID
            "status": "active",
            # Add other fields as needed
        }

# Get all the devices from NetBox
all_devices = netbox.dcim.devices.all()

# Create a list of hostnames from the scanned hosts
scanned_hosts = []
for host, status in hosts_list:
    if status == 'up':
        try:
            hostname = socket.gethostbyaddr(host)[0]
        except socket.herror:
            hostname = host  # Use the IP if the hostname couldn't be resolved
        scanned_hosts.append(hostname)

# Check each device in NetBox
for device in all_devices:
    # If the device was not found in the scan results, mark it as offline
    if device.name not in scanned_hosts:
        device.status = 'offline'
        device.save()
        print(f"Marked {device.name} as offline in NetBox.")

        # Remove the IP address of the offline device from NetBox
        try:
            ip_address = netbox.ipam.ip_addresses.get(address=f"{device.name}/24")
            if ip_address:
                ip_address.delete()
                print(f"Deleted IP address {device.name} from NetBox.")
        except Exception as e:
            print(f"Failed to delete IP address {device.name} from NetBox: {e}")
