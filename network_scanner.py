from scapy.all import ARP, Ether, srp, IP, TCP, sr1
import csv
import os

# This function scans the specified IP range for active devices using ARP requests.
def scan_network(ip_range):
    print(f"Scanning network: {ip_range}...")
    # Create an ARP request packet
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send packet and capture result
    result = srp(packet, timeout=3, verbose=0)[0]
    
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    return clients

# This function scans the specified ports on the given IP address to check if they are open.
def scan_ports(ip, ports):
    open_ports = []
    for port in ports:
        # Build a TCP SYN packet
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        
        # Check if port is open (SYN-ACK flag is 0x12)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports.append(port)
    return open_ports

# This function saves the scan results to a CSV file.
def save_results(data):
    print(f"Saving file to: {os.getcwd()}")
    keys = data[0].keys()
    with open('scan_results.csv', 'w', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(data)
    print("\nResults saved to scan_results.csv.")  

# This function validates the user input for the IP address range.   
import re
def is_valid_ip_range(ip_range):
    pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    if not re.match(pattern, ip_range):
        return False
    # Check each octet is 0-255
    octets = ip_range.split('.')
    return all(0 <= int(o) <= 255 for o in octets)

# This while loop prompts the user for IP addresses and continues scanning until a sentinel value is entered.
SENTINEL_VALUES = {"quit"}

while True:
    ip_range = input("Enter the IP address to scan (e.g., 203.0.113.42) or 'Quit' to quit: ").strip()
    if ip_range.lower() in SENTINEL_VALUES:
        print("Exiting scanner.")
        break

    if not is_valid_ip_range(ip_range):
        print("\nInvalid IP address. Please use IPv4 format (e.g., 203.0.113.42).")
        continue

    results = scan_network(ip_range)

    # Save results when active devices are found.
    if results:
        save_results(results)
    else:
        print("\nNo active devices found for that IP. Try another address.")