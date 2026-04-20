# Automated Network & Port Scanner

A professional-grade Python security tool developed in **Visual Studio Code**. This project demonstrates how to use low-level networking libraries to discover active hosts on a local network and audit specific ports for security vulnerabilities.

## Key Features
* **ARP Scanning:** Broadcasts ARP requests to identify live devices via MAC address.
* **TCP Port Discovery:** Performs a SYN scan to detect open services (like SSH, HTTP).
* **Automatic Logging:** Exports all findings into a structured `scan_results.csv` file.
* **Input Protection:** Validates IP addresses using Regex (Regular Expressions) to prevent errors.

## Getting Started
This project requires **Python 3** and the **Scapy** library.

1. **Clone the project**
   ```bash
   git clone [https://github.com/obi-ijeomah/automated-network-scanner.git](https://github.com/obi-ijeomah/automated-network-scanner.git)

2. **Install Scapy**
Run the following command in your terminal: `pip install scapy`

3. **Start the scanner**
Open your terminal (Bash or PowerShell) in the project folder and run the script:
`python network_scanner.py`

## Using The Interface
1. Enter a single IP address (e.g., 203.0.113.42).

2. The script will attempt to find the MAC address and scan for common ports.

3. Type quit to exit and save the final report.

## Project Structure
* automated_network_scanner.py: The main Python script.

* README.md: Documentation and instructions (the file you are reading).

* .gitignore: Prevents temporary cache files and your private scan results from being uploaded.

* scan_results.csv (Generated after scan): Contains the final report.

## How It Works
The scanner uses a TCP Three-Way Handshake logic for port scanning. It sends a SYN packet; if the target responds with SYN-ACK, the port is considered open.

## Disclaimer
This tool is for educational purposes only. Unauthorized scanning of networks is illegal. Always obtain explicit permission before running this tool against any network.