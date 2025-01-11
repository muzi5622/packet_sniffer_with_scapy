# Packet Sniffer with Scapy

A Python-based packet sniffer designed to capture HTTP requests and extract potential login credentials from network traffic. This project leverages the powerful Scapy library and is compatible with Python 3.

## Features
- Captures HTTP requests from a specified network interface.
- Extracts and displays URLs from the HTTP headers.
- Searches for login credentials in packet payloads using common keywords (e.g., `username`, `password`, `email`).
- Displays found credentials in a readable format.

## Requirements
- Python 3.1 or later
- Scapy library
- Root privileges to capture packets

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/muzi5622/packet_sniffer_with_scapy.git
   cd packet-sniffer```

2. Install required dependencies:
   ```bash
   pip install scapy```

3. Run the script with root privileges:
   ```bash
   sudo python3 packet_sniffer.py ```

## Usage
1. Replace `"eth0"` in the script with the name of your active network interface (e.g., `wlan0`, `en0`, etc.).
2. Run the script as root to start sniffing packets:
   ```bash
   sudo python3 packet_sniffer.py

3. When the script captures HTTP traffic containing potential login credentials, it will display output similar to this:
   ```
   ------------------------------------------------------------
   Login Credential Found!!

   [+] HTTP Request testphp.vulnweb.com/userinfo.php
   uname=asd&pass=asd
   ------------------------------------------------------------
   ```

## Notes
- This program only works with unencrypted HTTP traffic. It cannot capture data from HTTPS due to encryption.
- Ensure you have proper authorization to sniff traffic on the network. Unauthorized sniffing can violate privacy laws and lead to legal consequences.

## Disclaimer
This tool is intended for educational purposes and ethical hacking only. Use it responsibly and only on networks you own or have explicit permission to analyze. The author is not responsible for any misuse of this program.



