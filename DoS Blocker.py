import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, get_if_list
import ctypes

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")
print(get_if_list())

def packet_callback(packet):
    global packet_count, start_time, blocked_ips
    if IP in packet:
        src_ip = packet[IP].src
        packet_count[src_ip] += 1
        current_time = time.time()
        time_interval = current_time - start_time[0]

        if time_interval >= 1:
            for ip, count in packet_count.items():
                packet_rate = count / time_interval
                if packet_rate > THRESHOLD and ip not in blocked_ips:
                    print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                    if os.name == 'nt':
                        os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
                    else:
                        os.system(f"iptables -A INPUT -s {ip} -j DROP")
                    blocked_ips.add(ip)

            packet_count.clear()
            start_time[0] = current_time

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if __name__ == "__main__":
    if os.name == 'nt':
        if not is_admin():
            print("This script must be run as Administrator.")
            sys.exit(1)
    else:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            print("This script must be run as root.")
            sys.exit(1)

    from scapy.all import get_if_list
    print("Available interfaces:", get_if_list())
    # Set your interface name here if needed, e.g., iface="Ethernet"
    iface_name = None  # or "Ethernet", "Wi-Fi", etc.

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()
    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback, iface=iface_name)