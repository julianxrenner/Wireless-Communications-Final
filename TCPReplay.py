import os
import subprocess
from scapy.all import *

# pkts = rdpcap('./pcaps/9.\ SSH.pcap')
# stripped_pkts = [pkt.payload for pkt in pkts]
# wrpcap('stripped_file.pcap', stripped_pkts)\

# Note: I tried using scapy but I think because of the large pcap files it was very very slow so i swithced to the os library and tcpreplay command
# Make sure you install tcpreplay adn wireshark to run this code

interface = "lo0"
file = input("Enter PCAP File Name: ").strip()

if not os.path.isfile(file):
    print(f"Error: {file} not found!")
else:
    os.system(f'''editcap -F libpcap -T ether "{file}" "fixed_{file}"''')
    fixed_file = f"fixed_{file}"
    os.system(f"sudo tcpreplay -i {interface} '{fixed_file}'")
