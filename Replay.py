from scapy.all import rdpcap, sendp
import os
import platform
import subprocess

# File with malicious packets = output_chunk_00306_20201213135929.pcap


# Function to check device type and select the interfece (currently does not work on Windows)
def get_loopback_interface():
    os_type = platform.system()

    if os_type == "Linux":
        return "lo"
    elif os_type == "Darwin":
        return "lo0"
    elif os_type == "Windows":
        return "Loopback"
    else:
        raise Exception("Unsupported OS")


# Find interface based on device
loopback_iface = get_loopback_interface()

filename = input("Input a filename or enter '.' to loop through all files: ")
path = "./edit_pcaps"

# Either replays a specific file or all files
if filename == ".":
    for item in os.listdir(path)[::]:
        print(item)
        packets = rdpcap(f"./edit_pcaps/{item}")
        sendp(packets, iface=loopback_iface, verbose=True)
else:
    packets = rdpcap(f"./edit_pcaps/{filename}")
    sendp(packets, iface=loopback_iface, verbose=True)
