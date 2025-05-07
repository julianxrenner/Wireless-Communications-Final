from scapy.all import rdpcap, sendp
import os


filename = input("Input a filename or enter '.' to loop through all files: ")
path = "./edit_pcaps"

if filename == '.':
    for item in os.listdir(path)[500::]:
        print(item)
        packets = rdpcap(f"./edit_pcaps/{item}")
        sendp(packets, iface="lo0", verbose=True)
else:
    packets = rdpcap(f"./edit_pcaps/{filename}")
    sendp(packets, iface="lo0", verbose=True)