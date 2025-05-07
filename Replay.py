from scapy.all import rdpcap, sendp

packets = rdpcap("test.pcap")
sendp(packets, iface="lo0", verbose=True)