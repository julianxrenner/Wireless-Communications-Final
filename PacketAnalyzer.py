from scapy.all import IP, TCP, UDP

class PacketAnalyzer:
    def __init__(self):
        pass

    def process_packet(self, packet):
        features = {
            "frame.len": len(packet),
            "frame.time_epoch": getattr(packet, "time", 0),
            "ip.src": packet[IP].src if IP in packet else "0.0.0.0",
            "ip.dst": packet[IP].dst if IP in packet else "0.0.0.0",
            "ip.proto": packet[IP].proto if IP in packet else 0,
            "ip.ttl": packet[IP].ttl if IP in packet else 0,
            "tcp.srcport": packet[TCP].sport if TCP in packet else 0,
            "tcp.dstport": packet[TCP].dport if TCP in packet else 0,
            "tcp.seq": packet[TCP].seq if TCP in packet else 0,
            "tcp.ack": packet[TCP].ack if TCP in packet else 0,
            "tcp.flags.syn": int(packet[TCP].flags.S) if TCP in packet else 0,
            "udp.srcport": packet[UDP].sport if UDP in packet else 0,
            "udp.dstport": packet[UDP].dport if UDP in packet else 0,
            "udp.length": packet[UDP].len if UDP in packet else 0,
        }

        traffic = [
            features["frame.len"],
            features["frame.time_epoch"],
            features["ip.src"],
            features["ip.dst"],
            features["ip.proto"],
            features["ip.ttl"],
            features["tcp.srcport"],
            features["tcp.dstport"],
            features["tcp.seq"],
            features["tcp.ack"],
            features["tcp.flags.syn"],
            features["udp.srcport"],
            features["udp.dstport"],
            features["udp.length"],
        ]

        for i in [2, 3]:
            try:
                traffic[i] = int("".join([f"{int(x):03d}" for x in traffic[i].split(".")]))
            except:
                traffic[i] = 0

        return traffic