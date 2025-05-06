from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue


class CapturePackets:  # Class to capture packets from teh TCP replay.
    """Captures IP/TCP packets from specified interface using Scapy and queues them for processing."""

    def __init__(self):
        self.packet_queue = queue.Queue(
            maxsize=10000
        )  # Queue to hold packets as captured.
        self.stop_capture = threading.Event()  # Tell capture when to stop.

    def packet_callback(self, packet):  # Only queue packets in TCP or IP.
        # if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(
        self, interface="lo0"
    ):  # Start capturing on the same interfact as the TCPReplay script.
        def capture_thread():  # Start sniffing packets.
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                timeout=30,
                stop_filter=lambda _: self.stop_capture.is_set(),
            )

        self.capture_thread = threading.Thread(
            target=capture_thread
        )  # Sniff packets on a new thread.
        self.capture_thread.start()  # Starts the thread.

    def stop(self):  # Stop capturing.
        self.stop_capture.set()  # Stops the sniffer thread.
        self.capture_thread.join()  # Waits for the thread to stop before continuing.

    def process_packets(self):  # Process captured packets.
        count = 0
        while not self.packet_queue.empty():
            pkt = self.packet_queue.get()
            print(pkt.summary())
            count += 1
        print(f"Captured {count} packets.")


# Test the file directly..
if __name__ == "__main__":
    sniffer = CapturePackets()
    sniffer.start_capture(interface="lo0")
    sniffer.capture_thread.join()  # waits for the capture to finish
    sniffer.process_packets()  # process and print captured packets
    print(f"Captured {sniffer.packet_queue.qsize()} packets.")
