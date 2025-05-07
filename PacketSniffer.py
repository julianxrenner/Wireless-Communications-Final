from scapy.all import sniff, IP, TCP, UDP
import threading
import queue


class PacketSniffer:
    def __init__(self):
        # Queue to store captured packets
        self.packet_queue = queue.Queue(maxsize=10000)
        # Event to signal when to stop capturing
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        # Add IP packets to the queue
        if IP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="lo0"):
        # Define thread to run packet sniffer
        def capture_thread():
            sniff(
                iface=interface,
                prn=self.packet_callback,
                store=0,
                # timeout=10,
                stop_filter=lambda _: self.stop_capture.is_set(),
            )

        # Start sniffing in a separate thread
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        # Signal to stop capturing and wait for thread to finish
        self.stop_capture.set()
        self.capture_thread.join()
