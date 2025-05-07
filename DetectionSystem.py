from PacketSniffer import PacketSniffer
from PacketAnalyzer import PacketAnalyzer
from DetectionModel import DetectionModel
from AlertSystem import AlertSystem

class DetectionSystem:
    def __init__(self):
        self.packet_capture = PacketSniffer()
        self.packet_analyzer = PacketAnalyzer()
        self.detection_model = DetectionModel()
        self.alert_system = AlertSystem()

    def run(self):
        print("Starting Detection System on lo0...")
        self.packet_capture.start_capture()

        while True:
            try:
                packet = self.packet_capture.packet_queue.get()
                processed_packet = self.packet_analyzer.analyze_packets(packet)
                prediction = self.detection_model.predict(processed_packet)
                if prediction == "Malicious":
                    self.alert_system.send_alert(True)
            except KeyboardInterrupt:
                print("Stopping Detection System...")
                self.packet_capture.stop_capture()
                break
            except self.packet_capture.packet_queue.empty():
                continue

if __name__ == "__main__":
    detection_system = DetectionSystem()
    detection_system.run()