from PacketSniffer import PacketSniffer
from PacketAnalyzer import PacketAnalyzer
from DetectionModel import DetectionModel
from AlertSystem import AlertSystem


class DetectionSystem:
    def __init__(self):
        # Initialize components
        self.packet_capture = PacketSniffer()
        self.packet_analyzer = PacketAnalyzer()
        self.detection_model = DetectionModel()
        self.alert_system = AlertSystem()

    def run(self):
        print("Starting Detection System on lo0...")
        # Start packet capture
        self.packet_capture.start_capture()

        while True:
            try:
                # Get packet from queue
                packet = self.packet_capture.packet_queue.get()
                # Analyze packet
                processed_packet = self.packet_analyzer.process_packet(packet)
                # Predict using detection model
                prediction = self.detection_model.detect(processed_packet)
                print(prediction)
                # Send alert if malicious
                if prediction == "Malicious":
                    self.alert_system.send_alert()
            except KeyboardInterrupt:
                # Stop system on interrupt
                print("Stopping Detection System...")
                self.packet_capture.stop()
                break
            except self.packet_capture.packet_queue.empty():
                # If queue is empty, continue
                continue


if __name__ == "__main__":
    detection_system = DetectionSystem()
    detection_system.run()
