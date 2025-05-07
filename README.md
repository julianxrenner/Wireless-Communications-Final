# Network Intrusion Detection System

This project implements a real-time network intrusion detection system that monitors network traffic and identifies potential malicious activities using machine learning.

## Components

- **PacketSniffer**: Captures network packets in real-time
- **PacketAnalyzer**: Extracts relevant features from network packets
- **DetectionModel**: Machine learning model for identifying malicious traffic
- **AlertSystem**: Sends notifications when malicious activity is detected
- **Replay**: Tool for replaying captured network traffic for testing

## Requirements

- Python 3.7+
- Required packages (see requirements.txt):
  - scapy
  - scikit-learn
  - pandas
  - requests

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Running the Detection System

```bash
python DetectionSystem.py
```

The system will start monitoring network traffic on the loopback interface (lo0) and alert when malicious activity is detected. The user will need ntfy downloaded on their phone to recieve alerts. The topic you want to subscribe to is named "462_final_alerts".

### Replaying Network Traffic

To replay captured network traffic for testing:

```bash
python Replay.py
```

You can either:
- Enter a specific filename to replay a single capture file
- Enter '.' to loop through all files in the edit_pcaps directory

## Features

- Real-time packet capture and analysis
- Machine learning-based intrusion detection
- Automated alert system using ntfy.sh
- Support for TCP and UDP traffic analysis

## Data

The system uses a pre-trained model based on the SSDP dataset for detecting malicious traffic patterns.

## Note

This system requires appropriate permissions to capture network traffic. On some systems, you may need to run it with administrator/root privileges.