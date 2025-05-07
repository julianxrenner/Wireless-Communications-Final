from ssl import AlertDescription
import requests


class AlertSystem:
    def __init__(self):
        pass

    def send_alert(self):
        # Send a POST request to ntfy.sh to trigger an alert
        requests.post(
            "https://ntfy.sh/462_final_alerts",
            data="Potential Intrusion detected. Act right away.",
            headers={
                "Title": "Malicious Packets have been detected on your server",
                "Priority": "urgent",
                "Tags": "warning,skull",
            },
        )


if __name__ == "__main__":
    # Test alert sending
    alert = AlertSystem()
    alert.send_alert()
