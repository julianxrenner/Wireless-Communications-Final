# Download NFTY app and subscribe to the topic 462_final_alerts for free intrusion alerts.
import requests


def send_alert(attack):
    if attack == True:
        requests.post(
            "https://ntfy.sh/462_final_alerts",
            data="Potential Intrusion detected. Act right away.",
            headers={
                "Title": "Malicious Packets have been detected on your server",
                "Priority": "urgent",
                "Tags": "warning,skull",
            },
        )
    else:
        print("Normal Network Traffic")


if __name__ == "__main__":
    attack = True
    send_alert(attack)
