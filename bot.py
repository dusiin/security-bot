import os
import requests

SLACK_WEBHOOK = os.environ["SLACK_WEBHOOK_11ST"]

def send_test():

    payload = {
        "text": "🔐 Security bot test message"
    }

    requests.post(SLACK_WEBHOOK, json=payload)

if __name__ == "__main__":
    send_test()
