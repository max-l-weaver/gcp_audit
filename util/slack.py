"""
sends notification to slack channel via util.generate.generate_message
"""
import requests
import json

URL = 'https://hooks.slack.com/services/'
USERNAME = 'gcp-audit'
EMOJI = ":female-detective::skin-tone-2"

def notify_alerts_security(msg):
    """post to alerts-security channel"""
    attachments = [{
        "text": msg,
        "color": "#f50110"
        }]

    payload = dict(username=USERNAME,
                   icon_emoji=EMOJI,
                   attachments=attachments)

    data = {'payload': json.dumps(payload)}
    requests.post(URL, data=data)
