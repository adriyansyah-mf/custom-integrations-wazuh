import requests
import json
from requests.auth import HTTPBasicAuth
import sys

"""
ossec.conf configuration structure
 <integration>
     <name>custom-n8n</name>
     <hook_url>https://n8n.myserver.com/webhook/XXXXXXXXXXX</hook_url>
     <alert_format>json</alert_format>
 </integration>
"""

# read configuration
alert_file = sys.argv[1]
user = sys.argv[2].split(":")[0]
hook_url = sys.argv[3]

# read alert file
with open(alert_file) as f:
    alert_json = json.loads(f.read())

# extract alert fields
alert_level = alert_json["rule"]["level"]

# agent details
if "agentless" in alert_json:
          agent_ = "agentless"
else:
    agent_ = alert_json["agent"]["name"]

# combine message details
payload = json.dumps({
    "content": [
        {
                    "title": f"Wazuh Alert - Rule {alert_json['rule']['id']}",
                                "description": alert_json["rule"]["description"],
                                "raw_alert": alert_json,
        }
    ]
})

# send alert to n8n webhook
with open ('/tmp/debug.txt', 'a') as f:
     f.write(f"{payload}\n{json.dumps(alert_json, indent=2)}\nUser: {user}\nHook URL: {hook_url}\n")

req = requests.post(hook_url, data=payload, headers={"content-type": "application/json"})
# send alert to n8n webhook
with open ('/tmp/debug.txt', 'a') as f:
    f.write(f"Response: {req.text}\n")
sys.exit(0)
