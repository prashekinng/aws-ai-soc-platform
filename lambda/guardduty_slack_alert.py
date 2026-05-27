import json
import os
import urllib.request

def lambda_handler(event, context):
    webhook_url = os.environ['SLACK_WEBHOOK_URL']
    
    # Extract finding details from GuardDuty event
    detail     = event.get('detail', {})
    severity   = detail.get('severity', 0)
    title      = detail.get('title', 'Unknown')
    desc       = detail.get('description', 'No description')
    region     = event.get('region', 'Unknown')
    account_id = event.get('account', 'Unknown')
    
    # Find which customer this belongs to by region/VPC tag
    resources  = detail.get('resources', [{}])
    tags       = resources[0].get('tags', {}) if resources else {}
    customer   = tags.get('Customer', 'Unknown')

    # Build Slack message
    message = {
        "text": f":rotating_light: *GuardDuty Alert*",
        "attachments": [
            {
                "color": "danger",
                "fields": [
                    {"title": "Title",    "value": title,      "short": False},
                    {"title": "Severity", "value": str(severity), "short": True},
                    {"title": "Customer", "value": customer,   "short": True},
                    {"title": "Region",   "value": region,     "short": True},
                    {"title": "Account",  "value": account_id, "short": True},
                    {"title": "Description", "value": desc,    "short": False},
                ]
            }
        ]
    }

    # Send to Slack
    data = json.dumps(message).encode('utf-8')
    req  = urllib.request.Request(
        webhook_url,
        data=data,
        headers={'Content-Type': 'application/json'}
    )
    urllib.request.urlopen(req)
    
    return {"statusCode": 200}