import json
payload = {
    "source": "aws.guardduty",
    "detail-type": "GuardDuty Finding",
    "detail": {
        "type": "CryptoCurrency:EC2/BitcoinTool.B!DNS",
        "severity": 8,
        "id": "test-autoblk-001",
        "accountId": "247794288672",
        "region": "ap-south-1",
        "service": {
            "action": {
                "networkConnectionAction": {
                    "remoteIpDetails": {
                        "ipAddressV4": "185.220.101.1"
                    }
                }
            }
        },
        "resource": {
            "instanceDetails": {
                "instanceId": "i-09ae5cf4bdcb8be61",
                "tags": [{"key": "Customer", "value": "garda"}]
            }
        }
    }
}
with open("payload.json", "w") as f:
    json.dump(payload, f)
print("done")
