import json
payload = {
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "Say hello"}]
}
with open("bedrock_payload.json", "w") as f:
    json.dump(payload, f)
print("done")
