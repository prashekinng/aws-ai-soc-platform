import boto3
import json

client = boto3.client("bedrock-runtime", region_name="ap-south-1")

payload = {
    "anthropic_version": "bedrock-2023-05-31",
    "max_tokens": 100,
    "messages": [{"role": "user", "content": "Say hello"}]
}

response = client.invoke_model(
    modelId="anthropic.claude-3-haiku-20240307-v1:0",
    body=json.dumps(payload)
)

result = json.loads(response["body"].read())
print(json.dumps(result, indent=2))
