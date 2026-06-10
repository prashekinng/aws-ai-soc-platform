import boto3, json, urllib.request

ssm = boto3.client("ssm", region_name="ap-south-1")
key = ssm.get_parameter(Name="/cms/virustotal-api-key", WithDecryption=True)["Parameter"]["Value"]

url = "https://www.virustotal.com/api/v3/ip_addresses/185.220.101.1"
req = urllib.request.Request(url, headers={"x-apikey": key})
with urllib.request.urlopen(req) as r:
    data = json.loads(r.read())

stats = data["data"]["attributes"]["last_analysis_stats"]
print(json.dumps(stats, indent=2))
