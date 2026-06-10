"""
CMS Security Platform — Phase 2: AI Triage Lambda
===================================================
Triggered by EventBridge on every HIGH/CRITICAL GuardDuty or Security Hub finding.

Flow:
  1. Extract IP/instance details from the finding
  2. Enrich: query VirusTotal for IP reputation
  3. Enrich: pull AWS context (customer tag, current SG, instance state)
  4. Call AWS Bedrock (Claude 3 Haiku) with structured triage prompt
  5. Parse AI verdict: AUTO_BLOCK / HUMAN_APPROVE / DISMISS
  6. Route:
       AUTO_BLOCK     → move EC2 to quarantine SG → post AI report to Slack
       HUMAN_APPROVE  → post AI report to Slack with Approve/Dismiss links
       DISMISS        → log to audit S3, post low-priority note to Slack
  7. Write full audit log to S3

Environment variables (set in ai_triage.tf):
  SLACK_WEBHOOK_URL   — Slack incoming webhook
  QUARANTINE_SG_ID    — ID of the zero-rule quarantine security group
  AUDIT_BUCKET        — S3 bucket name for audit logs
  APPROVAL_API_URL    — API Gateway URL for Slack action links
  BEDROCK_MODEL_ID    — anthropic.claude-3-haiku-20240307-v1:0
  AWS_REGION_NAME     — ap-south-1
"""

import json
import os
import re
import uuid
import boto3
import urllib.request
import urllib.parse
from datetime import datetime, timezone


# ── Clients ──────────────────────────────────────────────────────────────────

ec2_client      = boto3.client("ec2",              region_name=os.environ["AWS_REGION_NAME"])
ssm_client      = boto3.client("ssm",              region_name=os.environ["AWS_REGION_NAME"])
bedrock_client  = boto3.client("bedrock-runtime",  region_name=os.environ["AWS_REGION_NAME"])
s3_client       = boto3.client("s3",               region_name=os.environ["AWS_REGION_NAME"])


# ── Constants ─────────────────────────────────────────────────────────────────

SLACK_WEBHOOK_URL  = os.environ["SLACK_WEBHOOK_URL"]
QUARANTINE_SG_IDS  = json.loads(os.environ["QUARANTINE_SG_IDS"])
AUDIT_BUCKET       = os.environ["AUDIT_BUCKET"]
APPROVAL_API_URL   = os.environ["APPROVAL_API_URL"]
BEDROCK_MODEL_ID   = os.environ["BEDROCK_MODEL_ID"]




# ══════════════════════════════════════════════════════════════════════════════
# MAIN HANDLER
# ══════════════════════════════════════════════════════════════════════════════

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")

    finding    = extract_finding(event)
    finding_id = finding.get("id", str(uuid.uuid4()))

    # Filter out low severity findings — only process HIGH (7+) and CRITICAL
    severity = finding.get("severity", 0)
    if isinstance(severity, (int, float)) and severity < 7:
        print(f"Skipping low severity finding ({severity}): {finding_id}")
        return {"statusCode": 200, "body": json.dumps({"finding_id": finding_id, "action": "SKIPPED_LOW_SEVERITY"})}
    if isinstance(severity, str) and severity.upper() not in ["HIGH", "CRITICAL"]:
        print(f"Skipping low severity finding ({severity}): {finding_id}")
        return {"statusCode": 200, "body": json.dumps({"finding_id": finding_id, "action": "SKIPPED_LOW_SEVERITY"})}

    # Step 1 — Extract observables (IP, instance ID)
    observables = extract_observables(finding)
    print(f"Observables: {observables}")

    # Step 2 — Enrich: VirusTotal
    vt_result = enrich_virustotal(observables.get("ip"))

    # Step 3 — Enrich: AWS context
    aws_context = enrich_aws_context(observables.get("instance_id"))

    # Step 4 — Call Bedrock for triage verdict
    verdict = call_bedrock(finding, vt_result, aws_context)
    print(f"AI verdict: {verdict}")

    # Step 5 — Route based on verdict
    action_taken = route_verdict(verdict, observables, aws_context, finding_id)

    # Step 6 — Write audit log
    write_audit_log(finding_id, finding, vt_result, aws_context, verdict, action_taken)

    return {"statusCode": 200, "body": json.dumps({"finding_id": finding_id, "action": action_taken})}

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — EXTRACT FINDING
# Normalises GuardDuty and Security Hub finding formats into one structure.
# ══════════════════════════════════════════════════════════════════════════════

def extract_finding(event):
    detail = event.get("detail", {})

    # GuardDuty format
    if event.get("source") == "aws.guardduty":
        return {
            "id":          detail.get("id", "unknown"),
            "type":        detail.get("type", "unknown"),
            "severity":    detail.get("severity", 0),
            "title":       detail.get("title", ""),
            "description": detail.get("description", ""),
            "region":      event.get("region", "ap-south-1"),
            "account":     event.get("account", ""),
            "service":     detail.get("service", {}),
            "resource":    detail.get("resource", {}),
            "source":      "guardduty"
        }

    # Security Hub format
    if event.get("source") == "aws.securityhub":
        findings = detail.get("findings", [{}])
        f = findings[0] if findings else {}
        return {
            "id":          f.get("Id", "unknown"),
            "type":        f.get("Title", "unknown"),
            "severity":    f.get("Severity", {}).get("Normalized", 0),
            "title":       f.get("Title", ""),
            "description": f.get("Description", ""),
            "region":      event.get("region", "ap-south-1"),
            "account":     event.get("account", ""),
            "service":     {},
            "resource":    f.get("Resources", [{}])[0] if f.get("Resources") else {},
            "source":      "securityhub"
        }

    return detail


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — EXTRACT OBSERVABLES
# Pulls IP address and EC2 instance ID from the finding for enrichment.
# ══════════════════════════════════════════════════════════════════════════════

def extract_observables(finding):
    observables = {"ip": None, "instance_id": None}

    service = finding.get("service", {})
    resource = finding.get("resource", {})

    # Try to find a remote IP (attacker IP)
    action = service.get("action", {})
    for action_type in ["networkConnectionAction", "portProbeAction", "dnsRequestAction"]:
        if action_type in action:
            remote = action[action_type].get("remoteIpDetails", {})
            if remote.get("ipAddressV4"):
                observables["ip"] = remote["ipAddressV4"]
                break

    # Try to find EC2 instance ID
    instance_details = resource.get("instanceDetails", {})
    if instance_details.get("instanceId"):
        observables["instance_id"] = instance_details["instanceId"]

    # Security Hub resource format
    if not observables["instance_id"]:
        resource_id = resource.get("Id", "")
        if "instance" in resource_id.lower():
            # ARN format: arn:aws:ec2:region:account:instance/i-xxxxx
            parts = resource_id.split("/")
            if len(parts) > 1:
                observables["instance_id"] = parts[-1]

    return observables


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — ENRICH: VIRUSTOTAL
# Queries VirusTotal for IP reputation. Returns malicious vendor count and tags.
# Free tier: 4 lookups/minute. Key stored in SSM /cms/virustotal-api-key
# ══════════════════════════════════════════════════════════════════════════════

def enrich_virustotal(ip_address):
    if not ip_address:
        return {"error": "no IP to look up", "malicious_count": 0, "tags": []}

    try:
        # Get API key from SSM
        param = ssm_client.get_parameter(
            Name="/cms/virustotal-api-key",
            WithDecryption=True
        )
        api_key = param["Parameter"]["Value"]

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        req = urllib.request.Request(url, headers={"x-apikey": api_key})

        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read())

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        tags  = data.get("data", {}).get("attributes", {}).get("tags", [])

        return {
            "ip":              ip_address,
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count":stats.get("suspicious", 0),
            "harmless_count":  stats.get("harmless", 0),
            "total_vendors":   sum(stats.values()) if stats else 0,
            "tags":            tags,
            "reputation":      data.get("data", {}).get("attributes", {}).get("reputation", 0)
        }

    except Exception as e:
        print(f"VirusTotal lookup failed for {ip_address}: {e}")
        return {"ip": ip_address, "error": str(e), "malicious_count": 0, "tags": []}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — ENRICH: AWS CONTEXT
# Pulls EC2 instance details to identify the affected customer and current state.
# The Customer tag on each EC2 tells us which of the 5 customers is affected.
# ══════════════════════════════════════════════════════════════════════════════

def enrich_aws_context(instance_id):
    if not instance_id:
        return {"error": "no instance ID", "customer": "unknown", "current_sg_ids": []}

    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        reservations = response.get("Reservations", [])

        if not reservations:
            return {"error": f"instance {instance_id} not found", "customer": "unknown"}

        instance = reservations[0]["Instances"][0]

        # Extract Customer tag — this is how we know which customer is affected
        tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
        customer = tags.get("Customer", tags.get("customer", tags.get("Name", "unknown")))

        # Current security groups (stored for rollback if we quarantine)
        current_sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

        return {
            "instance_id":    instance_id,
            "customer":       customer,
            "instance_state": instance.get("State", {}).get("Name", "unknown"),
            "instance_type":  instance.get("InstanceType", "unknown"),
            "private_ip":     instance.get("PrivateIpAddress", "unknown"),
            "current_sg_ids": current_sg_ids,
            "vpc_id":         instance.get("VpcId", "unknown"),
            "tags":           tags
        }

    except Exception as e:
        print(f"AWS context enrichment failed for {instance_id}: {e}")
        return {"instance_id": instance_id, "error": str(e), "customer": "unknown", "current_sg_ids": []}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — CALL BEDROCK
# Sends the enriched finding to Claude 3 Haiku via AWS Bedrock.
# Temperature = 0 for maximum consistency — same input → same output every time.
# Returns structured JSON verdict.
# ══════════════════════════════════════════════════════════════════════════════

def call_bedrock(finding, vt_result, aws_context):

    prompt = f"""You are a Tier 1 SOC analyst at a cloud security company.
Analyse the following AWS security finding and return a triage verdict.

SECURITY FINDING:
{json.dumps(finding, indent=2)}

VIRUSTOTAL ENRICHMENT (IP reputation check):
{json.dumps(vt_result, indent=2)}

AWS CONTEXT:
Customer affected: {aws_context.get('customer', 'unknown')}
Instance ID: {aws_context.get('instance_id', 'N/A')}
Instance state: {aws_context.get('instance_state', 'unknown')}
Current security groups: {aws_context.get('current_sg_ids', [])}

DECISION RULES:
- AUTO_BLOCK: Use ONLY when VirusTotal malicious_count > 5 AND finding type indicates active compromise (C2 activity, crypto mining, confirmed brute force with successful login). This automatically quarantines the EC2.
- HUMAN_APPROVE: Use for high severity but ambiguous findings (IAM anomalies, unusual API calls, after-hours access, first-seen activity). A human analyst will review before action is taken.
- DISMISS: Use ONLY when clearly a false positive (known automation pattern, low VirusTotal score, historically noisy finding type with no other indicators).

Return ONLY this JSON object. No explanation, no preamble, no markdown:
{{
  "severity": "Critical | High | Medium | Low",
  "verdict": "True Positive | False Positive | Needs Investigation",
  "mitre_technique": "T-ID: technique name",
  "summary": "2-3 sentence plain English summary of what happened and why it matters",
  "recommended_action": "AUTO_BLOCK | HUMAN_APPROVE | DISMISS",
  "reasoning": "1-2 sentences explaining why you chose this action",
  "containment_steps": ["step 1", "step 2", "step 3"],
  "customer_impact": "How this affects the specific customer and their environment",
  "false_positive_likelihood": "Low | Medium | High"
}}"""

    try:
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens":        1000,
                "temperature":       0,       # Must be 0 — deterministic verdicts
                "messages": [
                    {"role": "user", "content": prompt}
                ]
            })
        )

        response_body = json.loads(response["body"].read())
        ai_text = response_body["content"][0]["text"]

        # Parse the JSON response — strip any accidental markdown if present
        ai_text_clean = re.sub(r"```json|```", "", ai_text).strip()
        verdict = json.loads(ai_text_clean)

        return verdict

    except json.JSONDecodeError as e:
        print(f"Bedrock returned non-JSON response: {ai_text}. Error: {e}")
        # Safe fallback — always route to human if AI response is unparseable
        return {
            "severity":              "High",
            "verdict":               "Needs Investigation",
            "mitre_technique":       "Unknown",
            "summary":               "AI triage failed to parse response. Manual review required.",
            "recommended_action":    "HUMAN_APPROVE",
            "reasoning":             "Bedrock response could not be parsed — defaulting to human review.",
            "containment_steps":     ["Review finding manually in GuardDuty console"],
            "customer_impact":       "Unknown — manual investigation required",
            "false_positive_likelihood": "Unknown"
        }

    except Exception as e:
        print(f"Bedrock call failed: {e}")
        return {
            "severity":              "High",
            "verdict":               "Needs Investigation",
            "mitre_technique":       "Unknown",
            "summary":               f"AI triage error: {str(e)}. Manual review required.",
            "recommended_action":    "HUMAN_APPROVE",
            "reasoning":             "Bedrock call failed — defaulting to human review.",
            "containment_steps":     ["Review finding manually in GuardDuty console"],
            "customer_impact":       "Unknown",
            "false_positive_likelihood": "Unknown"
        }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — ROUTE VERDICT
# Routes to AUTO_BLOCK, HUMAN_APPROVE, or DISMISS based on AI verdict.
# ══════════════════════════════════════════════════════════════════════════════

def route_verdict(verdict, observables, aws_context, finding_id):
    action = verdict.get("recommended_action", "HUMAN_APPROVE")

    if action == "AUTO_BLOCK":
        return handle_auto_block(verdict, observables, aws_context, finding_id)

    elif action == "HUMAN_APPROVE":
        return handle_human_approve(verdict, observables, aws_context, finding_id)

    else:  # DISMISS
        return handle_dismiss(verdict, observables, aws_context, finding_id)


def handle_auto_block(verdict, observables, aws_context, finding_id):
    instance_id   = observables.get("instance_id")
    customer      = aws_context.get("customer", "unknown")
    original_sgs  = aws_context.get("current_sg_ids", [])

    if instance_id and original_sgs:
        try:
            # Move EC2 to quarantine SG — this is the containment action
            customer = aws_context.get("customer", "unknown")
            quarantine_sg = QUARANTINE_SG_IDS.get(customer)
            if not quarantine_sg:
                raise Exception(f"No quarantine SG found for customer {customer}")
            ec2_client.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[quarantine_sg]
            )
            action_taken = f"EC2 {instance_id} moved to quarantine SG {quarantine_sg}"
            print(action_taken)

            # Post to Slack with full AI report + confirmation
            message = build_auto_block_slack_message(
                verdict, customer, instance_id, finding_id, original_sgs
            )
            post_to_slack(message)

            return {
                "action":        "AUTO_BLOCK_EXECUTED",
                "instance_id":   instance_id,
                "original_sgs":  original_sgs,
                "quarantine_sg": quarantine_sg
            }

        except Exception as e:
            print(f"Auto-block failed for {instance_id}: {e}")
            # If quarantine fails, fall back to human approval
            verdict["reasoning"] += f" (Note: auto-block failed — {str(e)})"
            return handle_human_approve(verdict, observables, aws_context, finding_id)

    else:
        # No instance to quarantine — notify human
        return handle_human_approve(verdict, observables, aws_context, finding_id)


def handle_human_approve(verdict, observables, aws_context, finding_id):
    customer    = aws_context.get("customer", "unknown")
    instance_id = observables.get("instance_id", "N/A")
    original_sgs = aws_context.get("current_sg_ids", [])

    # Build approval and dismiss URLs
    approve_url = (
        f"{APPROVAL_API_URL}/action"
        f"?token={finding_id}"
        f"&action=quarantine"
        f"&instance={instance_id}"
        f"&original_sgs={','.join(original_sgs)}"
    )
    dismiss_url = (
        f"{APPROVAL_API_URL}/action"
        f"?token={finding_id}"
        f"&action=dismiss"
        f"&instance={instance_id}"
    )

    message = build_human_approve_slack_message(
        verdict, customer, instance_id, finding_id, approve_url, dismiss_url
    )
    post_to_slack(message)

    return {
        "action":      "PENDING_HUMAN_APPROVAL",
        "instance_id": instance_id,
        "finding_id":  finding_id
    }


def handle_dismiss(verdict, observables, aws_context, finding_id):
    customer    = aws_context.get("customer", "unknown")
    instance_id = observables.get("instance_id", "N/A")

    # Post low-priority note to Slack
    message = {
        "text": (
            f"ℹ️ *AI Triage — Dismissed as False Positive*\n"
            f"Customer: *{customer}* | Instance: `{instance_id}`\n"
            f"Finding ID: `{finding_id}`\n"
            f"Reason: {verdict.get('reasoning', 'N/A')}\n"
            f"_Audit log written to S3._"
        )
    }
    post_to_slack(message)

    return {"action": "DISMISSED", "instance_id": instance_id, "finding_id": finding_id}


# ══════════════════════════════════════════════════════════════════════════════
# SLACK MESSAGE BUILDERS
# ══════════════════════════════════════════════════════════════════════════════

def build_auto_block_slack_message(verdict, customer, instance_id, finding_id, original_sgs):
    severity_emoji = {"Critical": "🚨", "High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(verdict.get("severity"), "🔴")

    undo_url = (
        f"{APPROVAL_API_URL}/action"
        f"?token={finding_id}"
        f"&action=undo"
        f"&instance={instance_id}"
        f"&original_sgs={','.join(original_sgs)}"
    )

    steps = "\n".join([f"  {i+1}. {s}" for i, s in enumerate(verdict.get("containment_steps", []))])

    return {
        "text": (
            f"{severity_emoji} *AI TRIAGE — AUTO-BLOCKED*\n\n"
            f"*Customer:* {customer} | *Instance:* `{instance_id}`\n"
            f"*MITRE:* {verdict.get('mitre_technique', 'N/A')}\n"
            f"*Severity:* {verdict.get('severity')} | *Verdict:* {verdict.get('verdict')}\n\n"
            f"*What happened:*\n{verdict.get('summary', 'N/A')}\n\n"
            f"*Customer impact:* {verdict.get('customer_impact', 'N/A')}\n\n"
            f"*AI reasoning:* {verdict.get('reasoning', 'N/A')}\n\n"
            f"*Containment steps taken / recommended:*\n{steps}\n\n"
            f"✅ *EC2 `{instance_id}` has been quarantined automatically.*\n"
            f"If this is a false positive: <{undo_url}|Undo Quarantine>\n"
            f"Finding ID: `{finding_id}`"
        )
    }


def build_human_approve_slack_message(verdict, customer, instance_id, finding_id, approve_url, dismiss_url):
    severity_emoji = {"Critical": "🚨", "High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(verdict.get("severity"), "🔴")
    steps = "\n".join([f"  {i+1}. {s}" for i, s in enumerate(verdict.get("containment_steps", []))])
    fp_likelihood = verdict.get("false_positive_likelihood", "Unknown")

    return {
        "text": (
            f"{severity_emoji} *AI TRIAGE — HUMAN APPROVAL REQUIRED*\n\n"
            f"*Customer:* {customer} | *Instance:* `{instance_id}`\n"
            f"*MITRE:* {verdict.get('mitre_technique', 'N/A')}\n"
            f"*Severity:* {verdict.get('severity')} | *Verdict:* {verdict.get('verdict')}\n"
            f"*False positive likelihood:* {fp_likelihood}\n\n"
            f"*What happened:*\n{verdict.get('summary', 'N/A')}\n\n"
            f"*Customer impact:* {verdict.get('customer_impact', 'N/A')}\n\n"
            f"*AI reasoning:* {verdict.get('reasoning', 'N/A')}\n\n"
            f"*Recommended containment steps:*\n{steps}\n\n"
            f"👉 *Take action:*\n"
            f"  • <{approve_url}|✅ Approve — Quarantine EC2>\n"
            f"  • <{dismiss_url}|❌ Dismiss — False Positive>\n\n"
            f"Finding ID: `{finding_id}`"
        )
    }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — WRITE AUDIT LOG
# Every decision is written to S3 as JSON for compliance and prompt tuning.
# Path: s3://cms-ai-audit-logs-{project}/YYYY/MM/DD/{finding_id}.json
# ══════════════════════════════════════════════════════════════════════════════

def write_audit_log(finding_id, finding, vt_result, aws_context, verdict, action_taken):
    now = datetime.now(timezone.utc)
    key = f"{now.year}/{now.month:02d}/{now.day:02d}/{finding_id}.json"

    audit_record = {
        "timestamp":     now.isoformat(),
        "finding_id":    finding_id,
        "finding":       finding,
        "vt_result":     vt_result,
        "aws_context":   aws_context,
        "ai_verdict":    verdict,
        "action_taken":  action_taken
    }

    try:
        s3_client.put_object(
            Bucket=AUDIT_BUCKET,
            Key=key,
            Body=json.dumps(audit_record, indent=2, default=str),
            ContentType="application/json"
        )
        print(f"Audit log written to s3://{AUDIT_BUCKET}/{key}")

    except Exception as e:
        print(f"Failed to write audit log: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# UTILITY — POST TO SLACK
# ══════════════════════════════════════════════════════════════════════════════

def post_to_slack(message):
    try:
        data = json.dumps(message).encode("utf-8")
        req  = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"Slack response: {resp.status}")

    except Exception as e:
        print(f"Slack post failed: {e}")
