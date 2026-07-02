"""
CMS Security Platform — Agent 1: CloudTrail Anomaly Analyser
================================================================
Triggered by the SAME EventBridge rule as the existing ai_triage Lambda —
runs in parallel on every HIGH/CRITICAL GuardDuty/Security Hub finding.

Purpose:
  GuardDuty tells you something looks wrong. This agent answers
  "what did the attacker actually DO?" by reconstructing the attack
  chain from CloudTrail events tied to the same instance/identity.

Flow:
  1. Extract instance ID from the finding
  2. Pull CloudTrail events for that instance, last 2 hours
  3. Filter for high-risk API calls (IAM escalation, data access,
     defense evasion, brute force)
  4. Group filtered events by identity + time window
  5. Send to Bedrock with a ReAct-style prompt → attacker narrative
     + MITRE ATT&CK technique mapping
  6. Return the narrative — consumed by the supervisor Lambda
     (Stage 2) as additional context for the triage verdict

This Lambda does NOT make a block/approve/dismiss decision.
It only produces context. Decision-making stays with the triage agent.

Environment variables:
  BEDROCK_MODEL_ID   — anthropic.claude-3-haiku-20240307-v1:0
  AWS_REGION_NAME     — ap-south-1
  LOOKBACK_MINUTES    — CloudTrail lookback window (default 120 = 2 hours)
"""

import json
import os
import re
import boto3
from datetime import datetime, timezone, timedelta


# ── Clients ──────────────────────────────────────────────────────────────────

cloudtrail_client = boto3.client("cloudtrail",     region_name=os.environ["AWS_REGION_NAME"])
bedrock_client     = boto3.client("bedrock-runtime", region_name=os.environ["AWS_REGION_NAME"])


# ── Constants ─────────────────────────────────────────────────────────────────

BEDROCK_MODEL_ID  = os.environ["BEDROCK_MODEL_ID"]
LOOKBACK_MINUTES  = int(os.environ.get("LOOKBACK_MINUTES", "120"))

# High-risk API calls, grouped by attack-chain stage.
# Derived directly from the SOC mental model:
# Initial Access -> Privilege Escalation -> Persistence ->
# Defense Evasion -> Credential Access -> Exfiltration setup
HIGH_RISK_EVENTS = {
    # Initial Access
    "ConsoleLogin":        "Initial Access (login attempt)",
    # Privilege Escalation
    "AttachRolePolicy":    "Privilege Escalation",
    "AssumeRole":          "Privilege Escalation / Lateral Movement",
    # Persistence
    "CreateUser":          "Persistence (new identity created)",
    # Defense Evasion
    "DisableLogging":      "Defense Evasion (CloudTrail tampering)",
    "StopLogging":         "Defense Evasion (CloudTrail tampering)",
    # Credential Access
    "GetSecretValue":      "Credential Access",
    # Exfiltration setup
    "PutBucketPolicy":     "Exfiltration setup (bucket policy change)",
}


# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — FETCH + FILTER CLOUDTRAIL EVENTS
# ══════════════════════════════════════════════════════════════════════════════

def fetch_cloudtrail_events(instance_id: str) -> list:
    """
    Pull CloudTrail events for the lookback window.
    CloudTrail's lookup_events API lets us filter by ResourceName,
    which catches events where the instance ID appears anywhere
    in the event (as the target OR in the request parameters).
    """
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(minutes=LOOKBACK_MINUTES)

    print(f"Fetching CloudTrail events for {instance_id} "
          f"from {start_time.isoformat()} to {end_time.isoformat()}")

    events = []
    try:
        paginator = cloudtrail_client.get_paginator("lookup_events")
        for page in paginator.paginate(
            LookupAttributes=[
                {"AttributeKey": "ResourceName", "AttributeValue": instance_id}
            ],
            StartTime=start_time,
            EndTime=end_time,
        ):
            events.extend(page.get("Events", []))

    except Exception as e:
        # Fail open here — CloudTrail being unreachable shouldn't
        # block this agent from returning *something* to the supervisor.
        # We return empty list; supervisor proceeds without this context.
        print(f"CloudTrail lookup failed: {e}")
        return []

    print(f"Retrieved {len(events)} total CloudTrail events")
    return events


def filter_high_risk_events(events: list) -> list:
    """
    Keep only events matching our high-risk API call list.
    Each kept event is tagged with its attack-chain stage for
    easier prompt construction and human readability later.
    """
    filtered = []

    for event in events:
        event_name = event.get("EventName", "")

        # ConsoleLogin needs an extra check — we only care about FAILED
        # attempts (brute force signal), not every successful login.
        if event_name == "ConsoleLogin":
            try:
                ct_event = json.loads(event.get("CloudTrailEvent", "{}"))
                login_result = ct_event.get("responseElements", {}).get("ConsoleLogin", "")
                if login_result != "Failure":
                    continue  # skip successful logins, not a risk signal here
            except (json.JSONDecodeError, AttributeError):
                continue

        if event_name in HIGH_RISK_EVENTS:
            filtered.append({
                "event_name": event_name,
                "event_time": event.get("EventTime").isoformat() if event.get("EventTime") else None,
                "username":   event.get("Username", "unknown"),
                "attack_stage": HIGH_RISK_EVENTS[event_name],
            })

    # Sort chronologically — order matters for the attacker narrative
    filtered.sort(key=lambda e: e["event_time"] or "")

    print(f"Filtered to {len(filtered)} high-risk events")
    return filtered


# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — BUILD PROMPT + CALL BEDROCK
# ══════════════════════════════════════════════════════════════════════════════

def call_bedrock_for_narrative(instance_id: str, filtered_events: list) -> dict:
    """
    Sends filtered CloudTrail events to Bedrock.
    Uses system/user prompt split — system prompt sets the agent's role
    and constraints, user prompt contains the actual data for this run.
    Returns a structured narrative with MITRE mapping.
    """

    # No high-risk events found — return early, nothing to analyse
    if not filtered_events:
        return {
            "narrative": "No high-risk CloudTrail events found in the lookback window.",
            "mitre_techniques": [],
            "attack_chain": [],
            "risk_level": "Low",
            "analyst_note": "CloudTrail shows no suspicious API activity for this instance."
        }

    # Format events as a readable list for the prompt
    events_text = "\n".join([
        f"- [{e['event_time']}] {e['event_name']} | Stage: {e['attack_stage']} | User: {e['username']}"
        for e in filtered_events
    ])

    # System prompt — sets the agent's role, constraints, output format
    # This is FIXED — same every invocation
    system_prompt = """You are a cloud security analyst specialising in AWS incident response.
Your job is to analyse CloudTrail API call sequences and reconstruct attacker behaviour.
You must return ONLY valid JSON. No explanation, no preamble, no markdown fences.
Never recommend deleting resources or modifying IAM policies directly."""

    # User prompt — contains the actual data for this specific finding
    # This CHANGES every invocation
    user_prompt = f"""Analyse these CloudTrail events for EC2 instance {instance_id} and reconstruct what happened.

HIGH-RISK CLOUDTRAIL EVENTS (chronological):
{events_text}

Return ONLY this JSON structure:
{{
  "narrative": "2-3 sentence plain English story of what the attacker likely did and why it matters",
  "attack_chain": ["step 1", "step 2", "step 3"],
  "mitre_techniques": ["T-ID: technique name"],
  "risk_level": "Critical | High | Medium | Low",
  "analyst_note": "1 sentence on what a SOC analyst should investigate first"
}}"""

    try:
        response = bedrock_client.invoke_model(
            modelId=BEDROCK_MODEL_ID,
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens":        1000,
                "temperature":       0,
                "system":            system_prompt,
                "messages": [
                    {"role": "user", "content": user_prompt}
                ]
            })
        )

        response_body = json.loads(response["body"].read())
        ai_text = response_body["content"][0]["text"]

        # Strip markdown fences if model ignores formatting instruction
        ai_text_clean = re.sub(r"```json|```", "", ai_text).strip()
        return json.loads(ai_text_clean)

    except json.JSONDecodeError as e:
        print(f"Bedrock returned non-JSON: {ai_text if 'ai_text' in dir() else 'no response'}. Error: {e}")
        return {
            "narrative": "CloudTrail analysis failed — Bedrock response unparseable.",
            "mitre_techniques": [],
            "attack_chain": [],
            "risk_level": "Unknown",
            "analyst_note": "Manual CloudTrail review required."
        }

    except Exception as e:
        print(f"Bedrock call failed: {e}")
        return {
            "narrative": f"CloudTrail analysis failed — {str(e)}",
            "mitre_techniques": [],
            "attack_chain": [],
            "risk_level": "Unknown",
            "analyst_note": "Manual CloudTrail review required."
        }


# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — EXTRACT INSTANCE ID FROM FINDING
# Same logic as existing triage Lambda — handles both GuardDuty + Sec Hub
# ══════════════════════════════════════════════════════════════════════════════

def extract_instance_id(event: dict) -> str | None:
    detail   = event.get("detail", {})
    resource = detail.get("resource", {})

    # GuardDuty format
    instance_id = resource.get("instanceDetails", {}).get("instanceId")
    if instance_id:
        return instance_id

    # Security Hub format — resource ID is an ARN
    findings = detail.get("findings", [])
    if findings:
        resources = findings[0].get("Resources", [])
        if resources:
            resource_id = resources[0].get("Id", "")
            if "instance" in resource_id.lower():
                return resource_id.split("/")[-1]

    return None


# ══════════════════════════════════════════════════════════════════════════════
# MAIN HANDLER
# ══════════════════════════════════════════════════════════════════════════════

def lambda_handler(event, context):
    print(f"CloudTrail Agent received event: {json.dumps(event)}")

    # Step 1 — Extract instance ID from the finding
    instance_id = extract_instance_id(event)

    if not instance_id:
        print("No instance ID found in finding — nothing to analyse")
        return {
            "statusCode": 200,
            "narrative":  "No EC2 instance identified in this finding.",
            "risk_level": "Unknown"
        }

    print(f"Analysing CloudTrail for instance: {instance_id}")

    # Step 2 — Fetch CloudTrail events for this instance
    raw_events = fetch_cloudtrail_events(instance_id)

    # Step 3 — Filter to high-risk events only
    high_risk_events = filter_high_risk_events(raw_events)

    # Step 4 — Call Bedrock to produce attacker narrative
    narrative = call_bedrock_for_narrative(instance_id, high_risk_events)

    print(f"CloudTrail narrative: {json.dumps(narrative)}")

    # Return narrative — in Stage 2 the supervisor Lambda will
    # invoke this agent and use this return value as extra context
    return {
        "statusCode":      200,
        "instance_id":     instance_id,
        "events_found":    len(raw_events),
        "high_risk_count": len(high_risk_events),
        "narrative":       narrative
    }