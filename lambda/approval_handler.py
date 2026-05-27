"""
CMS Security Platform — Phase 2: Approval Handler Lambda
=========================================================
Invoked when analyst clicks Approve / Dismiss / Undo link in Slack.

The link format is:
  https://{api-gateway-url}/action?token={finding_id}&action={quarantine|dismiss|undo}&instance={i-xxx}&original_sgs={sg-xxx,sg-yyy}

Actions:
  quarantine  → move EC2 to quarantine SG (analyst approved containment)
  dismiss     → log as false positive, no action taken
  undo        → restore EC2 to original SG (analyst confirmed false positive after quarantine)

Returns an HTML page so the analyst sees a confirmation in their browser when they click the link.
"""

import json
import os
import boto3
import urllib.request
from datetime import datetime, timezone


# ── Clients ───────────────────────────────────────────────────────────────────

ec2_client = boto3.client("ec2", region_name=os.environ.get("AWS_REGION_NAME", "ap-south-1"))
s3_client  = boto3.client("s3",  region_name=os.environ.get("AWS_REGION_NAME", "ap-south-1"))

SLACK_WEBHOOK_URL = os.environ["SLACK_WEBHOOK_URL"]
QUARANTINE_SG_ID  = os.environ["QUARANTINE_SG_ID"]
AUDIT_BUCKET      = os.environ["AUDIT_BUCKET"]


# ══════════════════════════════════════════════════════════════════════════════
# MAIN HANDLER
# ══════════════════════════════════════════════════════════════════════════════

def lambda_handler(event, context):
    print(f"Approval handler received: {json.dumps(event)}")

    # Parse query parameters from the API Gateway request
    params       = event.get("queryStringParameters") or {}
    token        = params.get("token", "")        # finding_id used as token
    action       = params.get("action", "")       # quarantine | dismiss | undo
    instance_id  = params.get("instance", "")
    original_sgs = params.get("original_sgs", "").split(",") if params.get("original_sgs") else []

    # Remove empty strings from SG list
    original_sgs = [sg for sg in original_sgs if sg]

    if not token or not action:
        return html_response("❌ Invalid request — missing token or action.", 400)

    if action == "quarantine":
        return handle_quarantine(token, instance_id, original_sgs)

    elif action == "dismiss":
        return handle_dismiss(token, instance_id)

    elif action == "undo":
        return handle_undo(token, instance_id, original_sgs)

    else:
        return html_response(f"❌ Unknown action: {action}", 400)


# ══════════════════════════════════════════════════════════════════════════════
# ACTION: QUARANTINE (analyst approved containment)
# Moves EC2 to the quarantine SG. Saves original SGs to audit S3 for undo.
# ══════════════════════════════════════════════════════════════════════════════

def handle_quarantine(finding_id, instance_id, original_sgs):
    if not instance_id:
        return html_response("❌ No instance ID provided.", 400)

    try:
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[QUARANTINE_SG_ID]
        )

        msg = f"✅ EC2 `{instance_id}` quarantined successfully (analyst approved)."
        print(msg)

        # Notify Slack
        post_to_slack({
            "text": (
                f"✅ *Analyst Approved — EC2 Quarantined*\n"
                f"Instance `{instance_id}` moved to quarantine SG.\n"
                f"Original SGs saved for undo: `{original_sgs}`\n"
                f"Finding ID: `{finding_id}`"
            )
        })

        # Write approval to audit log
        write_action_log(finding_id, "QUARANTINE_APPROVED", instance_id, original_sgs)

        return html_response(
            f"✅ EC2 {instance_id} has been quarantined.\n\n"
            f"The instance is now network-isolated. You can investigate it via AWS SSM Session Manager.\n\n"
            f"Original security groups saved: {original_sgs}\n"
            f"If this is a false positive, use the Undo link from the original Slack message.",
            200
        )

    except Exception as e:
        print(f"Quarantine failed for {instance_id}: {e}")
        return html_response(f"❌ Quarantine failed: {str(e)}", 500)


# ══════════════════════════════════════════════════════════════════════════════
# ACTION: DISMISS (analyst assessed as false positive — no action needed)
# ══════════════════════════════════════════════════════════════════════════════

def handle_dismiss(finding_id, instance_id):
    msg = f"ℹ️ Finding {finding_id} dismissed as false positive by analyst."
    print(msg)

    post_to_slack({
        "text": (
            f"ℹ️ *Analyst Dismissed — False Positive*\n"
            f"Finding ID: `{finding_id}` | Instance: `{instance_id}`\n"
            f"No containment action taken. Audit log written."
        )
    })

    write_action_log(finding_id, "DISMISSED_BY_ANALYST", instance_id, [])

    return html_response(
        f"✅ Finding {finding_id} dismissed.\n\nNo action has been taken. This has been logged as a false positive.",
        200
    )


# ══════════════════════════════════════════════════════════════════════════════
# ACTION: UNDO (analyst confirmed false positive after quarantine was executed)
# Restores EC2 to its original security groups.
# ══════════════════════════════════════════════════════════════════════════════

def handle_undo(finding_id, instance_id, original_sgs):
    if not instance_id:
        return html_response("❌ No instance ID provided.", 400)

    if not original_sgs:
        return html_response(
            "❌ No original security groups found to restore. "
            "Please manually reassign the security group in the AWS console.",
            400
        )

    try:
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=original_sgs
        )

        msg = f"✅ EC2 {instance_id} restored to original SGs: {original_sgs}"
        print(msg)

        post_to_slack({
            "text": (
                f"↩️ *Quarantine Undone — False Positive Confirmed*\n"
                f"EC2 `{instance_id}` restored to original security groups: `{original_sgs}`\n"
                f"Finding ID: `{finding_id}`"
            )
        })

        write_action_log(finding_id, "QUARANTINE_UNDONE", instance_id, original_sgs)

        return html_response(
            f"✅ EC2 {instance_id} restored successfully.\n\n"
            f"Security groups restored to: {original_sgs}\n"
            f"The instance is back online.",
            200
        )

    except Exception as e:
        print(f"Undo failed for {instance_id}: {e}")
        return html_response(f"❌ Undo failed: {str(e)}", 500)


# ══════════════════════════════════════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════════════════════════════════════

def write_action_log(finding_id, action, instance_id, original_sgs):
    now = datetime.now(timezone.utc)
    key = f"{now.year}/{now.month:02d}/{now.day:02d}/{finding_id}-approval.json"

    record = {
        "timestamp":   now.isoformat(),
        "finding_id":  finding_id,
        "action":      action,
        "instance_id": instance_id,
        "original_sgs":original_sgs,
        "actor":       "analyst-via-slack-link"
    }

    try:
        s3_client.put_object(
            Bucket=AUDIT_BUCKET,
            Key=key,
            Body=json.dumps(record, indent=2),
            ContentType="application/json"
        )
    except Exception as e:
        print(f"Failed to write action log: {e}")


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


def html_response(message, status_code):
    """Returns an HTML page shown to the analyst when they click the Slack link."""
    emoji = "✅" if status_code == 200 else "❌"
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CMS Security Platform</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 600px; margin: 80px auto; padding: 20px; }}
        .box {{ border: 1px solid #ddd; border-radius: 8px; padding: 30px; background: #f9f9f9; }}
        h2 {{ color: #{'1a7a1a' if status_code == 200 else 'cc0000'}; }}
        pre {{ background: #eee; padding: 10px; border-radius: 4px; white-space: pre-wrap; }}
    </style>
</head>
<body>
    <div class="box">
        <h2>{emoji} CMS Security Platform</h2>
        <pre>{message}</pre>
        <p style="color: #888; font-size: 12px;">You can close this tab.</p>
    </div>
</body>
</html>"""

    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/html"},
        "body": html
    }
