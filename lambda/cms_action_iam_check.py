"""
CMS Action: IAM Check
Action group Lambda for cms-blast-radius-agent.
Checks the IAM role attached to an EC2 instance and evaluates
blast radius of its permissions before containment.
"""

import json
import boto3
import os

ec2_client = boto3.client("ec2", region_name=os.environ["AWS_REGION_NAME"])
iam_client = boto3.client("iam", region_name=os.environ["AWS_REGION_NAME"])


def get_instance_iam_role(instance_id: str) -> dict:
    """Get IAM role attached to the EC2 instance."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        iam_profile = instance.get("IamInstanceProfile", {})
        profile_arn = iam_profile.get("Arn", "")
        if not profile_arn:
            return {"role_name": None, "profile_arn": None}
        # Extract profile name from ARN
        profile_name = profile_arn.split("/")[-1]
        return {"role_name": profile_name, "profile_arn": profile_arn}
    except Exception as e:
        print(f"Failed to get instance IAM profile: {e}")
        return {"role_name": None, "profile_arn": None, "error": str(e)}


def evaluate_role_permissions(role_name: str) -> dict:
    """Check if the role has broad/dangerous permissions."""
    try:
        # Get attached managed policies
        attached = iam_client.list_attached_role_policies(RoleName=role_name)
        policies = attached.get("AttachedPolicies", [])

        # Check for dangerous policies
        dangerous_policies = [
            "AdministratorAccess",
            "PowerUserAccess",
            "IAMFullAccess",
            "AmazonEC2FullAccess",
            "AmazonS3FullAccess"
        ]

        found_dangerous = []
        for policy in policies:
            if policy["PolicyName"] in dangerous_policies:
                found_dangerous.append(policy["PolicyName"])

        blast_radius = "HIGH" if found_dangerous else "MEDIUM"
        if not policies:
            blast_radius = "LOW"

        return {
            "role_name": role_name,
            "attached_policies": [p["PolicyName"] for p in policies],
            "dangerous_policies_found": found_dangerous,
            "blast_radius": blast_radius,
            "confidence_score": 0.9 if found_dangerous else 0.7,
            "evidence": [
                f"Role {role_name} has {len(policies)} attached policies",
                f"Dangerous policies found: {found_dangerous}" if found_dangerous else "No dangerous managed policies found",
            ]
        }
    except Exception as e:
        print(f"Failed to evaluate role permissions: {e}")
        return {
            "role_name": role_name,
            "error": str(e),
            "blast_radius": "UNKNOWN",
            "confidence_score": 0.3,
            "evidence": [f"IAM evaluation failed: {str(e)}"]
        }


def lambda_handler(event, context):
    """
    Bedrock Agent action group handler.
    Bedrock passes parameters differently from EventBridge —
    parameters come in event['parameters'] as a list of dicts.
    """
    print(f"IAM Check received event: {json.dumps(event)}")

    # Extract instance_id from Bedrock Agent function call format
    parameters = event.get("parameters", [])
    instance_id = None
    for param in parameters:
        if param.get("name") == "instance_id":
            instance_id = param.get("value")
            break

    if not instance_id:
        return {
            "messageVersion": "1.0",
            "response": {
                "actionGroup": event.get("actionGroup"),
                "function": event.get("function"),
                "functionResponse": {
                    "responseBody": {
                        "TEXT": {
                            "body": json.dumps({
                                "error": "instance_id parameter missing",
                                "blast_radius": "UNKNOWN",
                                "confidence_score": 0.0
                            })
                        }
                    }
                }
            }
        }

    # Step 1 — Get IAM role attached to instance
    iam_profile = get_instance_iam_role(instance_id)

    if not iam_profile.get("role_name"):
        result = {
            "instance_id": instance_id,
            "iam_role": None,
            "blast_radius": "LOW",
            "confidence_score": 0.8,
            "evidence": ["No IAM role attached to this instance"],
            "containment_recommendation": "IMMEDIATE — no IAM blast radius risk"
        }
    else:
        # Step 2 — Evaluate role permissions
        role_eval = evaluate_role_permissions(iam_profile["role_name"])
        result = {
            "instance_id": instance_id,
            "iam_role": iam_profile["role_name"],
            "blast_radius": role_eval["blast_radius"],
            "confidence_score": role_eval["confidence_score"],
            "evidence": role_eval["evidence"],
            "dangerous_policies": role_eval.get("dangerous_policies_found", []),
            "containment_recommendation": (
                "PROGRESSIVE — revoke IAM sessions first before network isolation"
                if role_eval["blast_radius"] == "HIGH"
                else "IMMEDIATE — IAM blast radius acceptable"
            )
        }

    print(f"IAM check result: {json.dumps(result)}")

    # Return in Bedrock Agent action group response format
    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup"),
            "function": event.get("function"),
            "functionResponse": {
                "responseBody": {
                    "TEXT": {
                        "body": json.dumps(result)
                    }
                }
            }
        }
    }