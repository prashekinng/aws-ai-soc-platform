"""
CMS Action: Active Connections Check
Action group Lambda for cms-blast-radius-agent.
Checks VPC flow logs and EC2 network interfaces to identify
active connections before containment — prevents severing
critical production traffic during isolation.
"""

import json
import boto3
import os
from datetime import datetime, timezone, timedelta

ec2_client  = boto3.client("ec2",  region_name=os.environ["AWS_REGION_NAME"])
logs_client = boto3.client("logs", region_name=os.environ["AWS_REGION_NAME"])


def get_network_interfaces(instance_id: str) -> list:
    """Get network interfaces attached to the instance."""
    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response["Reservations"][0]["Instances"][0]
        interfaces = instance.get("NetworkInterfaces", [])
        return [
            {
                "interface_id": iface.get("NetworkInterfaceId"),
                "private_ip":   iface.get("PrivateIpAddress"),
                "subnet_id":    iface.get("SubnetId"),
                "vpc_id":       iface.get("VpcId"),
                "status":       iface.get("Status")
            }
            for iface in interfaces
        ]
    except Exception as e:
        print(f"Failed to get network interfaces: {e}")
        return []


def check_recent_flow_logs(private_ip: str) -> dict:
    """
    Check CloudWatch VPC flow logs for recent traffic.
    Looks for active connections in the last 30 minutes.
    Fail-open: if flow logs unavailable, assume connections exist.
    """
    try:
        log_groups = logs_client.describe_log_groups(
            logGroupNamePrefix="/aws/vpc/flowlogs"
        )
        if not log_groups.get("logGroups"):
            return {
                "flow_logs_available": False,
                "active_connections": "UNKNOWN",
                "confidence_score": 0.4,
                "evidence": ["VPC flow logs not found — assuming active connections exist"]
            }

        log_group_name = log_groups["logGroups"][0]["logGroupName"]
        end_time   = int(datetime.now(timezone.utc).timestamp() * 1000)
        start_time = int((datetime.now(timezone.utc) - timedelta(minutes=30)).timestamp() * 1000)

        response = logs_client.filter_log_events(
            logGroupName=log_group_name,
            startTime=start_time,
            endTime=end_time,
            filterPattern=f'"{private_ip}"',
            limit=20
        )

        events = response.get("events", [])
        if events:
            return {
                "flow_logs_available": True,
                "active_connections": "YES",
                "connection_count": len(events),
                "confidence_score": 0.85,
                "evidence": [
                    f"Found {len(events)} flow log entries for {private_ip} in last 30 minutes",
                    "Instance has active network traffic — immediate isolation may sever connections"
                ]
            }
        else:
            return {
                "flow_logs_available": True,
                "active_connections": "NO",
                "connection_count": 0,
                "confidence_score": 0.8,
                "evidence": [
                    f"No flow log entries for {private_ip} in last 30 minutes",
                    "Instance appears idle — immediate isolation is low risk"
                ]
            }

    except Exception as e:
        print(f"Flow log check failed: {e}")
        return {
            "flow_logs_available": False,
            "active_connections": "UNKNOWN",
            "confidence_score": 0.3,
            "evidence": [f"Flow log check failed: {str(e)} — defaulting to caution"]
        }


def lambda_handler(event, context):
    """Bedrock Agent action group handler."""
    print(f"Active connections check received: {json.dumps(event)}")

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
                "function":    event.get("function"),
                "functionResponse": {
                    "responseBody": {
                        "TEXT": {
                            "body": json.dumps({
                                "error": "instance_id parameter missing",
                                "active_connections": "UNKNOWN",
                                "confidence_score": 0.0
                            })
                        }
                    }
                }
            }
        }

    # Step 1 — Get network interfaces
    interfaces = get_network_interfaces(instance_id)

    if not interfaces:
        result = {
            "instance_id":       instance_id,
            "active_connections": "UNKNOWN",
            "confidence_score":  0.3,
            "evidence":          ["Could not retrieve network interfaces"],
            "containment_recommendation": "DEFER_TO_HUMAN — network state unknown"
        }
    else:
        private_ip = interfaces[0].get("private_ip")
        flow_check = check_recent_flow_logs(private_ip)

        active = flow_check["active_connections"]
        result = {
            "instance_id":        instance_id,
            "private_ip":         private_ip,
            "interfaces":         interfaces,
            "active_connections": active,
            "connection_count":   flow_check.get("connection_count", 0),
            "confidence_score":   flow_check["confidence_score"],
            "evidence":           flow_check["evidence"],
            "containment_recommendation": (
                "PROGRESSIVE — active connections detected, sever carefully"
                if active == "YES"
                else "IMMEDIATE — no active connections, safe to isolate"
                if active == "NO"
                else "DEFER_TO_HUMAN — connection state unknown"
            )
        }

    print(f"Active connections result: {json.dumps(result)}")

    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup"),
            "function":    event.get("function"),
            "functionResponse": {
                "responseBody": {
                    "TEXT": {
                        "body": json.dumps(result)
                    }
                }
            }
        }
    }