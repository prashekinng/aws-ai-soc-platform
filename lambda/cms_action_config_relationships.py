"""
CMS Action: Config Relationships Check
Action group Lambda for cms-blast-radius-agent.
Queries AWS Config to find resources related to the EC2 instance
— identifies downstream dependencies before containment.
"""

import json
import boto3
import os

config_client = boto3.client("config", region_name=os.environ["AWS_REGION_NAME"])
ec2_client    = boto3.client("ec2",    region_name=os.environ["AWS_REGION_NAME"])


def get_config_relationships(instance_id: str) -> dict:
    """
    Query AWS Config for resources related to this EC2 instance.
    Identifies security groups, subnets, VPCs, EBS volumes, ENIs.
    """
    try:
        response = config_client.get_resource_config_history(
            resourceType="AWS::EC2::Instance",
            resourceId=instance_id,
            limit=1
        )

        items = response.get("configurationItems", [])
        if not items:
            return {
                "config_available": False,
                "relationships": [],
                "evidence": ["AWS Config has no history for this instance"]
            }

        item = items[0]
        relationships = item.get("relationships", [])

        # Categorise relationships
        categorised = {
            "security_groups": [],
            "subnets":         [],
            "vpcs":            [],
            "volumes":         [],
            "network_interfaces": []
        }

        for rel in relationships:
            rt = rel.get("resourceType", "")
            rn = rel.get("resourceId",   "")
            if "SecurityGroup" in rt:
                categorised["security_groups"].append(rn)
            elif "Subnet" in rt:
                categorised["subnets"].append(rn)
            elif "VPC" in rt and "Subnet" not in rt:
                categorised["vpcs"].append(rn)
            elif "Volume" in rt:
                categorised["volumes"].append(rn)
            elif "NetworkInterface" in rt:
                categorised["network_interfaces"].append(rn)

        total = len(relationships)
        blast_risk = "HIGH" if total > 5 else "MEDIUM" if total > 2 else "LOW"

        return {
            "config_available":    True,
            "relationships":       categorised,
            "total_relationships": total,
            "blast_risk":          blast_risk,
            "evidence": [
                f"Instance has {total} related AWS resources in Config",
                f"Security groups: {categorised['security_groups']}",
                f"Connected to VPCs: {categorised['vpcs']}",
                f"Network interfaces: {len(categorised['network_interfaces'])}"
            ]
        }

    except config_client.exceptions.ResourceNotDiscoveredException:
        return {
            "config_available": False,
            "relationships":    [],
            "blast_risk":       "UNKNOWN",
            "evidence":         ["Instance not discovered by AWS Config — enable Config recording"]
        }
    except Exception as e:
        print(f"Config query failed: {e}")
        return {
            "config_available": False,
            "relationships":    [],
            "blast_risk":       "UNKNOWN",
            "evidence":         [f"Config query failed: {str(e)}"]
        }


def check_cross_tenant_risk(vpc_id: str) -> dict:
    """
    Check if the instance's VPC has peering connections to other customer VPCs.
    Cross-tenant peering = lateral movement risk if instance is compromised.
    """
    try:
        peering = ec2_client.describe_vpc_peering_connections(
            Filters=[
                {"Name": "requester-vpc-info.vpc-id", "Values": [vpc_id]},
                {"Name": "status-code",               "Values": ["active"]}
            ]
        )
        connections = peering.get("VpcPeeringConnections", [])

        if connections:
            peer_vpcs = [
                c["AccepterVpcInfo"]["VpcId"]
                for c in connections
            ]
            return {
                "cross_tenant_risk":    "HIGH",
                "peered_vpcs":          peer_vpcs,
                "peering_count":        len(connections),
                "evidence":             [
                    f"VPC {vpc_id} has {len(connections)} active peering connections",
                    f"Peered VPCs: {peer_vpcs}",
                    "Compromise could spread to peered customer VPCs"
                ]
            }
        return {
            "cross_tenant_risk": "LOW",
            "peered_vpcs":       [],
            "peering_count":     0,
            "evidence":          [f"VPC {vpc_id} has no active peering connections"]
        }

    except Exception as e:
        print(f"VPC peering check failed: {e}")
        return {
            "cross_tenant_risk": "UNKNOWN",
            "peered_vpcs":       [],
            "evidence":          [f"VPC peering check failed: {str(e)}"]
        }


def lambda_handler(event, context):
    """Bedrock Agent action group handler."""
    print(f"Config relationships check received: {json.dumps(event)}")

    # Extract instance_id from Bedrock Agent function call format
    parameters  = event.get("parameters", [])
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
                                "error":            "instance_id parameter missing",
                                "blast_risk":       "UNKNOWN",
                                "confidence_score": 0.0
                            })
                        }
                    }
                }
            }
        }

    # Step 1 — Get Config relationships
    config_result = get_config_relationships(instance_id)

    # Step 2 — Check cross-tenant VPC peering risk
    vpcs = config_result.get("relationships", {}).get("vpcs", [])
    cross_tenant = {"cross_tenant_risk": "UNKNOWN", "evidence": ["No VPC found"]}
    if vpcs:
        cross_tenant = check_cross_tenant_risk(vpcs[0])

    # Combine evidence and calculate overall confidence
    all_evidence = config_result.get("evidence", []) + cross_tenant.get("evidence", [])

    blast_risk       = config_result.get("blast_risk", "UNKNOWN")
    cross_risk       = cross_tenant.get("cross_tenant_risk", "UNKNOWN")
    confidence_score = 0.85 if config_result.get("config_available") else 0.4

    # Escalate if cross-tenant risk is high
    if cross_risk == "HIGH":
        blast_risk       = "CRITICAL"
        confidence_score = 0.95

    result = {
        "instance_id":          instance_id,
        "blast_risk":           blast_risk,
        "cross_tenant_risk":    cross_risk,
        "total_relationships":  config_result.get("total_relationships", 0),
        "peered_vpcs":          cross_tenant.get("peered_vpcs", []),
        "confidence_score":     confidence_score,
        "evidence":             all_evidence,
        "containment_recommendation": (
            "DEFER_TO_HUMAN — critical cross-tenant blast radius"
            if blast_risk == "CRITICAL"
            else "PROGRESSIVE — multiple resource dependencies"
            if blast_risk == "HIGH"
            else "IMMEDIATE — low blast radius"
            if blast_risk == "LOW"
            else "DEFER_TO_HUMAN — blast radius unknown"
        )
    }

    print(f"Config relationships result: {json.dumps(result)}")

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