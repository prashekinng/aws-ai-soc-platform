# aws-ai-soc-platform
AI-augmented SOC platform on AWS — GuardDuty, Security Hub, Splunk SIEM, and AWS Bedrock-powered alert triage and detection generation via Terraform

# CMS Security Platform — AWS Cloud Security Project

## Project Overview
Cloud Security Engineer role at Virsec Systems securing AWS 
infrastructure for a CMS cybersecurity product across 5 enterprise 
customers.

## Architecture
- 6 VPCs (1 Splunk + 5 customer) in a single AWS account
- One dedicated EC2 per customer running the CMS stack
- Provisioned entirely with Terraform using for_each pattern
- New customer onboarding = add one line to terraform.tfvars

## Security Stack
- GuardDuty → EventBridge → Lambda → Slack (real-time alerting)
- Security Hub with CIS + FSBP benchmarks
- AWS Config with 6 compliance rules
- CloudTrail (multi-region, log validation enabled)
- VPC Flow Logs per customer VPC → Splunk
- KMS encryption on all EBS volumes and S3 buckets
- SSM for EC2 access — no port 22 open on any instance

## SIEM
Splunk ingests 5 data sources:
- aws_guardduty
- aws_securityhub  
- aws_config
- aws_vpcflow
- aws_cloudtrail

## Terraform Structure
| File | Purpose |
|---|---|
| network.tf | 6 VPCs, subnets, IGWs, route tables |
| security_groups.tf | Firewall rules per EC2 |
| iam.tf | All IAM roles, policies, instance profiles |
| kms.tf | KMS key for EBS + S3 encryption |
| compute.tf | Customer EC2s + Elastic IPs |
| splunk.tf | Splunk EC2 + persistent EBS volume |
| s3.tf | CloudTrail + Config log buckets |
| cloudwatch.tf | VPC Flow Log groups per customer |
| security.tf | GuardDuty, Security Hub, Config, CloudTrail, Flow Logs |
| eventbridge.tf | GuardDuty finding routing rules |
| lambda.tf | Slack alerting function |

## Key Design Decisions
- **for_each pattern** — one code block creates all 5 customer VPCs. 
  Adding a new customer = one line in terraform.tfvars
- **No VPC peering** — Splunk pulls from AWS APIs directly, 
  no EC2-to-EC2 communication needed
- **Persistent EBS for Splunk** — prevent_destroy = true means 
  Splunk data survives EC2 termination
- **SSM only** — no port 22 open on any EC2, full audit trail

## Setup
1. Copy terraform.tfvars.example to terraform.tfvars and fill in values
2. Create S3 bucket and DynamoDB table for Terraform state
3. Run terraform init, terraform plan, terraform apply

## Author
Prashanth Bura | Cloud Security Engineer | 2026
