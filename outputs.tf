# Customer EC2 instance IDs
output "customer_ec2_ids" {
  description = "Instance IDs of all customer EC2s"
  value       = { for k, v in aws_instance.customer_ec2 : k => v.id }
}

# Customer EC2 public IPs (Elastic IPs)
output "customer_eip_addresses" {
  description = "Elastic IP addresses assigned to customer EC2s"
  value       = { for k, v in aws_eip.customer_eip : k => v.public_ip }
}

# Customer VPC IDs
output "customer_vpc_ids" {
  description = "VPC IDs for all customer VPCs"
  value       = { for k, v in aws_vpc.customer : k => v.id }
}

# Splunk EC2 public IP
output "splunk_public_ip" {
  description = "Elastic IP address of Splunk EC2 - use this to access Splunk UI"
  value       = aws_eip.splunk_eip.public_ip
}

# Splunk UI URL
output "splunk_url" {
  description = "Splunk web UI URL"
  value       = "http://${aws_eip.splunk_eip.public_ip}:8000"
}

# GuardDuty Detector ID
output "guardduty_detector_id" {
  description = "GuardDuty detector ID"
  value       = aws_guardduty_detector.cms.id
}

# CloudTrail ARN
output "cloudtrail_arn" {
  description = "CloudTrail ARN"
  value       = aws_cloudtrail.cms.arn
}

# CloudWatch Log Group names for VPC Flow Logs
output "vpc_flowlog_groups" {
  description = "CloudWatch Log Group names for each customer VPC Flow Logs"
  value       = { for k, v in aws_cloudwatch_log_group.cms : k => v.name }
}

# S3 bucket names
output "s3_bucket_names" {
  description = "S3 bucket names for CloudTrail and Config logs"
  value = {
    cloudtrail = aws_s3_bucket.cloudtrail.bucket
    config     = aws_s3_bucket.config.bucket
  }
}

# KMS Key ARN
output "kms_key_arn" {
  description = "KMS key ARN used for encryption"
  value       = aws_kms_key.cms.arn
}