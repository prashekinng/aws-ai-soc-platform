##GuardDuty
resource "aws_guardduty_detector" "cms" {
  enable = true

  tags = {
    Name = "cms-guardduty"
    project = var.project 
  }
}


##SecurityHub
# 1. define securityhub resource
resource "aws_securityhub_account" "cms" {
}

# 2. Subscribe to a specific standard
resource "aws_securityhub_standards_subscription" "cis" {
  depends_on    = [aws_securityhub_account.cms]
  standards_arn = "arn:aws:securityhub:ap-south-1::standards/cis-aws-foundations-benchmark/v/1.2.0"
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  depends_on    = [aws_securityhub_account.cms]
  standards_arn = "arn:aws:securityhub:ap-south-1::standards/aws-foundational-security-best-practices/v/1.0.0"
}


##config
# 1. create iam role for config - check in iam.tf

# 2. define config recorder
resource "aws_config_configuration_recorder" "config" {
  name     = "config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = true
    include_global_resource_types = true
    }

}

# 3. define config delivery channel (Required to start recording)
resource "aws_config_delivery_channel" "config" {
  name           = "config-deliverychannel"
  s3_bucket_name = aws_s3_bucket.config.id
  depends_on     = [aws_config_configuration_recorder.config]
}

# 4. Manage the Status (Starts/Stops the recorder)
resource "aws_config_configuration_recorder_status" "config" {
  name       = aws_config_configuration_recorder.config.name
  is_enabled = true

  # Recommended to avoid race conditions during creation
  depends_on = [aws_config_delivery_channel.config]
}



##cloudtrail
resource "aws_cloudtrail" "cms" {
  depends_on = [aws_s3_bucket_policy.cloudtrail]

  name                          = "cloudtrail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail = true
  enable_log_file_validation = true
  kms_key_id = aws_kms_key.cms.arn

  tags = {
    Name = "cms-cloudtrail"
    project = var.project 
  }
}



## VPC Flow logs

resource "aws_flow_log" "cms" {
  for_each = var.customers
  iam_role_arn    = aws_iam_role.vpc_flow_logs.arn
  log_destination = aws_cloudwatch_log_group.cms[each.key].arn
  log_destination_type = "cloud-watch-logs"
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.customer[each.key].id

  tags = {
    Name = "cms-vpcflowlogs"
    project = var.project 
  }
}
