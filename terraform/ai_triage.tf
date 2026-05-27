# =============================================================================
# CMS Security Platform — Phase 2: AI Triage Layer
# All new resources for the AI-augmented alert triage system.
# Existing files (lambda.tf, iam.tf, security_groups.tf) are NOT modified.
# =============================================================================


# -----------------------------------------------------------------------------
# 1. QUARANTINE SECURITY GROUP
# An EC2 moved into this SG has zero inbound and zero outbound rules.
# It is fully network-isolated but still running — preserves forensic evidence.
# SSM Session Manager still works (uses AWS control plane, not data plane).
# -----------------------------------------------------------------------------

resource "aws_security_group" "quarantine" {
  name        = "cms-quarantine-sg"
  description = "Zero-rule quarantine SG. EC2s moved here are fully network-isolated for containment."
  vpc_id      = aws_vpc.splunk.id  # Placed in security VPC — not customer VPCs

  # No ingress rules  — all inbound traffic blocked
  # No egress rules   — all outbound traffic blocked

  tags = {
    Name    = "cms-quarantine-sg"
    project = var.project
    Purpose = "incident-containment"
  }
}


# -----------------------------------------------------------------------------
# 2. AUDIT S3 BUCKET
# Every AI decision is logged here as JSON:
#   - original finding + enrichment data + full Bedrock prompt
#   - full Bedrock response + recommended action + action taken + timestamp
# Used for: compliance, false positive review, prompt tuning over time.
# -----------------------------------------------------------------------------

resource "aws_s3_bucket" "ai_audit" {
  bucket        = "cms-ai-audit-logs-${var.project}"
  force_destroy = false  # Never accidentally delete audit logs

  tags = {
    Name    = "cms-ai-audit-logs"
    project = var.project
    Purpose = "ai-triage-audit-trail"
  }
}

resource "aws_s3_bucket_versioning" "ai_audit" {
  bucket = aws_s3_bucket.ai_audit.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "ai_audit" {
  bucket                  = aws_s3_bucket.ai_audit.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "ai_audit" {
  bucket = aws_s3_bucket.ai_audit.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}


# -----------------------------------------------------------------------------
# 3. SSM PARAMETER — VirusTotal API Key
# Lambda reads this at runtime. Never hardcoded in code or environment variables.
# Get a free key at: https://www.virustotal.com (register → API key in profile)
# Deploy with: aws ssm put-parameter \
#   --name /cms/virustotal-api-key \
#   --value "YOUR_KEY_HERE" \
#   --type SecureString \
#   --region ap-south-1
# This resource just documents it exists — actual value set via CLI above.
# -----------------------------------------------------------------------------

resource "aws_ssm_parameter" "virustotal_key" {
  name        = "/cms/virustotal-api-key"
  description = "VirusTotal API key for IP/hash enrichment in AI triage Lambda"
  type        = "SecureString"
  value       = "PLACEHOLDER_SET_VIA_CLI"  # Replace via: aws ssm put-parameter ...

  lifecycle {
    ignore_changes = [value]  # Don't overwrite real key on terraform apply
  }

  tags = {
    Name    = "cms-virustotal-api-key"
    project = var.project
  }
}


# -----------------------------------------------------------------------------
# 4. EVENTBRIDGE RULE — routes HIGH/CRITICAL findings to AI triage Lambda
# This sits alongside the existing guardduty_high rule in eventbridge.tf.
# Catches both GuardDuty AND Security Hub HIGH/CRITICAL findings.
# The existing Slack alert Lambda still fires separately — both run in parallel.
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "ai_triage" {
  name        = "cms-ai-triage-rule"
  description = "Routes HIGH/CRITICAL GuardDuty and Security Hub findings to AI triage Lambda"

  event_pattern = jsonencode({
    source      = ["aws.guardduty", "aws.securityhub"]
    detail-type = ["GuardDuty Finding", "Security Hub Findings - Imported"]
    detail = {
      severity = [{ numeric = [">=", 7] }]
    }
  })

  tags = {
    Name    = "cms-ai-triage-rule"
    project = var.project
  }
}

resource "aws_cloudwatch_event_target" "ai_triage" {
  rule = aws_cloudwatch_event_rule.ai_triage.name
  arn  = aws_lambda_function.ai_triage.arn
}

resource "aws_lambda_permission" "ai_triage_eventbridge" {
  statement_id  = "AllowEventBridgeInvokeAITriage"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ai_triage.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ai_triage.arn
}


# -----------------------------------------------------------------------------
# 5. API GATEWAY — receives analyst Approve / Dismiss / Undo clicks from Slack
# Slack message contains links like:
#   https://{api-id}.execute-api.ap-south-1.amazonaws.com/approve?token=xxx&instance=i-xxx&action=quarantine
# API Gateway receives the click and invokes the approval_handler Lambda.
# -----------------------------------------------------------------------------

resource "aws_apigatewayv2_api" "approval" {
  name          = "cms-approval-api"
  protocol_type = "HTTP"
  description   = "Receives analyst approval/dismiss/undo actions from Slack links"

  tags = {
    Name    = "cms-approval-api"
    project = var.project
  }
}

resource "aws_apigatewayv2_stage" "approval" {
  api_id      = aws_apigatewayv2_api.approval.id
  name        = "$default"
  auto_deploy = true
}

resource "aws_apigatewayv2_integration" "approval" {
  api_id             = aws_apigatewayv2_api.approval.id
  integration_type   = "AWS_PROXY"
  integration_uri    = aws_lambda_function.approval_handler.invoke_arn
  integration_method = "POST"
}

resource "aws_apigatewayv2_route" "approve" {
  api_id    = aws_apigatewayv2_api.approval.id
  route_key = "GET /action"
  target    = "integrations/${aws_apigatewayv2_integration.approval.id}"
}

resource "aws_lambda_permission" "approval_api_gateway" {
  statement_id  = "AllowAPIGatewayInvokeApproval"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.approval_handler.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.approval.execution_arn}/*/*"
}


# -----------------------------------------------------------------------------
# 6. LAMBDA — AI TRIAGE FUNCTION
# Triggered by EventBridge on HIGH/CRITICAL findings.
# Flow: enrich with VirusTotal + AWS context → call Bedrock → route to
#       AUTO_BLOCK / HUMAN_APPROVE / DISMISS → log to audit S3.
# -----------------------------------------------------------------------------

data "archive_file" "ai_triage_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/ai_triage_function.py"
  output_path = "${path.module}/../lambdas/ai_triage_function.zip"
}

resource "aws_lambda_function" "ai_triage" {
  filename         = data.archive_file.ai_triage_zip.output_path
  function_name    = "cms-ai-triage"
  role             = aws_iam_role.ai_triage_lambda.arn
  handler          = "ai_triage_function.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.ai_triage_zip.output_base64sha256
  timeout          = 60  # Bedrock + VirusTotal calls need more than default 3s

  environment {
    variables = {
      SLACK_WEBHOOK_URL    = var.slack_webhook_url
      QUARANTINE_SG_ID     = aws_security_group.quarantine.id
      AUDIT_BUCKET         = aws_s3_bucket.ai_audit.bucket
      APPROVAL_API_URL     = aws_apigatewayv2_api.approval.api_endpoint
      BEDROCK_MODEL_ID     = "anthropic.claude-3-haiku-20240307-v1:0"
      AWS_REGION_NAME      = var.region
    }
  }

  tags = {
    Name    = "cms-ai-triage"
    project = var.project
  }
}


# -----------------------------------------------------------------------------
# 7. LAMBDA — APPROVAL HANDLER
# Invoked when analyst clicks Approve / Dismiss / Undo link in Slack.
# Reads action from query params, validates one-time token, executes or reverses
# containment, logs result to audit S3.
# -----------------------------------------------------------------------------

data "archive_file" "approval_handler_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambdas/approval_handler.py"
  output_path = "${path.module}/../lambdas/approval_handler.zip"
}

resource "aws_lambda_function" "approval_handler" {
  filename         = data.archive_file.approval_handler_zip.output_path
  function_name    = "cms-approval-handler"
  role             = aws_iam_role.ai_triage_lambda.arn  # Reuses same role
  handler          = "approval_handler.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.approval_handler_zip.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      QUARANTINE_SG_ID  = aws_security_group.quarantine.id
      AUDIT_BUCKET      = aws_s3_bucket.ai_audit.bucket
    }
  }

  tags = {
    Name    = "cms-approval-handler"
    project = var.project
  }
}


# -----------------------------------------------------------------------------
# 8. OUTPUTS — useful values after terraform apply
# -----------------------------------------------------------------------------

output "quarantine_sg_id" {
  description = "Security group ID for EC2 containment"
  value       = aws_security_group.quarantine.id
}

output "ai_audit_bucket" {
  description = "S3 bucket for AI triage audit logs"
  value       = aws_s3_bucket.ai_audit.bucket
}

output "approval_api_url" {
  description = "API Gateway URL for Slack approval links"
  value       = aws_apigatewayv2_api.approval.api_endpoint
}

output "ai_triage_lambda_arn" {
  description = "ARN of the AI triage Lambda function"
  value       = aws_lambda_function.ai_triage.arn
}
