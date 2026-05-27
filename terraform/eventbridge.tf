# Rule 1 — High/Critical findings only → triggers Lambda
resource "aws_cloudwatch_event_rule" "guardduty_high" {
  name        = "cms-guardduty-high-severity"
  description = "Captures GuardDuty findings with severity 7 and above"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [7, 7.5, 8, 8.5, 9, 9.5, 10]
    }
  })

  tags = {
    Name    = "cms-guardduty-high-severity"
    project = var.project
  }
}

# Target for Rule 1 — send to Lambda
resource "aws_cloudwatch_event_target" "guardduty_high_lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_high.name
  target_id = "SendToLambda"
  arn       = aws_lambda_function.guardduty_slack.arn
}

# Rule 2 — All findings → sends to CloudWatch Logs for Splunk
resource "aws_cloudwatch_event_rule" "guardduty_all" {
  name        = "cms-guardduty-all-findings"
  description = "Captures all GuardDuty findings for Splunk ingestion"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })

  tags = {
    Name    = "cms-guardduty-all-findings"
    project = var.project
  }
}

# Target for Rule 2 — send to CloudWatch Log Group
resource "aws_cloudwatch_event_target" "guardduty_all_cloudwatch" {
  rule      = aws_cloudwatch_event_rule.guardduty_all.name
  target_id = "SendToCloudWatch"
  arn       = aws_cloudwatch_log_group.guardduty_events.arn
}

# CloudWatch Log Group for GuardDuty events (Splunk pulls from here)
resource "aws_cloudwatch_log_group" "guardduty_events" {
  name              = "/cms/guardduty/events"
  retention_in_days = 30

  tags = {
    Name    = "cms-guardduty-events"
    project = var.project
  }
}

# Allow EventBridge to write to the CloudWatch Log Group
resource "aws_cloudwatch_log_resource_policy" "eventbridge_guardduty" {
  policy_name = "cms-eventbridge-guardduty-policy"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.guardduty_events.arn}:*"
      }
    ]
  })
}