# IAM role for Lambda
resource "aws_iam_role" "lambda" {
  name = "cms-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name    = "cms-lambda-role"
    project = var.project
  }
}

# Attach basic Lambda execution policy
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Inline policy to allow Lambda to read GuardDuty findings
resource "aws_iam_role_policy" "lambda_guardduty" {
  name = "cms-lambda-guardduty-policy"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "guardduty:GetFindings",
          "guardduty:ListFindings"
        ]
        Resource = "*"
      }
    ]
  })
}

# Zip the Lambda source code
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/guardduty_slack_alert.py"
  output_path = "${path.module}/../lambda/guardduty_slack_alert.zip"
}

# Lambda function
resource "aws_lambda_function" "guardduty_slack" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "cms-guardduty-slack-alert"
  role             = aws_iam_role.lambda.arn
  handler          = "guardduty_slack_alert.lambda_handler"
  runtime          = "python3.12"
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }

  tags = {
    Name    = "cms-guardduty-slack-alert"
    project = var.project
  }
}

# Allow EventBridge to invoke the Lambda function
resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty_slack.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_high.arn
}