data "aws_caller_identity" "current" {}

# Create the KMS Key
resource "aws_kms_key" "cms" {
  description             = "My cms encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow CloudTrail to encrypt logs"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name    = "cms-kms-key"
    project = var.project
  }
}

# Add a user-friendly alias
resource "aws_kms_alias" "cms_alias" {
  name          = "alias/cms-key"
  target_key_id = aws_kms_key.cms.key_id
}
