# Create the KMS Key
resource "aws_kms_key" "cms" {
  description             = "My cms encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = {
    Name = "cms-kms-key"
    project = var.project
  }
}

# Add a user-friendly alias
resource "aws_kms_alias" "cms_alias" {
  name          = "alias/cms-key"
  target_key_id = aws_kms_key.cms.key_id
}