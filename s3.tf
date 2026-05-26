
## cloudtrail
# 1. Define the S3 Bucket
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "cms-cloudtrail-logs-prashanth" # Must be globally unique

  tags = {
    Name        = "cloudtrail-bucket"
    project = var.project
  }
}

# 2. enable versioning
resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

# 3. encrypt all objects in s3
resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cms.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# 4. block all public access to s3
resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id

  # Block new public ACLs and uploading public objects
  block_public_acls       = true

  # Block new public bucket policies
  block_public_policy     = true

  # Ignore existing public ACLs on the bucket and its objects
  ignore_public_acls      = true

  # Restrict access to only the bucket owner and AWS services
  restrict_public_buckets = true
}

# 5. define policy for s3
resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = [aws_s3_bucket.cloudtrail.arn]
      },

      {
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}


## config
# 1. Define the S3 Bucket
resource "aws_s3_bucket" "config" {
  bucket = "cms-config-logs-prashanth" # Must be globally unique

  tags = {
    Name        = "config-bucket"
    project = var.project
  }
}

# 2. enable versioning
resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

# 3. encrypt all objects in s3
resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.cms.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# 4. block all public access to s3
resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  # Block new public ACLs and uploading public objects
  block_public_acls       = true

  # Block new public bucket policies
  block_public_policy     = true

  # Ignore existing public ACLs on the bucket and its objects
  ignore_public_acls      = true

  # Restrict access to only the bucket owner and AWS services
  restrict_public_buckets = true
}


# 5. define policy for s3
resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = [aws_s3_bucket.config.arn]
      },

      {
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config.arn}/*"
        Condition = { StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" } }
      }
    ]
  })
}

