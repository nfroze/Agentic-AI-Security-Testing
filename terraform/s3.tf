# S3 Bucket for storing security test reports
resource "aws_s3_bucket" "reports" {
  bucket = "${var.project_name}-reports-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name = "${var.project_name}-reports"
  }
}

# Versioning enabled for audit trail
resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Server-side encryption (SSE-S3, managed keys)
resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Block all public access (security best practice)
resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Lifecycle policy: transition to cheaper storage classes over time
resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "archive-reports"
    status = "Enabled"

    filter {}


    # Transition to Infrequent Access after 90 days
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    # Transition to Glacier after 365 days
    transition {
      days          = 365
      storage_class = "GLACIER_IR"
    }

    # Delete after 2555 days (7 years, archive retention)
    expiration {
      days = 2555
    }
  }
}

# MFA Delete (optional, requires bucket owner's MFA device to permanently delete)
# Note: This requires console setup; Terraform cannot enable MFA Delete directly on versioned buckets
