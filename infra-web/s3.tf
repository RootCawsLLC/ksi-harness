data "aws_caller_identity" "current" {}

# CodeBuild reads the packaged repo (source.zip) from here.
resource "aws_s3_bucket" "source" {
  bucket        = "${var.project}-source-${data.aws_caller_identity.current.account_id}-${var.aws_region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "source" {
  bucket                  = aws_s3_bucket.source.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
