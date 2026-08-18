# A minimal boundary slice that passes every gate in policy/rego/terraform.rego.
#
# This is not a reference architecture. It exists so the CI job proves two things: that the
# policies pass on conforming configuration, and that the failing fixture next door fails for
# the reasons stated rather than because the parser choked.

terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# --------------------------------------------------------------- ingress: KSI-CNA-RNT

resource "aws_security_group" "alb" {
  name        = "northwind-alb"
  description = "Public entry point. Only the two declared public service ports are reachable."
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS from the internet"
    protocol    = "tcp"
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP, redirected to HTTPS at the listener"
    protocol    = "tcp"
    from_port   = 80
    to_port     = 80
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name        = "northwind-app"
  description = "Application tier. Reachable only from the load balancer's own group."
  vpc_id      = var.vpc_id

  ingress {
    description     = "Application traffic from the ALB"
    protocol        = "tcp"
    from_port       = 8443
    to_port         = 8443
    security_groups = [aws_security_group.alb.id]
  }
}

# Administrative access is a private path, not an allow-listed CIDR. SSM Session Manager reaches
# the instance over the AWS API, so no inbound rule is required at all.
resource "aws_security_group" "data" {
  name        = "northwind-data"
  description = "Database tier. Reachable only from the application tier."
  vpc_id      = var.vpc_id

  ingress {
    description     = "PostgreSQL from the application tier"
    protocol        = "tcp"
    from_port       = 5432
    to_port         = 5432
    security_groups = [aws_security_group.app.id]
  }
}

# ------------------------------------------------------- encryption at rest: KSI-SVC-SIN

resource "aws_s3_bucket" "artifacts" {
  bucket = "northwind-artifacts"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      # A customer-managed key, because who holds the key is the distinction a federal customer
      # actually asks about. KSI-SVC-KYM covers the rotation side of the same question.
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_kms_key" "data" {
  description         = "Northwind data encryption key"
  enable_key_rotation = true
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = var.availability_zone
  size              = 20
  encrypted         = true
  kms_key_id        = aws_kms_key.data.arn
}

resource "aws_db_instance" "main" {
  identifier        = "northwind"
  engine            = "postgres"
  instance_class    = "db.t4g.small"
  allocated_storage = 20

  storage_encrypted = true
  kms_key_id        = aws_kms_key.data.arn

  publicly_accessible = false
  deletion_protection = true
}

# ------------------------------------------------------------------ logging: KSI-MLA-*

resource "aws_s3_bucket" "audit_logs" {
  bucket = "northwind-audit-logs"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_cloudtrail" "org" {
  name           = "northwind-org"
  s3_bucket_name = aws_s3_bucket.audit_logs.id

  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.data.arn
}

# ---------------------------------------------------------------------- iam: KSI-IAM-ELP

resource "aws_iam_role" "reader" {
  name = "northwind-artifact-reader"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "reader" {
  name = "read-artifacts"
  role = aws_iam_role.reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:aws:s3:::northwind-artifacts/*"
    }]
  })
}

# Break-glass administrative access exists, but it is bounded by a condition rather than left
# standing. That is what KSI-IAM-JIT asks for, and it is why the wildcard gate checks for the
# absence of a condition rather than the presence of a wildcard.
resource "aws_iam_role_policy" "breakglass" {
  name = "break-glass"
  role = aws_iam_role.reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "*"
      Resource  = "*"
      Condition = { StringEquals = { "aws:PrincipalTag/break-glass" = "true" } }
    }]
  })
}

variable "vpc_id" {
  type = string
}

variable "availability_zone" {
  type    = string
  default = "us-gov-west-1a"
}
