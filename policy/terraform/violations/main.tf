# Deliberately non-compliant configuration. Every resource here trips at least one gate in
# policy/rego/terraform.rego, and the CI job asserts that conftest rejects this directory.
#
# A policy suite that has only ever been run against passing input tells you nothing. This is the
# negative control.

terraform {
  required_version = ">= 1.9"
}

# Trips: all protocols from the internet (KSI-CNA-RNT, KSI-CNA-MAT).
resource "aws_security_group" "everything" {
  name   = "temporary-debug"
  vpc_id = var.vpc_id

  ingress {
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Trips: SSH open to the world.
resource "aws_security_group" "bastion" {
  name   = "bastion"
  vpc_id = var.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Trips: PostgreSQL reachable over IPv6 from anywhere. The IPv6 case is the one most hand-written
# checks miss.
resource "aws_security_group" "database" {
  name   = "database"
  vpc_id = var.vpc_id

  ingress {
    protocol         = "tcp"
    from_port        = 5432
    to_port          = 5432
    ipv6_cidr_blocks = ["::/0"]
  }
}

# Warns: 8080 is open to the internet and is not a declared public service port.
resource "aws_security_group" "app_direct" {
  name   = "app-direct"
  vpc_id = var.vpc_id

  ingress {
    protocol    = "tcp"
    from_port   = 8080
    to_port     = 8080
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Trips: no server-side encryption configuration (KSI-SVC-SIN).
resource "aws_s3_bucket" "uploads" {
  bucket = "northwind-uploads"
}

# Trips: three of four blocks set, which is not a block.
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  block_public_policy     = false
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Trips: unencrypted volume.
resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = false
}

# Trips: unencrypted database storage.
resource "aws_db_instance" "legacy" {
  identifier        = "legacy"
  engine            = "mysql"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_encrypted = false
}

# Trips: log file validation off, so the audit record is not tamper-evident (KSI-MLA-OSM).
# Warns: single region, so activity elsewhere is unlogged (KSI-MLA-LET).
resource "aws_cloudtrail" "partial" {
  name                       = "partial"
  s3_bucket_name             = "northwind-uploads"
  enable_log_file_validation = false
}

# Trips: standing administrative grant with no condition (KSI-IAM-ELP, KSI-IAM-JIT).
resource "aws_iam_role_policy" "admin" {
  name = "admin"
  role = "northwind-ops"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

variable "vpc_id" {
  type    = string
  default = "vpc-000000000000"
}
