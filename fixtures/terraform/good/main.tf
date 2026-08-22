resource "aws_s3_bucket" "data" {
  bucket = "corp-data"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "db" {
  engine              = "postgres"
  storage_encrypted   = true
  publicly_accessible = false
  password            = var.db_password
}

resource "aws_kms_key" "key" {
  description         = "app key"
  enable_key_rotation = true
}

resource "aws_ebs_volume" "vol" {
  size      = 40
  encrypted = true
}
