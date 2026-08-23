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

resource "google_sql_database_instance" "postgres" {
  name             = "app-db"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = false
      ssl_mode     = "ENCRYPTED_ONLY"
    }
  }
}

resource "google_compute_firewall" "allow_internal" {
  name    = "allow-internal"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["10.0.0.0/24"]
}

resource "google_project_iam_member" "app_sql_client" {
  project = "my-project"
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:app@my-project.iam.gserviceaccount.com"
}

resource "google_service_account" "app" {
  account_id = "app-sa"
}
