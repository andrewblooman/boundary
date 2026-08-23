resource "aws_s3_bucket" "data" {
  bucket = "corp-data"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  engine              = "postgres"
  publicly_accessible = true
  password            = "FAKE-PASSWORD-FOR-TESTS"
}

resource "aws_iam_policy" "admin" {
  name   = "admin"
  policy = "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
}

resource "aws_kms_key" "key" {
  description = "app key"
}

resource "aws_ebs_volume" "vol" {
  size = 40
}

resource "aws_lb_listener" "http" {
  protocol = "HTTP"
  port     = 80

  default_action {
    type = "forward"
  }
}

resource "google_sql_database_instance" "postgres" {
  name             = "app-db"
  database_version = "POSTGRES_15"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ALLOW_UNENCRYPTED_AND_ENCRYPTED"
    }
  }
}

resource "google_compute_firewall" "allow_ssh" {
  name    = "allow-ssh"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]
}

resource "google_project_iam_member" "public_viewer" {
  project = "my-project"
  role    = "roles/viewer"
  member  = "allUsers"
}

resource "google_project_iam_member" "dev_owner" {
  project = "my-project"
  role    = "roles/owner"
  member  = "user:dev@example.com"
}

resource "google_service_account_key" "app_key" {
  service_account_id = "app-sa"
}

resource "aws_subnet" "public" {
  vpc_id                  = "vpc-123"
  cidr_block              = "10.0.1.0/24"
  map_public_ip_on_launch = true
}

resource "aws_instance" "web" {
  ami                         = "ami-123"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}

resource "google_project_iam_member" "service_account_admin" {
  project = "my-project"
  role    = "roles/iam.serviceAccountAdmin"
  member  = "serviceAccount:app@my-project.iam.gserviceaccount.com"
}
