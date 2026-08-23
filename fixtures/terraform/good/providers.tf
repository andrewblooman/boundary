terraform {
  required_version = ">= 1.15, < 2.0"

  backend "gcs" {
    bucket = "corp-terraform-state"
    prefix = "production"
  }
}

provider "aws" {
  default_tags {
    tags = {
      environment = "production"
      managed_by  = "terraform"
    }
  }
}

provider "google" {
  default_labels = {
    environment = "production"
    managed_by  = "terraform"
  }
}
