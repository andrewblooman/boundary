terraform {
  required_version = ">= 1.14"

  backend "s3" {
    bucket         = "corp-terraform-state"
    dynamodb_table = "terraform-locks"
  }
}

provider "aws" {}

provider "google" {}
