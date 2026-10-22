terraform {
  required_version = ">= 1.9.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.region

  # Safety: refuse to run against any account other than the dedicated mail-console account.
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = {
      Project     = "mail-console"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}
