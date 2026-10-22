# Remote state. Create the bucket (versioned, SSE-KMS, BPA) and lock table by hand
# in the NEW account first (README step 0), then replace the placeholders.
#
# Locking: Terraform >= 1.10 can use `use_lockfile = true` (S3-native lock, no DynamoDB).
# This repo pins >= 1.9, so the DynamoDB table is used; switch when you move to >= 1.10.
terraform {
  backend "s3" {
    bucket         = "REPLACE-mc-terraform-state"
    key            = "mail-console/production/terraform.tfstate"
    region         = "ap-south-1"
    encrypt        = true
    dynamodb_table = "REPLACE-mc-terraform-locks"
  }
}
