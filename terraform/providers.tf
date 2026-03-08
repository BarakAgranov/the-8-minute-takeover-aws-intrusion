# =============================================================================
# providers.tf -- Terraform and AWS Provider Configuration
# =============================================================================
# SCENARIO: "The 8-Minute Takeover"
# Based on: Sysdig TRT observation, November 28, 2025
#
# This file configures the Terraform version and the AWS provider.
# We pin provider versions to avoid breaking changes during the lab.
# =============================================================================

terraform {
  # Minimum Terraform version required.
  # We use >= 1.10.0 because it supports all HCL features used in this config.
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source = "hashicorp/aws"
      # Using ~> 5.80 for broad compatibility.
      # AWS provider v6 introduced breaking changes around API Gateway and
      # some S3 resource arguments. This scenario does not use API Gateway,
      # but ~> 5.80 has been tested and verified stable for all resources
      # used here. If you have v6+ installed, change to ">= 6.0".
      version = "~> 5.80"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.7.0"
    }
  }
}

# -----------------------------------------------------------------------------
# AWS Provider
# -----------------------------------------------------------------------------
# The provider uses the default credential chain:
#   1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
#   2. Shared credentials file (~/.aws/credentials)
#   3. IAM instance profile (if running on EC2)
#
# IMPORTANT: Use a DEDICATED LAB ACCOUNT for this scenario.
# Never run attack simulations in a production AWS account.
# -----------------------------------------------------------------------------
provider "aws" {
  region = var.aws_region

  # Default tags applied to every resource created by this configuration.
  # These tags make it easy to identify and clean up lab resources.
  default_tags {
    tags = {
      Project     = "cloud-attack-lab"
      Scenario    = "8-minute-takeover"
      Environment = "lab"
      ManagedBy   = "terraform"
      Warning     = "INTENTIONALLY-VULNERABLE-DO-NOT-USE-IN-PRODUCTION"
    }
  }
}
