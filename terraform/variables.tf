# =============================================================================
# variables.tf -- Input Variables
# =============================================================================
# All configurable parameters for the scenario.
# Copy terraform.tfvars.example to terraform.tfvars and fill in your values.
# =============================================================================

variable "aws_region" {
  description = "AWS region to deploy the lab infrastructure in. Choose a region where you have Bedrock model access enabled."
  type        = string
  default     = "us-east-1"
}

variable "project_prefix" {
  description = "Prefix for all resource names. Use your initials or a short identifier to avoid S3 bucket name collisions."
  type        = string
  default     = "acme-ai"

  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.project_prefix))
    error_message = "Project prefix must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "admin_user_name" {
  description = "Name of the admin IAM user that the attacker will target. In the real attack, this user was named 'frick'."
  type        = string
  default     = "frick"
}

variable "lambda_function_name" {
  description = "Name of the Lambda function the attacker will inject code into. In the real attack, this was 'EC2-init'."
  type        = string
  default     = "EC2-init"
}

variable "enable_cloudtrail" {
  description = "Enable CloudTrail logging. Set to true to see detection in action. CloudTrail costs ~$2/100K events."
  type        = bool
  default     = true
}

# =============================================================================
# Local Values -- Computed from variables
# =============================================================================
# Locals let us define values that are used in multiple places.
# This avoids repetition and keeps the config DRY (Don't Repeat Yourself).
# =============================================================================

locals {
  # Common tags for resources that need explicit tags
  # (in addition to the default_tags in the provider block)
  common_tags = {
    Project  = "cloud-attack-lab"
    Scenario = "8-minute-takeover"
  }
}
