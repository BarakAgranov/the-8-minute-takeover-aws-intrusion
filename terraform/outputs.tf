# =============================================================================
# outputs.tf -- Values Needed for the Attack Phase
# =============================================================================
# These outputs provide the information you need to execute each attack step.
# After running `terraform apply`, use `terraform output` to retrieve them.
#
# SENSITIVE values (access keys) require: terraform output -json
# =============================================================================

# --- S3 Bucket (Initial Access) ---

output "rag_bucket_name" {
  description = "Name of the public S3 bucket containing RAG data and leaked credentials"
  value       = aws_s3_bucket.rag_data.id
}

output "rag_bucket_url" {
  description = "HTTPS URL for the public S3 bucket (for browser access)"
  value       = "https://${aws_s3_bucket.rag_data.id}.s3.amazonaws.com"
}

output "rag_bucket_region" {
  description = "Region of the RAG data bucket"
  value       = var.aws_region
}

# --- Compromised User Credentials (Initial Access) ---

output "compromised_access_key_id" {
  description = "Access Key ID for rag-pipeline-user (the 'leaked' credential)"
  value       = aws_iam_access_key.rag_pipeline_user.id
  sensitive   = true
}

output "compromised_secret_access_key" {
  description = "Secret Access Key for rag-pipeline-user (the 'leaked' credential)"
  value       = aws_iam_access_key.rag_pipeline_user.secret
  sensitive   = true
}

# --- Lambda Function (Escalation Target) ---

output "lambda_function_name" {
  description = "Name of the Lambda function the attacker will inject code into"
  value       = aws_lambda_function.ec2_init.function_name
}

output "lambda_function_arn" {
  description = "ARN of the Lambda function"
  value       = aws_lambda_function.ec2_init.arn
}

output "lambda_execution_role_arn" {
  description = "ARN of the Lambda execution role (has AdministratorAccess)"
  value       = aws_iam_role.ec2_init_lambda_role.arn
}

# --- Target Users ---

output "admin_user_name" {
  description = "Name of the admin IAM user the attacker will target"
  value       = aws_iam_user.admin_frick.name
}

output "bedrock_user_name" {
  description = "Name of the user with Bedrock access (for LLMjacking)"
  value       = aws_iam_user.rocker.name
}

# --- Secrets (Harvesting Targets) ---

output "secrets_manager_names" {
  description = "Names of Secrets Manager secrets to harvest"
  value = [
    aws_secretsmanager_secret.db_credentials.name,
    aws_secretsmanager_secret.stripe_key.name,
    aws_secretsmanager_secret.sendgrid_key.name,
  ]
}

output "ssm_parameter_names" {
  description = "Names of SSM parameters to harvest"
  value = [
    aws_ssm_parameter.db_connection_string.name,
    aws_ssm_parameter.jwt_secret.name,
    aws_ssm_parameter.encryption_key.name,
  ]
}

# --- Account Info ---

output "aws_region" {
  description = "AWS region where infrastructure is deployed"
  value       = var.aws_region
}

# --- Quick Reference ---

output "attack_summary" {
  description = "Quick reference for all attack-phase values"
  value       = <<-EOT

    ============================================
    8-MINUTE TAKEOVER -- ATTACK PHASE REFERENCE
    ============================================

    S3 Bucket:       ${aws_s3_bucket.rag_data.id}
    Lambda Function: ${aws_lambda_function.ec2_init.function_name}
    Admin Target:    ${aws_iam_user.admin_frick.name}
    Region:          ${var.aws_region}

    To get the compromised credentials, run:
      terraform output -json compromised_access_key_id
      terraform output -json compromised_secret_access_key

    Or discover them the attacker way:
      aws s3 cp s3://${aws_s3_bucket.rag_data.id}/config/pipeline-config.env - --no-sign-request

  EOT
}
