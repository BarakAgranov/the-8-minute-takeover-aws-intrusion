# =============================================================================
# main.tf -- All Infrastructure Resources
# =============================================================================
# SCENARIO: "The 8-Minute Takeover"
# Based on: Sysdig TRT observation of a real attack, November 28, 2025
#
# This file creates intentionally vulnerable infrastructure that mirrors
# the real-world environment the attacker compromised. Each resource has
# inline comments explaining:
#   - What it is
#   - Why it is configured this way (the vulnerability)
#   - What the secure alternative would be
#
# WARNING: This infrastructure is INTENTIONALLY INSECURE.
# Deploy ONLY in a dedicated lab/sandbox AWS account.
# =============================================================================


# =============================================================================
# RANDOM SUFFIX
# =============================================================================
# S3 bucket names must be globally unique across all AWS accounts.
# We append a random hex string to avoid naming collisions.
# =============================================================================

resource "random_id" "suffix" {
  byte_length = 4
}


# =============================================================================
# SECTION 1: THE PUBLIC S3 BUCKET (Initial Access Vector)
# =============================================================================
# In the real attack, the attacker found AWS credentials inside publicly
# accessible S3 buckets that contained RAG (Retrieval-Augmented Generation)
# data for AI models. The buckets used common AI tool naming conventions,
# making them trivially discoverable through automated scanning.
#
# VULNERABILITY: The bucket allows anonymous public read access AND
# contains files with embedded AWS credentials.
#
# SECURE ALTERNATIVE:
#   - Enable S3 Block Public Access at the account level
#   - Never store credentials in S3 objects
#   - Use IAM roles and temporary credentials instead of access keys
#   - Enable Amazon Macie to scan for sensitive data in S3
# =============================================================================

resource "aws_s3_bucket" "rag_data" {
  # The bucket name mimics real AI/ML project naming conventions.
  # Attackers scan for buckets with names like "rag-data", "training-data",
  # "ml-pipeline", "embeddings", etc.
  bucket        = "${var.project_prefix}-rag-data-${random_id.suffix.hex}"
  force_destroy = true # Allows Terraform to delete the bucket even if it has objects
}

# VULNERABILITY: Bucket-level Block Public Access is DISABLED.
# This overrides the bucket's default protections and allows public policies.
#
# SECURE ALTERNATIVE: All four settings should be true (which is the default
# for new buckets since April 2023). This is the first line of defense.
resource "aws_s3_bucket_public_access_block" "rag_data" {
  bucket = aws_s3_bucket.rag_data.id

  block_public_acls       = false # VULNERABLE: Should be true
  block_public_policy     = false # VULNERABLE: Should be true
  ignore_public_acls      = false # VULNERABLE: Should be true
  restrict_public_buckets = false # VULNERABLE: Should be true
}

# VULNERABILITY: A bucket policy that grants anonymous read access to everyone.
# The Principal "*" means ANY identity -- authenticated or not -- can read objects.
#
# SECURE ALTERNATIVE: Use specific IAM principals, VPC endpoints, or
# pre-signed URLs for access. Never use Principal: "*" unless the data
# is truly intended to be public (like a static website).
resource "aws_s3_bucket_policy" "rag_data_public_read" {
  bucket = aws_s3_bucket.rag_data.id

  # We must wait for the public access block to be disabled first,
  # otherwise AWS will reject this public policy.
  depends_on = [aws_s3_bucket_public_access_block.rag_data]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadAccess"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.rag_data.arn}/*"
      },
      {
        Sid       = "PublicListBucket"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:ListBucket"
        Resource  = aws_s3_bucket.rag_data.arn
      }
    ]
  })
}

# --- S3 Seed Data Objects ---
# These files simulate real RAG pipeline data. One of them contains
# AWS credentials "accidentally" embedded in a configuration file.

resource "aws_s3_object" "training_manifest" {
  bucket       = aws_s3_bucket.rag_data.id
  key          = "datasets/training-data-manifest.csv"
  content_type = "text/csv"
  content      = <<-CSV
    dataset_id,source,record_count,last_updated,status
    ds-001,customer-support-tickets,145000,2025-10-15,active
    ds-002,product-documentation,32000,2025-11-01,active
    ds-003,internal-wiki-export,78000,2025-09-22,active
    ds-004,api-documentation,12000,2025-11-10,active
    ds-005,sales-call-transcripts,56000,2025-10-28,active
  CSV

  depends_on = [aws_s3_bucket_public_access_block.rag_data]
}

resource "aws_s3_object" "embeddings_readme" {
  bucket       = aws_s3_bucket.rag_data.id
  key          = "embeddings/README.md"
  content_type = "text/markdown"
  content      = <<-MD
    # Embeddings Pipeline

    This directory contains pre-computed vector embeddings for the RAG knowledge base.
    Embeddings are generated using Amazon Bedrock Titan Embeddings v2.

    ## Pipeline Schedule
    - Full re-index: Weekly (Sunday 2am UTC)
    - Incremental updates: Daily (4am UTC)

    ## Configuration
    See ../config/pipeline-config.env for pipeline settings.
  MD

  depends_on = [aws_s3_bucket_public_access_block.rag_data]
}

# VULNERABILITY: This configuration file contains HARDCODED AWS CREDENTIALS.
# In the real attack, credentials were embedded in RAG data files.
# This is extremely common in AI/ML pipelines where developers hardcode
# credentials for convenience during development and forget to remove them.
#
# SECURE ALTERNATIVE:
#   - Use IAM roles instead of access keys
#   - Store credentials in Secrets Manager, not config files
#   - Use environment variables injected at runtime
#   - Scan all files with tools like TruffleHog or git-secrets before upload
resource "aws_s3_object" "pipeline_config" {
  bucket       = aws_s3_bucket.rag_data.id
  key          = "config/pipeline-config.env"
  content_type = "text/plain"

  # The credentials below belong to the rag-pipeline-user IAM user.
  # An attacker who downloads this file gets valid AWS access keys.
  content = <<-ENV
    # RAG Pipeline Configuration
    # Last updated: 2025-11-20 by devops team
    #
    # Bedrock model settings
    BEDROCK_MODEL_ID=amazon.titan-embed-text-v2:0
    BEDROCK_REGION=us-east-1
    EMBEDDING_DIMENSION=1024
    BATCH_SIZE=25

    # S3 settings for data ingestion
    S3_DATA_BUCKET=${aws_s3_bucket.rag_data.id}
    S3_OUTPUT_PREFIX=embeddings/output/

    # AWS credentials for the pipeline service account
    # TODO: Move these to Secrets Manager (ticket: DEVOPS-4521)
    AWS_ACCESS_KEY_ID=${aws_iam_access_key.rag_pipeline_user.id}
    AWS_SECRET_ACCESS_KEY=${aws_iam_access_key.rag_pipeline_user.secret}
    AWS_DEFAULT_REGION=${var.aws_region}

    # Lambda function for post-processing
    LAMBDA_FUNCTION_NAME=${var.lambda_function_name}

    # Logging
    LOG_LEVEL=INFO
    LOG_FORMAT=json
  ENV

  depends_on = [aws_s3_bucket_public_access_block.rag_data]
}

resource "aws_s3_object" "sample_documents" {
  bucket       = aws_s3_bucket.rag_data.id
  key          = "datasets/sample-support-tickets.jsonl"
  content_type = "application/jsonl"
  content      = <<-JSONL
    {"id": "T-10001", "subject": "Cannot reset password", "body": "I have been trying to reset my password for the last hour...", "category": "auth", "priority": "high"}
    {"id": "T-10002", "subject": "API rate limit exceeded", "body": "Our integration is hitting 429 errors after the latest update...", "category": "api", "priority": "medium"}
    {"id": "T-10003", "subject": "Billing discrepancy", "body": "The invoice for October shows charges for services we did not use...", "category": "billing", "priority": "low"}
    {"id": "T-10004", "subject": "Data export request", "body": "We need a full export of our account data for compliance audit...", "category": "data", "priority": "high"}
    {"id": "T-10005", "subject": "SSO integration broken", "body": "After updating our IdP certificate the SAML login stopped working...", "category": "auth", "priority": "critical"}
  JSONL

  depends_on = [aws_s3_bucket_public_access_block.rag_data]
}


# =============================================================================
# SECTION 2: IAM USERS AND GROUPS (Attack Principals)
# =============================================================================
# This section creates the IAM identities involved in the attack:
#
# 1. rag-pipeline-user -- The compromised user whose credentials are in S3.
#    Has ReadOnlyAccess + Lambda write + limited Bedrock permissions.
#
# 2. frick -- An admin user. The attacker's ultimate target.
#    Has AdministratorAccess. The attacker will create new access keys
#    for this user via the Lambda escalation.
#
# 3. rocker -- A user with Bedrock permissions (for LLMjacking simulation).
# =============================================================================

# --- The Compromised User: rag-pipeline-user ---

resource "aws_iam_user" "rag_pipeline_user" {
  name = "rag-pipeline-user"
  path = "/service-accounts/"

  # In real environments, service accounts are often created with minimal
  # documentation. This user was likely created by a developer who needed
  # to run a Bedrock pipeline from Lambda and never had its permissions
  # reviewed after initial setup.
}

resource "aws_iam_access_key" "rag_pipeline_user" {
  user = aws_iam_user.rag_pipeline_user.name

  # VULNERABILITY: Long-lived access keys that never expire.
  # These are the credentials that end up in the S3 bucket.
  #
  # SECURE ALTERNATIVE:
  #   - Use IAM roles with temporary credentials (STS)
  #   - If access keys are required, enforce rotation (max 90 days)
  #   - Use AWS Organizations SCPs to prevent access key creation
  #   - Monitor key age with AWS Config rules
}

# Group: readonly-users
# The rag-pipeline-user is in this group, which grants broad read access.
resource "aws_iam_group" "readonly_users" {
  name = "readonly-users"
}

resource "aws_iam_group_membership" "readonly_membership" {
  name  = "readonly-group-membership"
  group = aws_iam_group.readonly_users.name
  users = [aws_iam_user.rag_pipeline_user.name]
}

# VULNERABILITY: ReadOnlyAccess is an AWS managed policy that grants
# read-only access to EVERY AWS service. This includes the ability to
# list Lambda functions, list Secrets Manager secrets (but not values),
# describe EC2 instances, list IAM users, and much more.
#
# This is the "reconnaissance superpower" -- an attacker with ReadOnlyAccess
# can map the entire AWS environment in minutes.
#
# SECURE ALTERNATIVE:
#   - Grant only the specific read permissions needed (e.g., s3:GetObject
#     on specific buckets, bedrock:InvokeModel on specific models)
#   - Use permission boundaries to cap maximum permissions
resource "aws_iam_group_policy_attachment" "readonly_policy" {
  group      = aws_iam_group.readonly_users.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# VULNERABILITY: The rag-pipeline-user has Lambda write permissions.
# This was granted so the user could deploy pipeline code to Lambda.
# The dangerous permissions are UpdateFunctionCode and InvokeFunction,
# which let the attacker replace Lambda code and execute it.
#
# SECURE ALTERNATIVE:
#   - Use a CI/CD pipeline for Lambda deployments (no human access keys)
#   - If direct Lambda access is needed, scope it to specific functions
#   - Enable Lambda code signing to prevent unauthorized code changes
#   - Use SCPs to restrict UpdateFunctionCode to CI/CD roles only
resource "aws_iam_user_policy" "rag_pipeline_lambda" {
  name = "rag-pipeline-lambda-access"
  user = aws_iam_user.rag_pipeline_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "LambdaWriteAccess"
        Effect = "Allow"
        Action = [
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:InvokeFunction",
          "lambda:GetFunction",
          "lambda:ListFunctions"
        ]
        Resource = "*"
        # VULNERABLE: Resource is "*" -- allows modifying ANY Lambda function.
        # SECURE: Scope to specific function ARNs:
        # Resource = "arn:aws:lambda:*:*:function:rag-pipeline-*"
      }
    ]
  })
}

# Limited Bedrock permissions for the RAG pipeline.
resource "aws_iam_user_policy" "rag_pipeline_bedrock" {
  name = "rag-pipeline-bedrock-access"
  user = aws_iam_user.rag_pipeline_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BedrockInvokeAndList"
        Effect = "Allow"
        Action = [
          "bedrock:InvokeModel",
          "bedrock:ListFoundationModels",
          "bedrock:GetFoundationModel",
          "bedrock:ListCustomModels",
          "bedrock:GetModelInvocationLoggingConfiguration",
          "bedrock:ListInferenceProfiles"
        ]
        Resource = "*"
      }
    ]
  })
}


# --- The Admin User: frick ---
# This is the HIGH-VALUE TARGET. The attacker's goal is to create
# new access keys for this user, gaining full admin access.

resource "aws_iam_user" "admin_frick" {
  name = var.admin_user_name
  path = "/admins/"

  # VULNERABILITY: Admin users with long-lived access keys.
  # SECURE ALTERNATIVE:
  #   - Use IAM Identity Center (SSO) for admin access
  #   - Require MFA for all admin operations
  #   - Use temporary credentials via STS AssumeRole
  #   - Implement just-in-time (JIT) access elevation
}

resource "aws_iam_user_policy_attachment" "admin_frick_policy" {
  user       = aws_iam_user.admin_frick.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Give frick an existing access key (simulates a real admin with keys).
# The attacker will create a SECOND key pair via the Lambda escalation.
resource "aws_iam_access_key" "admin_frick" {
  user = aws_iam_user.admin_frick.name
}


# --- The Bedrock User: rocker ---
# In the real attack, the attacker created access keys for a user
# with BedrockFullAccess to enable LLMjacking.

resource "aws_iam_user" "rocker" {
  name = "rocker"
  path = "/service-accounts/"
}

resource "aws_iam_user_policy_attachment" "rocker_bedrock" {
  user       = aws_iam_user.rocker.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonBedrockFullAccess"
}


# =============================================================================
# SECTION 3: THE LAMBDA FUNCTION (Privilege Escalation Vector)
# =============================================================================
# This Lambda function is the KEY to the entire attack. It does something
# completely ordinary (tagging EC2 instances), but its execution role has
# AdministratorAccess -- the classic "we gave it admin to avoid permission
# errors" anti-pattern.
#
# The attacker will:
# 1. Discover this function via ListFunctions (ReadOnlyAccess)
# 2. Note its execution role has admin permissions
# 3. Replace its code with malicious code (UpdateFunctionCode)
# 4. Invoke it to run the malicious code with admin privileges
# 5. The malicious code creates new access keys for the admin user
#
# VULNERABILITY: Overprivileged Lambda execution role.
# SECURE ALTERNATIVE:
#   - Grant the execution role ONLY ec2:CreateTags (least privilege)
#   - Enable Lambda code signing to block unauthorized updates
#   - Use an SCP to deny UpdateFunctionCode except from CI/CD roles
#   - Monitor UpdateFunctionCode events in CloudTrail
# =============================================================================

# The Lambda execution role -- this is what makes the attack possible.
resource "aws_iam_role" "ec2_init_lambda_role" {
  name = "EC2-init-lambda-execution-role"

  # The trust policy defines WHO can assume this role.
  # Only the Lambda service can assume it.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

# VULNERABILITY: The execution role has FULL ADMINISTRATOR ACCESS.
# Any code running in this Lambda can do ANYTHING in the AWS account:
# create users, delete resources, access secrets, launch instances, etc.
#
# SECURE ALTERNATIVE: A custom policy with only the needed permissions:
#   {
#     "Effect": "Allow",
#     "Action": ["ec2:CreateTags"],
#     "Resource": "*"
#   }
resource "aws_iam_role_policy_attachment" "ec2_init_admin" {
  role       = aws_iam_role.ec2_init_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# Also attach the basic Lambda execution role for CloudWatch Logs.
resource "aws_iam_role_policy_attachment" "ec2_init_basic" {
  role       = aws_iam_role.ec2_init_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Package the Lambda code into a zip file.
# Terraform's archive_file data source handles this automatically.
data "archive_file" "ec2_init_code" {
  type        = "zip"
  source_file = "${path.module}/lambda/ec2_init.py"
  output_path = "${path.module}/lambda/ec2_init.zip"
}

# The Lambda function itself.
resource "aws_lambda_function" "ec2_init" {
  function_name = var.lambda_function_name
  description   = "Initializes EC2 instances with standard organizational tags"
  role          = aws_iam_role.ec2_init_lambda_role.arn
  handler       = "ec2_init.lambda_handler"
  runtime       = "python3.12"

  filename         = data.archive_file.ec2_init_code.output_path
  source_code_hash = data.archive_file.ec2_init_code.output_base64sha256

  # VULNERABILITY: 3-second timeout. The attacker will increase this to 30
  # seconds via UpdateFunctionConfiguration to give the malicious code
  # enough time to complete IAM API calls.
  timeout     = 3
  memory_size = 128

  environment {
    variables = {
      LOG_LEVEL = "INFO"
    }
  }

  # NOTE: No code signing configuration is set.
  # SECURE ALTERNATIVE: Enable code signing:
  #   code_signing_config_arn = aws_lambda_code_signing_config.example.arn
  # This would prevent UpdateFunctionCode with unsigned code.
}


# =============================================================================
# SECTION 4: SECRETS MANAGER (Credential Harvesting Targets)
# =============================================================================
# These secrets simulate real production credentials that an attacker
# would find valuable. In the real attack, the attacker harvested secrets
# from Secrets Manager, SSM Parameter Store, and CloudWatch Logs.
#
# VULNERABILITY: The admin user (and the Lambda execution role) has
# full access to these secrets. In a well-designed environment, access
# would be restricted to specific application roles.
#
# SECURE ALTERNATIVE:
#   - Use resource-based policies on secrets to restrict access
#   - Enable automatic rotation for all secrets
#   - Use VPC endpoints to restrict secret access to specific VPCs
#   - Monitor GetSecretValue calls in CloudTrail
# =============================================================================

resource "aws_secretsmanager_secret" "db_credentials" {
  name                    = "prod/database/postgres-main"
  description             = "Production PostgreSQL database credentials"
  recovery_window_in_days = 0 # Allows immediate deletion for lab cleanup
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    engine   = "postgres"
    host     = "prod-db-main.cluster-abc123.us-east-1.rds.amazonaws.com"
    port     = 5432
    dbname   = "acme_production"
    username = "app_service"
    password = "Pr0d-DB-S3cur3-P@ssw0rd-2025!"
  })
}

resource "aws_secretsmanager_secret" "stripe_key" {
  name                    = "prod/api/stripe-secret-key"
  description             = "Stripe payment processing API secret key"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "stripe_key" {
  secret_id     = aws_secretsmanager_secret.stripe_key.id
  secret_string = "sk_live_SIMULATED_DO_NOT_USE_51abc123def456ghi789"
}

resource "aws_secretsmanager_secret" "sendgrid_key" {
  name                    = "prod/api/sendgrid-api-key"
  description             = "SendGrid email service API key"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "sendgrid_key" {
  secret_id     = aws_secretsmanager_secret.sendgrid_key.id
  secret_string = "SG.SIMULATED_DO_NOT_USE.abc123def456ghi789jkl012mno345"
}


# =============================================================================
# SECTION 5: SSM PARAMETER STORE (Additional Secret Targets)
# =============================================================================
# SSM Parameter Store is another common location for secrets.
# Many organizations use it alongside (or instead of) Secrets Manager
# because it is free for standard parameters.
#
# VULNERABILITY: Secrets stored as SecureString are encrypted at rest
# but accessible to anyone with ssm:GetParameter permission.
# The admin role (and ReadOnlyAccess) can read parameter metadata,
# and the admin role can decrypt SecureString values.
# =============================================================================

resource "aws_ssm_parameter" "db_connection_string" {
  name  = "/prod/database/connection-string"
  type  = "SecureString"
  value = "postgresql://app_service:Pr0d-DB-S3cur3-P@ssw0rd-2025!@prod-db-main.cluster-abc123.us-east-1.rds.amazonaws.com:5432/acme_production"

  description = "Production database connection string"
}

resource "aws_ssm_parameter" "jwt_secret" {
  name  = "/prod/app/jwt-secret"
  type  = "SecureString"
  value = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.SIMULATED-SECRET-DO-NOT-USE.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

  description = "JWT signing secret for the production API"
}

resource "aws_ssm_parameter" "encryption_key" {
  name  = "/prod/app/encryption-key"
  type  = "SecureString"
  value = "aes-256-gcm:k=SIMULATED_KEY_c29tZSByYW5kb20gYnl0ZXM="

  description = "AES-256-GCM encryption key for data at rest"
}


# =============================================================================
# SECTION 6: CLOUDTRAIL (Detection and Forensics)
# =============================================================================
# CloudTrail records every API call made in the AWS account.
# This is how Sysdig observed and reconstructed the real attack.
# In our lab, we enable it so you can see the attacker's API calls
# in the CloudTrail Event History (console) or via CLI queries.
#
# NOTE: CloudTrail management events are free for the first trail.
# Data events (e.g., S3 GetObject, Lambda Invoke) cost extra.
# =============================================================================

resource "aws_s3_bucket" "cloudtrail_logs" {
  count         = var.enable_cloudtrail ? 1 : 0
  bucket        = "${var.project_prefix}-cloudtrail-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  count  = var.enable_cloudtrail ? 1 : 0
  bucket = aws_s3_bucket.cloudtrail_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs[0].arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs[0].arn}/AWSLogs/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "lab_trail" {
  count                         = var.enable_cloudtrail ? 1 : 0
  name                          = "${var.project_prefix}-attack-lab-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs[0].id
  include_global_service_events = true # Captures IAM events (which are global)
  is_multi_region_trail         = false # Single region to save costs
  enable_logging                = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}
