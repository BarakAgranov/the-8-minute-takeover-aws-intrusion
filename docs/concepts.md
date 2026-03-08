# Cloud Concepts -- The 8-Minute Takeover

Every cloud concept encountered in this scenario, explained from scratch in the order they appear during the attack.

---

## S3 Buckets and Public Access

### What It Is
Amazon S3 (Simple Storage Service) stores data as "objects" inside "buckets." Each bucket has a globally unique name. Objects are organized using key prefixes that look like directories (e.g., `config/pipeline-config.env`).

### How It Works
By default, S3 buckets are private. Access can be granted through three mechanisms that layer on top of each other: bucket policies (JSON documents defining allowed actions and principals), ACLs (legacy per-object permissions), and S3 Block Public Access (an account-level or bucket-level override that blocks all public access regardless of policies or ACLs).

When a bucket policy includes `"Principal": "*"` with `"Effect": "Allow"`, it grants access to everyone on the internet, authenticated or not.

### Why It Matters for Security
Public S3 buckets are the number one source of cloud data breaches. Attackers use tools like S3Scanner and bucket-finder to enumerate buckets with predictable names (e.g., `company-data`, `rag-training`). If the bucket is public and contains credentials or sensitive data, the attacker gets free access with no authentication trail in CloudTrail.

### Key AWS APIs
`s3:GetObject`, `s3:ListBucket`, `s3:PutBucketPolicy`, `s3control:PutPublicAccessBlock`

---

## IAM Users, Groups, and Policies

### What It Is
AWS Identity and Access Management (IAM) controls who can do what in an AWS account. It has three core identity types: users (long-lived credentials for humans or service accounts), roles (temporary credentials assumed by services or federated identities), and groups (collections of users that share the same policies).

### How It Works
Permissions are defined in IAM policies (JSON documents). There are two types of policies: managed policies (standalone, reusable, either AWS-managed like ReadOnlyAccess or customer-managed) and inline policies (embedded directly in a user, group, or role). Policies are either identity-based (attached to a user/group/role) or resource-based (attached to a resource like an S3 bucket).

When a principal makes an API call, IAM evaluates all applicable policies. If any policy explicitly denies the action, it is denied. Otherwise, at least one policy must explicitly allow it.

### Why It Matters for Security
Overprivileged IAM identities are the most common root cause of cloud breaches. A service account with ReadOnlyAccess can map an entire AWS environment. A user with `iam:AttachUserPolicy` can escalate to admin. A Lambda execution role with AdministratorAccess lets any code injected into that function do anything.

### Key AWS APIs
`iam:ListUsers`, `iam:ListAttachedUserPolicies`, `iam:GetUserPolicy`, `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam:CreateUser`

---

## AWS STS and GetCallerIdentity

### What It Is
AWS Security Token Service (STS) manages temporary security credentials. Its most important API for attackers is `GetCallerIdentity`, which returns the account ID, user ID, and ARN of the calling identity.

### How It Works
GetCallerIdentity is unique: it requires zero permissions. Even if the IAM user has no policies attached at all, this call succeeds. AWS validates the request signature (proving you have the secret key) and returns who the signature belongs to.

### Why It Matters for Security
GetCallerIdentity is always an attacker's first call with stolen credentials because it is guaranteed to work and reveals the account ID, identity type, and user path. Detecting GetCallerIdentity calls from unexpected IP addresses is a high-fidelity indicator of credential compromise.

### Key AWS APIs
`sts:GetCallerIdentity`, `sts:AssumeRole`

---

## ReadOnlyAccess -- Why It Is Dangerous

### What It Is
`ReadOnlyAccess` is an AWS-managed policy that grants read-only (`Describe*`, `Get*`, `List*`) permissions to nearly every AWS service -- over 200 services, thousands of API actions.

### How It Works
Organizations attach ReadOnlyAccess to developer accounts, service accounts, and troubleshooting roles because it seems safe. After all, it only reads data, right?

### Why It Matters for Security
ReadOnlyAccess is a reconnaissance superpower. With it, an attacker can enumerate every IAM user and their policies, list every Lambda function and its execution role, discover every secret name in Secrets Manager, find every S3 bucket, catalog every EC2 instance, and map the entire environment in minutes. This information reveals all escalation paths.

---

## Lambda Functions and Execution Roles

### What It Is
AWS Lambda is a serverless compute service that runs code in response to events. Every Lambda function has an execution role -- an IAM role that Lambda assumes when running the function code.

### How It Works
When a Lambda function is invoked, Lambda calls `sts:AssumeRole` on the execution role, receives temporary credentials, and injects them as environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`). The function code can then use these credentials (automatically via the AWS SDK) to call other AWS services.

### Why It Matters for Security
The execution role determines the blast radius of a Lambda compromise. If the role has AdministratorAccess, any code running in that function can do anything in the AWS account. This is a known privilege escalation path: an attacker with `lambda:UpdateFunctionCode` permission can replace the code and invoke the function to execute arbitrary operations with the role's permissions.

### Key AWS APIs
`lambda:ListFunctions`, `lambda:GetFunction`, `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `lambda:Invoke`

---

## UpdateFunctionCode as a Privilege Escalation Path

### What It Is
The `lambda:UpdateFunctionCode` API replaces a Lambda function's deployed code with new code. Critically, no `iam:PassRole` permission is required because the function keeps its existing execution role.

### How It Works
The attacker uploads a zip file containing malicious code. Lambda replaces the old code and, on the next invocation, runs the new code with the unchanged execution role. If the attacker names their file identically to the original (e.g., `ec2_init.py` for handler `ec2_init.lambda_handler`), no handler configuration change is needed.

### Why It Matters for Security
This is one of the most dangerous privilege escalation paths in AWS. The attacker never directly assumes the admin role. They use Lambda as a proxy, which is harder to detect and does not require `sts:AssumeRole` permission. The defense is Lambda code signing, which blocks UpdateFunctionCode with unsigned code.

---

## Lambda Code Signing

### What It Is
Lambda code signing lets you ensure that only code signed by a trusted publisher can be deployed. You create a signing profile, sign your deployment packages, and configure the Lambda function to reject unsigned code.

### How It Works
When code signing is configured, Lambda validates the signature of any code uploaded via UpdateFunctionCode. If the code is unsigned or signed by an untrusted profile, Lambda rejects the update.

### Why It Matters for Security
Code signing would have completely prevented the attack. Even with UpdateFunctionCode permission, the attacker cannot upload unsigned malicious code if code signing is enforced. This is the single most effective defense against Lambda code injection.

---

## AWS Secrets Manager

### What It Is
AWS Secrets Manager stores, rotates, and manages access to secrets such as database credentials, API keys, and encryption keys. Secrets are encrypted at rest using AWS KMS.

### How It Works
Applications call `GetSecretValue` to retrieve secrets at runtime. Access is controlled by IAM policies and optional resource-based policies on individual secrets. Secrets Manager supports automatic rotation via Lambda functions.

### Why It Matters for Security
With admin access, an attacker can retrieve every secret in the account using `ListSecrets` followed by `GetSecretValue`. This yields database passwords, payment processor keys, email service credentials, and other high-value data. Resource-based policies on individual secrets can restrict access even from admin users.

### Key AWS APIs
`secretsmanager:ListSecrets`, `secretsmanager:GetSecretValue`

---

## SSM Parameter Store

### What It Is
AWS Systems Manager Parameter Store provides secure, hierarchical storage for configuration data and secrets. It supports String, StringList, and SecureString (KMS-encrypted) parameter types.

### How It Works
Applications call `GetParameter` with `WithDecryption=true` to retrieve and decrypt SecureString parameters. Unlike Secrets Manager, Parameter Store does not have built-in rotation and is free for standard-tier parameters.

### Why It Matters for Security
Many organizations use Parameter Store for secrets because it is free. With admin access, an attacker can decrypt and read all SecureString parameters.

### Key AWS APIs
`ssm:DescribeParameters`, `ssm:GetParameter`

---

## Amazon Bedrock and LLMjacking

### What It Is
Amazon Bedrock provides API access to foundation models (LLMs) from Anthropic, Meta, Amazon, and other providers. LLMjacking is the unauthorized use of cloud-hosted AI models at the victim's expense.

### How It Works
Attackers steal cloud credentials with Bedrock permissions and invoke expensive AI models. First documented by Sysdig in May 2024, LLMjacking costs can reach $46,000/day. Attackers first check if model invocation logging is enabled; if not, their usage is invisible.

### Why It Matters for Security
LLMjacking is a growing threat as more organizations enable Bedrock access. Unlike crypto mining (which has obvious CPU/GPU signatures), LLMjacking generates no unusual compute metrics. The only detection is API-level monitoring via CloudTrail or Bedrock invocation logging.

### Key AWS APIs
`bedrock:ListFoundationModels`, `bedrock:GetModelInvocationLoggingConfiguration`, `bedrock-runtime:InvokeModel`

---

## EC2 GPU Instances and Service Quotas

### What It Is
EC2 GPU instance types (p3, p4, p5, g4, g5) provide access to NVIDIA GPUs for machine learning, rendering, and other compute-intensive workloads. Prices range from $3.06/hr (g4dn.xlarge) to $98/hr (p5.48xlarge).

### How It Works
GPU instances are launched like any EC2 instance but require specific AMIs (typically Deep Learning AMIs) and may require service quota increases. By default, most accounts have 0 vCPU quota for GPU instance types.

### Why It Matters for Security
Attackers launch GPU instances for crypto mining or unauthorized model training. The cost impact can be severe: a p4d.24xlarge costs $32.77/hr ($23,600/month). Setting service quotas to 0 for GPU types and using SCPs to deny GPU launches are the primary defenses.

### Key AWS APIs
`ec2:DescribeImages`, `ec2:RunInstances`, `ec2:DescribeInstanceTypes`

---

## CloudTrail

### What It Is
AWS CloudTrail records every API call made in an AWS account as "events." It is the primary audit log for AWS and is how defenders reconstruct attacks after the fact.

### How It Works
By default, CloudTrail records management events (control plane operations like CreateUser, UpdateFunctionCode, RunInstances) for 90 days in the Event History (free). Creating a trail delivers events to an S3 bucket for long-term storage. Data events (like S3 GetObject or Lambda Invoke) require explicit configuration and cost extra.

### Why It Matters for Security
CloudTrail is how Sysdig observed and reconstructed the real 8-minute attack. Every API call in this scenario generates a CloudTrail event with the caller identity, source IP, timestamp, and request parameters. However, anonymous S3 requests to public buckets are NOT logged in CloudTrail (only in S3 server access logs).

### Key AWS APIs
`cloudtrail:LookupEvents`, `cloudtrail:GetTrailStatus`

---

## IAM Access Keys and Key Rotation

### What It Is
IAM access keys are long-lived credentials consisting of an access key ID (starts with `AKIA`) and a secret access key. They are used for programmatic access to AWS and never expire unless explicitly disabled or deleted.

### How It Works
When a request is signed with an access key, AWS validates the signature against the stored secret key. Unlike temporary credentials from STS (which expire after hours), access keys remain valid indefinitely.

### Why It Matters for Security
Long-lived access keys are the most common entry point for cloud attacks. They can be leaked in code commits, configuration files, CI/CD logs, or S3 objects. Best practice is to use IAM roles with temporary credentials wherever possible, and to enforce key rotation (maximum 90 days) when keys are necessary.

### Key AWS APIs
`iam:CreateAccessKey`, `iam:ListAccessKeys`, `iam:DeleteAccessKey`, `iam:UpdateAccessKey`
