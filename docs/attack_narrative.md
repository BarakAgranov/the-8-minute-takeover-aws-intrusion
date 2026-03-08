# The 8-Minute Takeover -- Attack Narrative

## The Victim

Acme AI is a fast-growing startup that builds RAG-powered (Retrieval-Augmented Generation) chatbots for enterprise customers. Their engineering team of 40 people moves fast, shipping features weekly. They use Amazon Bedrock for embeddings, Lambda functions for data processing pipelines, and S3 for storing training datasets. Their AWS account has grown organically, with permissions granted ad hoc as developers needed them.

## Three Mistakes

The attack was made possible by three independent misconfigurations, each made by a different developer, at different times, for understandable reasons:

**Mistake 1: Credentials in a configuration file.** A machine learning engineer, rushing to meet a sprint deadline, hardcoded AWS access keys into `pipeline-config.env` so the RAG pipeline could authenticate to Bedrock. The keys belonged to `rag-pipeline-user`, a service account with ReadOnlyAccess plus Lambda write and Bedrock invoke permissions. The engineer planned to move them to Secrets Manager (ticket DEVOPS-4521, still open).

**Mistake 2: A public S3 bucket.** A different developer, setting up the bucket for a customer demo, disabled S3 Block Public Access and set a bucket policy with `"Principal": "*"`. The demo worked. The public access was never reverted.

**Mistake 3: An overprivileged Lambda role.** A DevOps engineer created the `EC2-init` Lambda function to tag newly launched EC2 instances. The function only needed `ec2:CreateTags` permission. But when the engineer encountered permission errors during initial testing, they attached `AdministratorAccess` to the execution role "just to get it working." The function worked. The permissions were never scoped down.

## The Attack (Minute by Minute)

### T+0:00 -- Discovery

The attacker -- later identified as using AI-assisted automation based on the speed of their actions and the presence of Serbian-language comments in their code -- scans for S3 buckets with AI-related naming patterns. They find `acme-ai-rag-data-a1b2c3d4`. An anonymous `ListBucket` request succeeds, revealing four objects including `config/pipeline-config.env`.

A `GetObject` request downloads the config file. Inside: `AWS_ACCESS_KEY_ID=AKIA...` and `AWS_SECRET_ACCESS_KEY=...`. Valid AWS credentials, sitting in a public bucket, waiting to be found.

No CloudTrail event is generated. Anonymous S3 requests to public buckets are only logged in S3 server access logs, which Acme AI has not enabled.

### T+0:01 -- Identity

The attacker configures the stolen credentials and calls `sts:GetCallerIdentity`. The response reveals: account 123456789012, user `rag-pipeline-user` in the `/service-accounts/` path. A CloudTrail event fires, but nobody is watching for GetCallerIdentity from external IPs.

### T+0:02 -- Reconnaissance

Over the next three minutes, the attacker enumerates 12+ AWS services with machine-like speed. They list IAM users (finding `frick` with AdministratorAccess), Lambda functions (finding `EC2-init` with an admin execution role), S3 buckets, Secrets Manager secrets, SSM parameters, Bedrock models, EC2 instances, ECS clusters, RDS instances, and more.

The speed of the enumeration -- 30+ distinct API actions in under 3 minutes -- suggests LLM-assisted automation. A human would take 15-20 minutes to run these commands manually.

### T+0:05 -- Failed Escalation

The attacker tries the direct path: `sts:AssumeRole` for roles named `admin`, `Administrator`, `sysadmin`, and `netadmin`. All attempts fail because `rag-pipeline-user` lacks `sts:AssumeRole` permission. Four `AccessDenied` events fire in CloudTrail.

### T+0:06 -- The Pivot

The attacker pivots to an indirect escalation path. They know that `EC2-init` has an admin execution role and that they have `lambda:UpdateFunctionCode` permission.

First, they call `UpdateFunctionConfiguration` to increase the function timeout from 3 to 30 seconds. Then they upload a malicious `ec2_init.py` that calls `iam:CreateAccessKey` for user `frick`. The file is named identically to the original, so the handler configuration (`ec2_init.lambda_handler`) resolves without any additional changes.

### T+0:08 -- Admin Access

The attacker invokes the modified Lambda function. Lambda assumes the admin execution role, injecting temporary admin credentials into the function's environment. The malicious code uses these credentials to create a new access key for `frick` and returns it in the Lambda response.

The attacker now has permanent AdministratorAccess keys. Even if the Lambda function is immediately restored, the keys remain valid.

**Total time from initial access to admin: 8 minutes.**

### T+0:09 -- Secret Harvesting

With admin credentials, the attacker calls `GetSecretValue` on all three Secrets Manager secrets (database credentials, Stripe API key, SendGrid API key) and `GetParameter` with decryption on all three SSM SecureString parameters (connection string, JWT secret, encryption key). Six API calls, six pieces of sensitive data.

### T+0:10 -- LLMjacking Preparation

The attacker calls `GetModelInvocationLoggingConfiguration` to check if Bedrock usage is monitored. Finding that logging is not configured, they enumerate available models across Anthropic, Meta, and Amazon providers.

### T+0:11 -- GPU Instance Attempt

The attacker searches for Deep Learning AMIs (finding 1,300+), creates a key pair called `stevan-gpu-key`, and attempts to launch `p5.48xlarge` instances. When those fail due to capacity, they try `p4d.24xlarge` (8x NVIDIA A100 GPUs, $32.77/hour). The instance launches with a public IP and no authentication on the JupyterLab interface.

### T+0:11 -- Persistence

The attacker creates a new IAM user `backdoor-admin`, attaches AdministratorAccess, and generates access keys. This provides a third independent admin access path, ensuring persistent access even if the other compromised identities are discovered and remediated.

## Detection

The attack was observed by Sysdig's Threat Research Team through their cloud monitoring infrastructure. The team identified the attacker's activity based on the pattern of API calls: the rapid enumeration, the failed role assumptions, the Lambda code injection, and the CreateAccessKey for the admin user. The AI-assisted nature of the attack was inferred from the speed and the presence of Serbian-language comments in the injected Lambda code.

## Key Takeaways

1. **Three small mistakes, one catastrophic outcome.** Each misconfiguration alone would be survivable. Together, they created an exploitable kill chain.

2. **AI is accelerating attacks.** The 8-minute timeline collapses the detection window. Traditional security operations that depend on manual alert triage cannot respond in time.

3. **ReadOnlyAccess is not read-only.** It enables complete environment mapping, revealing every escalation path. Treat it as a sensitive permission.

4. **Lambda code injection is the new privilege escalation.** UpdateFunctionCode does not require PassRole. If the execution role is overprivileged, any code injected into the function inherits those privileges.

5. **Prevention beats detection.** CSPM and DSPM would have flagged the public bucket and embedded credentials before the attack started. Acting on posture alerts prevents the entire chain.
