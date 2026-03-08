# CNAPP Detection Mapping -- The 8-Minute Takeover

## Overview

This document maps every detectable event in the attack chain to the CNAPP (Cloud-Native Application Protection Platform) component that would detect it. A platform like Palo Alto Networks Prisma Cloud or Cortex Cloud covers all six components described here.

## CNAPP Components Used

| Component | Full Name | What It Does |
|-----------|-----------|-------------|
| **CSPM** | Cloud Security Posture Management | Detects misconfigurations in cloud resources (public buckets, missing encryption, overly permissive policies) |
| **CDR** | Cloud Detection and Response | Monitors API calls in real-time and detects anomalous behavior patterns (unusual access, privilege escalation) |
| **CWP** | Cloud Workload Protection | Protects runtime workloads (containers, Lambda, VMs) from malicious activity |
| **CIEM** | Cloud Infrastructure Entitlement Management | Analyzes IAM permissions to find overprivileged identities and risky access paths |
| **DSPM** | Data Security Posture Management | Discovers and classifies sensitive data, detects credential exposure |

## Full Detection Mapping

| Attack Step | CNAPP Component | Detection Description | Severity | What the SOC Would See | Remediation |
|-------------|----------------|----------------------|----------|----------------------|-------------|
| Step 1: Public S3 bucket | **CSPM** | S3 bucket has Block Public Access disabled at bucket level | Critical | Posture alert: S3 bucket "acme-ai-rag-data-*" allows anonymous access via bucket policy with Principal: * | Enable S3 Block Public Access at account and bucket level; remove Principal: * from bucket policy |
| Step 1: Credentials in S3 | **DSPM** | AWS access key pattern detected in S3 object | Critical | Data scan alert: AWS access key (AKIA*) found in s3://acme-ai-rag-data-*/config/pipeline-config.env | Remove credentials from S3; rotate the exposed access key; use IAM roles instead of long-lived keys |
| Step 2: Identity verification | **CDR** | GetCallerIdentity from external IP address | Medium | Identity anomaly: rag-pipeline-user called GetCallerIdentity from non-VPC IP (geolocation mismatch) | Add IP-based conditions to IAM policies; investigate credential compromise |
| Step 3: Burst enumeration | **CDR** | Unusual volume of List/Describe API calls in short timeframe | High | Behavior alert: rag-pipeline-user made 30+ distinct List/Describe calls across 12 services in 3 minutes | Investigate the source identity; restrict ReadOnlyAccess to specific services |
| Step 3: Overprivileged user | **CIEM** | Service account has AWS managed ReadOnlyAccess policy | Medium | Permission alert: rag-pipeline-user has ReadOnlyAccess (grants read to all 200+ AWS services) | Replace ReadOnlyAccess with scoped read policies for only needed services |
| Step 4: Failed role assumptions | **CDR** | Multiple failed sts:AssumeRole attempts | High | Auth alert: rag-pipeline-user attempted AssumeRole on 4 non-existent or restricted roles in 30 seconds | Investigate immediately; service accounts should never attempt role assumption outside their normal pattern |
| Step 5: Lambda admin role | **CIEM** | Lambda execution role has AdministratorAccess | Critical | Permission alert: EC2-init-lambda-execution-role has AdministratorAccess (function only needs ec2:CreateTags) | Apply least-privilege: replace AdministratorAccess with a custom policy granting only ec2:CreateTags |
| Step 6: Lambda config change | **CDR** | UpdateFunctionConfiguration increased timeout significantly | High | Config alert: EC2-init timeout changed from 3s to 30s by rag-pipeline-user (not a CI/CD identity) | Alert on Lambda configuration changes by non-pipeline identities; restrict UpdateFunctionConfiguration |
| Step 6: Lambda code injection | **CDR** | UpdateFunctionCode called by non-CI/CD identity | Critical | Runtime alert: EC2-init code updated by rag-pipeline-user (expected: CI/CD pipeline role only) | Enable Lambda code signing; restrict UpdateFunctionCode to CI/CD roles via SCP |
| Step 6: No code signing | **CSPM** | Lambda function has no code signing configuration | Medium | Posture alert: EC2-init has no CodeSigningConfigArn (unsigned code can be deployed) | Enable Lambda code signing with a signing profile |
| Step 6: Code modified outside pipeline | **CWP** | Lambda function code modified at runtime | Critical | Workload alert: EC2-init code hash changed outside deployment pipeline | Enable code signing; alert on CodeSha256 changes outside approved workflows |
| Step 7: Admin key creation | **CDR** | CreateAccessKey for admin user from Lambda role | Critical | Identity alert: EC2-init-lambda-execution-role created access key for admin user "frick" | Immediately disable the new key; investigate Lambda code; restrict CreateAccessKey via SCP |
| Step 7: Multiple keys | **CIEM** | IAM user has more than 1 active access key | Medium | Entitlement alert: user "frick" now has 2 active access keys (1 expected) | Delete the unauthorized key; enforce max 1 key per user via AWS Config rule |
| Steps 9-10: Bulk secret access | **CDR** | Rapid GetSecretValue and GetParameter calls | High | Data alert: admin user retrieved all 6 secrets/parameters within 1 minute from external IP | Restrict secret access via resource policies; alert on bulk secret retrieval |
| Steps 9-10: Sensitive data access | **DSPM** | Mass access to secrets containing credentials and API keys | Critical | Data alert: database credentials, payment API keys, and encryption keys accessed by unusual principal | Implement secret access policies; require justification for bulk access |
| Step 11: Bedrock logging check | **CDR** | GetModelInvocationLoggingConfiguration by compromised user | Medium | Recon alert: admin user checking if Bedrock usage is monitored | Enable Bedrock invocation logging; alert on logging configuration queries |
| Step 11: Missing Bedrock logging | **CSPM** | Bedrock model invocation logging is not enabled | Medium | Posture alert: Bedrock invocation logging is not configured (model usage is unmonitored) | Enable model invocation logging to S3 and/or CloudWatch |
| Step 12: GPU launch attempt | **CDR** | RunInstances for GPU instance type from unusual principal | Critical | Resource alert: admin user attempted p4d.24xlarge launch ($32.77/hr) -- DryRun detected | Set service quotas to 0 for GPU types; use SCPs to deny GPU launches except from approved roles |
| Step 13: Backdoor user created | **CDR** | CreateUser + AttachUserPolicy (AdministratorAccess) sequence | Critical | Identity alert: new user "backdoor-admin" created with AdministratorAccess by compromised admin | Delete the backdoor user; investigate the full attack chain; rotate all compromised credentials |
| Step 13: Backdoor entitlement | **CIEM** | New IAM user with AdministratorAccess created outside normal process | Critical | Entitlement alert: "backdoor-admin" has full admin privileges but was not created via approved IAM workflow | Remove the user; enforce IAM user creation via approved pipeline only (SCP) |

## Detection Timeline

In a well-configured CNAPP deployment, the first alerts would fire **before the attack even begins**:

| Time | Alert Source | Alert |
|------|-------------|-------|
| Pre-attack | CSPM | Public S3 bucket detected (posture scan) |
| Pre-attack | DSPM | Credentials in S3 detected (data scan) |
| Pre-attack | CIEM | ReadOnlyAccess on service account; Lambda role with admin |
| T+0:01 | CDR | GetCallerIdentity from external IP |
| T+0:03 | CDR | Burst enumeration pattern |
| T+0:05 | CDR | Failed AssumeRole attempts |
| T+0:06 | CDR | UpdateFunctionConfiguration + UpdateFunctionCode |
| T+0:08 | CDR | CreateAccessKey for admin user from Lambda |
| T+0:09 | CDR | Bulk secret retrieval |
| T+0:10 | CDR | Bedrock logging recon |
| T+0:11 | CDR | RunInstances for GPU; CreateUser with admin |

The pre-attack CSPM and DSPM alerts, if acted upon, would have prevented the entire attack by fixing the public bucket and removing the credentials.
