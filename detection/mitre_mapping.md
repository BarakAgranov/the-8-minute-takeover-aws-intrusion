# MITRE ATT&CK Mapping -- The 8-Minute Takeover

## Overview

This document maps every step of the attack to the MITRE ATT&CK for Cloud framework. The mapping covers 14 technique applications across 8 distinct MITRE techniques spanning 7 tactics.

## Full Mapping Table

| Step | Technique ID | Technique Name | Tactic | Description |
|------|-------------|----------------|--------|-------------|
| 1 - S3 Discovery | T1530 | Data from Cloud Storage | Collection | Attacker downloads credentials from a publicly accessible S3 bucket containing RAG pipeline data. Anonymous ListBucket and GetObject calls require no authentication. |
| 1 - Credential Use | T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Attacker uses the discovered AWS access keys (embedded in pipeline-config.env) to authenticate as the rag-pipeline-user service account. |
| 2 - Identity Check | T1087.004 | Account Discovery: Cloud Account | Discovery | Attacker calls sts:GetCallerIdentity to identify the compromised user, account ID, and ARN path. This API requires no permissions and always succeeds. |
| 3 - Service Enumeration | T1580 | Cloud Infrastructure Discovery | Discovery | Attacker enumerates Lambda functions, S3 buckets, IAM users, Secrets Manager, SSM, Bedrock, and EC2 using ReadOnlyAccess permissions. Covers 12+ AWS services in under 3 minutes. |
| 3 - Service Discovery | T1526 | Cloud Service Discovery | Discovery | Attacker lists available services and their configurations to map the environment and identify escalation paths. |
| 4 - Role Assumption | T1078 | Valid Accounts | Defense Evasion | Attacker attempts to assume admin roles (admin, Administrator, sysadmin, netadmin). All attempts fail due to missing sts:AssumeRole permission. |
| 6 - Code Injection | T1648 | Serverless Execution | Execution | Attacker replaces EC2-init Lambda function code via UpdateFunctionCode. The malicious payload runs with the function's admin execution role. |
| 6 - Privilege Escalation | T1546 | Event Triggered Execution | Privilege Escalation | Lambda executes the injected code with AdministratorAccess via its execution role. The attacker gains admin privileges without directly assuming any role. |
| 7 - Key Creation | T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence | The injected Lambda code calls iam:CreateAccessKey for the admin user "frick", generating permanent admin credentials returned in the function response. |
| 9 - Secrets Manager | T1555.006 | Cloud Secrets Management Stores | Credential Access | Attacker uses admin access to call GetSecretValue on all Secrets Manager secrets, retrieving database credentials, Stripe keys, and SendGrid keys. |
| 10 - SSM Parameters | T1555.006 | Cloud Secrets Management Stores | Credential Access | Attacker calls GetParameter with decryption on SSM SecureString parameters, retrieving connection strings, JWT secrets, and encryption keys. |
| 11 - LLMjacking Recon | T1496.004 | Resource Hijacking: Cloud Service Hijacking | Impact | Attacker checks Bedrock logging status and enumerates available models to prepare for LLMjacking (unauthorized AI model invocation at the victim's expense). |
| 12 - GPU Dry Run | T1496.001 | Resource Hijacking: Compute Hijacking | Impact | Attacker searches for Deep Learning AMIs and attempts to launch GPU instances (p4d.24xlarge at $32.77/hr) for crypto mining or model training. |
| 13 - Backdoor User | T1136.003 | Create Account: Cloud Account | Persistence | Attacker creates a new IAM user "backdoor-admin" with AdministratorAccess and generates access keys, establishing persistent access independent of the original compromise. |
| 13 - Backdoor Keys | T1098.001 | Account Manipulation: Additional Cloud Credentials | Persistence | Attacker creates access keys for the backdoor user, providing a third independent admin access path. |

## Technique Coverage by Tactic

| Tactic | Techniques Used | Steps |
|--------|----------------|-------|
| Initial Access | T1078.004 | 1 |
| Discovery | T1087.004, T1580, T1526 | 2, 3 |
| Defense Evasion | T1078 | 4 |
| Execution | T1648 | 6 |
| Privilege Escalation | T1546 | 6 |
| Credential Access | T1555.006 | 9, 10 |
| Persistence | T1098.001, T1136.003 | 7, 13 |
| Impact | T1496.001, T1496.004 | 11, 12 |
| Collection | T1530 | 1 |

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [T1648 - Serverless Execution](https://attack.mitre.org/techniques/T1648/)
- [T1496.004 - Cloud Service Hijacking](https://attack.mitre.org/techniques/T1496/004/)
- [T1530 - Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/)
- [Sysdig TRT: The 8-Minute Takeover](https://sysdig.com/blog/8-minute-takeover/)
