# The 8-Minute Takeover

**Cloud Attack Simulation** | **AWS** | **Intermediate-Advanced** | **Based on a Real Attack**

> Recreate the AI-assisted AWS intrusion observed by Sysdig TRT on November 28, 2025, where an attacker escalated from stolen S3 credentials to full admin access in 8 minutes.

---

## Attack Chain

```
  T+0:00  PUBLIC S3 BUCKET DISCOVERY
  +--------------------------------------------+
  | Scan for AI-named buckets                  |  aws s3 ls (--no-sign-request)
  | Download pipeline-config.env               |  Extract AWS credentials
  | MITRE: T1530                               |
  +---------------------+----------------------+
                        |
  T+0:01                v
  +--------------------------------------------+
  | IDENTITY VERIFICATION                      |
  | sts:GetCallerIdentity -> rag-pipeline-user |  ReadOnly + Lambda write
  | MITRE: T1087.004                           |
  +---------------------+----------------------+
                        |
  T+0:02                v
  +--------------------------------------------+
  | MASSIVE RECONNAISSANCE                     |
  | Enumerate 12+ AWS services in 3 minutes    |  IAM, Lambda, S3, Secrets,
  | Speed indicates LLM-assisted automation    |  SSM, Bedrock, EC2, ...
  | MITRE: T1580                               |
  +---------------------+----------------------+
                        |
  T+0:06                v
  +--------------------------------------------+
  | LAMBDA CODE INJECTION                      |
  | 1. Increase timeout (3s -> 30s)            |  UpdateFunctionConfiguration
  | 2. Inject credential harvester             |  UpdateFunctionCode
  | 3. Invoke -> admin keys returned           |  lambda:Invoke
  | MITRE: T1648, T1098.001                    |
  +---------------------+----------------------+
                        |
  T+0:08  <<< ADMIN ACCESS ACHIEVED >>>
                        |
                        v
  +--------------------------------------------+
  | SECRET HARVESTING                          |  Secrets Manager + SSM
  | LLMJACKING RECON                           |  Bedrock model enumeration
  | GPU INSTANCE ATTEMPT                       |  p4d.24xlarge dry run
  | PERSISTENCE                                |  backdoor-admin user
  | MITRE: T1555.006, T1496.004, T1136.003    |
  +--------------------------------------------+
```

## Narrative

A fast-growing AI startup deploys a RAG pipeline on AWS. Three independent misconfigurations create a kill chain: a developer hardcodes AWS credentials in a pipeline config file, another developer makes the S3 bucket public for a demo, and a DevOps engineer grants a Lambda function AdministratorAccess "to avoid permission errors."

An attacker scanning for AI-named S3 buckets discovers the public bucket, downloads the config file, and extracts valid AWS credentials. Using these credentials, they map the entire AWS environment in 3 minutes, discover the overprivileged Lambda function, inject malicious code that creates admin access keys, and achieve full administrative control in 8 minutes. What follows: secret harvesting, LLMjacking reconnaissance, GPU instance attempts, and backdoor user creation.

## Prerequisites

- **AWS Account**: A dedicated lab/sandbox account (never production)
- **AWS CLI v2**: Configured with admin credentials for the lab account
- **Terraform**: >= 1.10.0
- **Python**: >= 3.10
- **S3 Block Public Access**: Must be disabled at the account level (setup script checks this)

## Quick Start

```bash
git clone https://github.com/BarakAgranov/the-8-minute-takeover-aws-intrusion.git
cd scenario-8min-takeover

# One-command setup (checks prereqs, deploys infra, installs deps)
./setup.sh

# Activate the virtual environment
source .venv/bin/activate
cd attack

# Choose your mode:
python main.py --auto       # Full automated attack chain
python main.py --manual     # Deploy + print manual commands
python main.py              # Interactive menu
```

## Execution Modes

### Automated Mode (`--auto`)

Runs all four attack phases sequentially with colored output. No user input required. Shows CNAPP detection points at each step.

```bash
python attack/main.py --auto --skip-deploy  # If infra is already up
```

### Manual Mode (`--manual`)

Deploys infrastructure, then prints all the commands you need for manual execution. For the complete educational walkthrough with concept explanations and expected outputs, see [docs/attack_guide.md](docs/attack_guide.md).

### Interactive Mode (default)

Shows a numbered menu to run individual attack phases. Useful for testing specific steps or re-running phases after making changes.

## MITRE ATT&CK Mapping

| Step | Technique | ID | Tactic |
|------|----------|-----|--------|
| S3 credential discovery | Data from Cloud Storage | T1530 | Collection |
| Identity verification | Cloud Account Discovery | T1087.004 | Discovery |
| Service enumeration | Cloud Infrastructure Discovery | T1580 | Discovery |
| Failed role assumption | Valid Accounts | T1078 | Defense Evasion |
| Lambda code injection | Serverless Execution | T1648 | Execution |
| Admin key creation | Additional Cloud Credentials | T1098.001 | Persistence |
| Secret harvesting | Cloud Secrets Mgmt Stores | T1555.006 | Credential Access |
| LLMjacking recon | Cloud Service Hijacking | T1496.004 | Impact |
| GPU dry run | Compute Hijacking | T1496.001 | Impact |
| Backdoor user | Create Cloud Account | T1136.003 | Persistence |

Full details: [detection/mitre_mapping.md](detection/mitre_mapping.md)

## CNAPP Detection Mapping

| Step | Component | Detection | Severity |
|------|-----------|-----------|----------|
| Public S3 bucket | **CSPM** | BPA disabled, Principal: * policy | Critical |
| Credentials in S3 | **DSPM** | AWS key pattern in S3 object | Critical |
| Burst enumeration | **CDR** | 30+ API calls in 3 minutes | High |
| Overprivileged user | **CIEM** | ReadOnlyAccess on service account | Medium |
| Lambda admin role | **CIEM** | Execution role has AdministratorAccess | Critical |
| Code injection | **CDR** | UpdateFunctionCode by non-CI/CD identity | Critical |
| Admin key creation | **CDR** | CreateAccessKey from Lambda role | Critical |
| Secret harvesting | **CDR** + **DSPM** | Bulk GetSecretValue calls | High |
| Backdoor user | **CDR** + **CIEM** | CreateUser with AdministratorAccess | Critical |

Full details: [detection/cnapp_mapping.md](detection/cnapp_mapping.md)

## Cost Estimate

| Resource | Hourly Cost | Notes |
|----------|-----------|-------|
| IAM users, policies | Free | No cost for IAM resources |
| S3 bucket + objects | < $0.01 | Minimal storage |
| Lambda function | < $0.01 | Only invoked a few times |
| Secrets Manager (3 secrets) | ~$0.04/hr | $0.40/secret/month |
| SSM Parameters | Free | Standard tier |
| CloudTrail (if enabled) | ~$0.01/hr | First trail is free for mgmt events |
| **Total** | **~$0.05/hr** | **~$1.20/day** |

GPU instances are NEVER actually launched (DryRun=True only).

## Cleanup

```bash
# Automated cleanup (handles attacker-created resources + terraform destroy)
./cleanup.sh

# Or manually:
cd terraform && terraform destroy
```

The cleanup script also re-enables account-level S3 Block Public Access.

**Manual verification checklist** (check in the AWS Console after cleanup):
- No `backdoor-admin`, `rag-pipeline-user`, `frick`, or `rocker` IAM users
- No `EC2-init` Lambda function
- No `acme-ai-rag-data-*` S3 buckets
- No `prod/*` secrets or `/prod/*` SSM parameters
- S3 Block Public Access re-enabled at account level

## Project Structure

```
scenario-8min-takeover/
+-- README.md                        # This file
+-- setup.sh                         # One-command setup
+-- cleanup.sh                       # Complete teardown
+-- terraform/                       # Infrastructure as code
|   +-- main.tf                      # All AWS resources
|   +-- variables.tf                 # Input variables
|   +-- outputs.tf                   # Values for attack scripts
|   +-- providers.tf                 # Provider configuration
|   +-- terraform.tfvars.example     # Example variable values
|   +-- lambda/ec2_init.py           # Legitimate Lambda code
+-- attack/                          # Attack scripts (Python + boto3)
|   +-- main.py                      # Menu-driven launcher
|   +-- config.py                    # Terraform output bridge
|   +-- exploit.py                   # Phase 1: Initial Access
|   +-- escalate.py                  # Phase 2: Privilege Escalation
|   +-- exfiltrate.py                # Phase 3: Secret Harvesting
|   +-- impact.py                    # Phase 4: LLMjacking/GPU/Persistence
|   +-- utils.py                     # Shared utilities
|   +-- payloads/ec2_init.py         # Malicious Lambda payload
|   +-- requirements.txt             # Python dependencies
+-- detection/                       # Detection mapping
|   +-- mitre_mapping.md             # MITRE ATT&CK mapping
|   +-- cnapp_mapping.md             # CNAPP component mapping
+-- docs/                            # Educational documentation
    +-- attack_guide.md              # Full step-by-step walkthrough
    +-- concepts.md                  # Cloud concepts explained
    +-- attack_narrative.md          # The full attack story
    +-- real_world_examples.md       # Similar real-world breaches
```

## Lessons from the Real Attack

This scenario is based on a real attack published by Sysdig's Threat Research Team:

1. **Three small misconfigurations, one catastrophic outcome.** No single mistake was critical alone. Together, they formed an exploitable chain.
2. **AI is accelerating attacks.** The 8-minute timeline makes manual detection impossible. Automated CDR is essential.
3. **ReadOnlyAccess is a reconnaissance superpower.** Treat it as a sensitive permission on service accounts.
4. **Lambda code injection bypasses traditional escalation.** No PassRole needed. Code signing is the defense.
5. **Prevention beats detection.** CSPM alerts about the public bucket would have prevented everything.

## Educational Resources

- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [Lambda Code Signing](https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html)
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Rhino Security Labs: AWS IAM Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [Sysdig: LLMjacking](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)

For the complete educational walkthrough with detailed command explanations, concept deep-dives, and expected outputs, see [docs/attack_guide.md](docs/attack_guide.md).
