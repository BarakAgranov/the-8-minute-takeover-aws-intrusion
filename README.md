# The 8-Minute Takeover

**Cloud Attack Simulation** | **AWS** | **Intermediate-Advanced** | **Based on a Real Attack**

Recreate the AI-assisted AWS intrusion observed by Sysdig TRT on November 28, 2025, where an attacker escalated from stolen S3 credentials to full admin access in 8 minutes.

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
  T+0:02                v
  +--------------------------------------------+
  | RECONNAISSANCE                             |
  | Enumerate 12+ AWS services in 3 minutes    |  IAM, Lambda, S3, Secrets,
  | Discover admin user + overprivileged Lambda |  SSM, Bedrock, EC2, ...
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

---

## Prerequisites

You need **all four** of these before running the lab:

### 1. A dedicated AWS lab account

Do NOT use a production account. This lab creates intentionally vulnerable resources (public S3 buckets, overprivileged IAM roles). Use a sandbox/lab account with no real data.

### 2. AWS CLI v2

```bash
aws --version    # Should show aws-cli/2.x.x
```

If not installed: [AWS CLI install guide](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html)

The CLI must be configured with **admin-level credentials** for your lab account:

```bash
aws configure
# Enter your Access Key ID, Secret Access Key, and region (us-east-1 recommended)

# Verify it works:
aws sts get-caller-identity
# Should return your lab account ID and user ARN
```

### 3. Terraform >= 1.10.0

```bash
terraform --version    # Should show Terraform v1.10+
```

If not installed: [Terraform install guide](https://developer.hashicorp.com/terraform/install)

### 4. Python >= 3.8

```bash
python3 --version    # Should show Python 3.8+
```

On Ubuntu/Debian, you also need the venv package:

```bash
sudo apt install python3.X-venv    # Replace X with your minor version (e.g., python3.8-venv)
```

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/BarakAgranov/the-8-minute-takeover-aws-intrusion.git
cd scenario-8min-takeover

# One-command setup (checks prereqs, configures env, deploys infrastructure)
./setup.sh

# Activate the virtual environment
source .venv/bin/activate
cd attack

# Run the attack
python main.py --auto          # Full automated attack chain
```

The `setup.sh` script handles everything: checking prerequisites, disabling S3 Block Public Access (with your confirmation), creating the Python virtual environment, installing dependencies, and deploying infrastructure with Terraform. It is safe to re-run if something fails.

---

## Usage

### Execution Modes

```bash
# Interactive menu -- pick individual phases
python main.py

# Automated -- full attack chain, no user input
python main.py --auto

# Manual -- deploy infra + print commands for manual execution
python main.py --manual
```

### Logging

```bash
# Write structured JSON log to logs/ directory
python main.py --auto --log
```

Creates a file like `logs/attack-run-20260308-143022.jsonl` with every event: phases, steps, API results, detections, errors, and timing. Useful for post-run analysis and debugging.

### Reports

```bash
# Generate Markdown report after attack completes
python main.py --auto --log --report

# Generate report from a previous run's log file
python main.py report
```

Creates a file like `reports/attack-report-20260308-143522.md` with a structured summary: compromised identity, enumeration results, credentials harvested, MITRE technique mappings, CNAPP detections, and remediation priorities.

### Lab Status

```bash
# Check lab environment health
python main.py status
```

Shows:
- AWS credential validity and account ID
- Infrastructure deployment status and cost estimate
- S3 Block Public Access status
- Attack progress (which phases have been run)
- Python environment health (venv, dependencies)
- Log file inventory

### Other Flags

```bash
--skip-deploy    # Skip Terraform if infrastructure is already up
--skip-cleanup   # Don't show the cleanup reminder at the end
```

---

## Cleanup

```bash
# Automated cleanup (handles attacker-created resources + terraform destroy + re-enables BPA)
./cleanup.sh

# Or manually:
cd terraform && terraform destroy
```

The cleanup script:
1. Deletes the `backdoor-admin` user (not managed by Terraform)
2. Removes extra access keys from `frick` (created during the attack)
3. Runs `terraform destroy` to remove all lab infrastructure
4. Re-enables S3 Block Public Access at the account level
5. Cleans up local files (state, cache, temp files)
6. Clears AWS CLI attacker profiles

**Manual verification checklist** (check in the AWS Console):
- No `backdoor-admin`, `rag-pipeline-user`, `frick`, or `rocker` IAM users
- No `EC2-init` Lambda function
- No `acme-ai-rag-data-*` S3 buckets
- No `prod/*` secrets in Secrets Manager
- No `/prod/*` parameters in SSM Parameter Store
- S3 Block Public Access re-enabled at account level

---

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
| Lambda admin role | **CIEM** | Execution role has AdministratorAccess | Critical |
| Code injection | **CDR** | UpdateFunctionCode by non-CI/CD identity | Critical |
| Admin key creation | **CDR** | CreateAccessKey from Lambda role | Critical |
| Secret harvesting | **CDR** + **DSPM** | Bulk GetSecretValue calls | High |
| Backdoor user | **CDR** + **CIEM** | CreateUser with AdministratorAccess | Critical |

Full details: [detection/cnapp_mapping.md](detection/cnapp_mapping.md)

---

## Cost Estimate

| Resource | Hourly Cost | Notes |
|----------|-----------|-------|
| IAM users, policies | Free | |
| S3 bucket + objects | < $0.01 | Minimal storage |
| Lambda function | < $0.01 | Only invoked a few times |
| Secrets Manager (3 secrets) | ~$0.04/hr | $0.40/secret/month |
| SSM Parameters | Free | Standard tier |
| CloudTrail (if enabled) | ~$0.01/hr | First trail mgmt events free |
| **Total** | **~$0.05/hr** | **~$1.20/day** |

GPU instances are NEVER actually launched (DryRun=True only).

Use `python main.py status` to see how long your lab has been running and the estimated cost.

---

## Project Structure

```
scenario-8min-takeover/
+-- README.md                        # This file
+-- setup.sh                         # One-command setup (safe to re-run)
+-- cleanup.sh                       # Complete teardown
+-- terraform/                       # Infrastructure as code
|   +-- main.tf                      # All AWS resources
|   +-- variables.tf                 # Input variables
|   +-- outputs.tf                   # Values for attack scripts
|   +-- providers.tf                 # Provider configuration
|   +-- terraform.tfvars.example     # Example variable values
|   +-- lambda/ec2_init.py           # Legitimate Lambda code
+-- attack/                          # Attack scripts (Python + boto3)
|   +-- main.py                      # Launcher (interactive/auto/manual/status/report)
|   +-- config.py                    # Terraform output bridge
|   +-- exploit.py                   # Phase 1: Initial Access
|   +-- escalate.py                  # Phase 2: Privilege Escalation
|   +-- exfiltrate.py                # Phase 3: Secret Harvesting
|   +-- impact.py                    # Phase 4: LLMjacking/GPU/Persistence
|   +-- status.py                    # Lab environment status checker
|   +-- report.py                    # Post-attack report generator
|   +-- utils.py                     # Shared utilities + structured logging
|   +-- payloads/ec2_init.py         # Malicious Lambda payload
|   +-- requirements.txt             # Python dependencies
+-- detection/                       # Detection mapping
|   +-- mitre_mapping.md             # MITRE ATT&CK mapping
|   +-- cnapp_mapping.md             # CNAPP component mapping
+-- docs/                            # Educational documentation
|   +-- attack_guide.md              # Full step-by-step walkthrough
|   +-- concepts.md                  # Cloud concepts explained
|   +-- attack_narrative.md          # The full attack story
|   +-- real_world_examples.md       # Similar real-world breaches
+-- logs/                            # Structured attack logs (created at runtime)
+-- reports/                         # Generated attack reports (created at runtime)
```

---

## Lessons from the Real Attack

1. **Three small misconfigurations, one catastrophic outcome.** No single mistake was critical alone. Together, they formed an exploitable chain.
2. **AI is accelerating attacks.** The 8-minute timeline makes manual detection impossible. Automated CDR is essential.
3. **ReadOnlyAccess is a reconnaissance superpower.** Treat it as a sensitive permission on service accounts.
4. **Lambda code injection bypasses traditional escalation.** No PassRole needed. Code signing is the defense.
5. **Prevention beats detection.** CSPM alerts about the public bucket would have prevented everything.

---

## Educational Resources

- [docs/attack_guide.md](docs/attack_guide.md) -- Complete educational walkthrough with flag-by-flag command explanations
- [docs/concepts.md](docs/concepts.md) -- Every cloud concept in this scenario explained from scratch
- [docs/attack_narrative.md](docs/attack_narrative.md) -- The full attack story told as an incident report
- [docs/real_world_examples.md](docs/real_world_examples.md) -- 6 real breaches using similar techniques
- [Sysdig: The 8-Minute Takeover](https://www.sysdig.com/blog/ai-assisted-cloud-intrusion-achieves-admin-access-in-8-minutes/) -- The original research this lab is based on
- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [Rhino Security: AWS IAM Privilege Escalation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
