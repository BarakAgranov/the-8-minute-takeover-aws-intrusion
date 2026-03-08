# Real-World Examples -- The 8-Minute Takeover

Documented breaches that used techniques similar to those in this scenario.

---

## 1. The 8-Minute Takeover (Sysdig TRT, November 2025)

**Source:** [Sysdig Blog - LLMjacking and the 8-Minute Takeover](https://sysdig.com/blog/8-minute-takeover/)

**What happened:** On November 28, 2025, Sysdig's Threat Research Team observed an attacker escalate from stolen S3 credentials to full AWS admin access in 8 minutes. The attacker used AI-assisted automation (evidenced by speed and Serbian-language code comments) to enumerate the environment, discover an overprivileged Lambda function, inject malicious code, and create admin access keys.

**How it maps to this scenario:** This is the exact attack we simulate. Every step in our attack chain directly reproduces the observed behavior: public S3 bucket discovery, credential extraction, burst enumeration, failed role assumptions, Lambda code injection, admin key harvesting, secret theft, LLMjacking recon, GPU instance launch, and backdoor user creation.

**Key takeaway:** The 8-minute timeline demonstrates that AI-assisted attacks collapse traditional detection windows. Organizations need real-time CDR, not manual alert triage.

---

## 2. SCARLETEEL 1.0 (Sysdig, February 2023)

**Source:** [Sysdig Blog - SCARLETEEL](https://sysdig.com/blog/cloud-breach-terraform-data-theft-scarleteel/)

**What happened:** Attackers exploited a containerized workload to gain initial access to an AWS environment. They found IAM credentials stored in S3 buckets and Terraform state files (which store secrets in plaintext). Using these credentials, they exfiltrated over 1 TB of data and attempted to expand their access across multiple AWS accounts.

**How it maps to this scenario:** Both attacks begin with credential discovery in S3 (our Step 1). SCARLETEEL found credentials in Terraform state files; our attacker finds them in a pipeline configuration file. Both demonstrate why storing credentials in S3 objects is catastrophically dangerous regardless of the file format.

**Key takeaway:** Terraform state files are a particularly high-value target because they contain every secret managed by Terraform in plaintext. Use remote state backends with encryption and access controls.

---

## 3. SCARLETEEL 2.0 (Sysdig, July 2023)

**Source:** [Sysdig Blog - SCARLETEEL 2.0](https://sysdig.com/blog/scarleteel-2-0/)

**What happened:** A more sophisticated version of the SCARLETEEL campaign. The attacker exploited a Jupyter notebook to gain access, then discovered a policy configuration error (a typo in a deny statement) that allowed privilege escalation. With elevated permissions, they deployed 42 crypto-mining EC2 instances at a cost of approximately $4,000 per day.

**How it maps to this scenario:** SCARLETEEL 2.0's privilege escalation via a policy misconfiguration parallels our Lambda code injection escalation (Steps 5-7). Both attacks exploit unintended permission grants to jump from limited to admin access. The crypto-mining deployment maps to our GPU instance recon (Step 12).

**Key takeaway:** A single typo in an IAM policy can create an exploitable privilege escalation path. Automated IAM analysis (CIEM) is essential for catching these misconfigurations before attackers do.

---

## 4. First LLMjacking Campaign (Sysdig, May 2024)

**Source:** [Sysdig Blog - LLMjacking](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/)

**What happened:** Sysdig discovered attackers using stolen cloud credentials to invoke AI models hosted on Amazon Bedrock, specifically Claude models from Anthropic. The attackers ran a reverse proxy that sold access to the stolen Bedrock endpoint. The estimated cost to the victim was $46,000 per day.

**How it maps to this scenario:** Our Step 11 (LLMjacking reconnaissance) directly simulates the attacker's preparation for this type of abuse. The real attacker checked if Bedrock invocation logging was enabled (it was not), then began invoking models. Our scenario checks the same logging configuration and enumerates available models.

**Key takeaway:** LLMjacking is a uniquely dangerous threat because it generates no unusual compute metrics. The only detection is API-level monitoring via CloudTrail or Bedrock invocation logging. Enable invocation logging for all Bedrock models.

---

## 5. GUI-Vil Campaign (Permiso, 2023)

**Source:** [Permiso Blog - GUI-Vil](https://permiso.io/blog/gui-vil)

**What happened:** An Indonesian threat group systematically scanned GitHub and other public repositories for exposed AWS access keys. When they found valid credentials, they used the AWS Console (GUI) -- rather than the CLI -- to launch GPU instances for crypto mining. The group achieved initial instance launch within 31 minutes of credential discovery and targeted regions with available GPU capacity.

**How it maps to this scenario:** GUI-Vil's workflow mirrors our Steps 1-2 (credential discovery) and Step 12 (GPU instance launch). The key difference is that GUI-Vil found credentials in code repositories while our attacker finds them in S3. Both campaigns target GPU instances for resource hijacking.

**Key takeaway:** Automated credential scanning is widespread. Any credential committed to a public repository is typically exploited within minutes. Use tools like git-secrets, trufflehog, and GitHub's built-in secret scanning to prevent credential leaks.

---

## 6. AWS Cryptomining Campaign (GuardDuty, November 2025)

**Source:** AWS Security Blog and GuardDuty findings documentation.

**What happened:** AWS GuardDuty detected a campaign where attackers compromised IAM credentials (primarily through phishing and credential stuffing) and deployed crypto miners across EC2 instances and ECS tasks within 10 minutes of initial access. The attackers used automation to rapidly enumerate the environment, escalate privileges, and launch miners in multiple regions simultaneously.

**How it maps to this scenario:** The 10-minute timeline closely matches our 8-minute scenario. Both campaigns demonstrate the speed of modern automated attacks: credential compromise, rapid enumeration, privilege escalation, and resource deployment all happening within a single SOC alert triage cycle. The cross-service movement (IAM to EC2 to ECS) mirrors our multi-service attack chain.

**Key takeaway:** Automated attacks routinely complete within 10 minutes. Detection and response must be equally automated. GuardDuty and CDR platforms provide the real-time monitoring needed to catch these attacks before impact.

---

## Common Patterns Across All Attacks

| Pattern | Attacks | Our Step |
|---------|---------|----------|
| Credentials found in storage/repos | SCARLETEEL 1.0, GUI-Vil, 8-Min Takeover | Step 1 |
| Rapid automated enumeration | All six campaigns | Step 3 |
| Privilege escalation via misconfig | SCARLETEEL 2.0, 8-Min Takeover | Steps 5-7 |
| GPU/compute resource hijacking | SCARLETEEL 2.0, GUI-Vil, GuardDuty campaign | Step 12 |
| AI/LLM service abuse | First LLMjacking, 8-Min Takeover | Step 11 |
| Sub-15-minute attack completion | 8-Min Takeover, GuardDuty campaign, GUI-Vil | All steps |
| Backdoor persistence | 8-Min Takeover | Step 13 |
