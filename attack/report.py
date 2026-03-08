"""
report.py -- Post-attack report generation.

Generates a Markdown report summarizing the attack run: what was done,
what was found, what CNAPP would have detected, and remediation steps.

Can be generated from:
  1. Live attack results (passed in from run_all_phases)
  2. A log file from a previous run (--report flag with log path)
"""
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils import console, print_success, print_info, print_error


def generate_report(
    results: Dict[str, Any],
    config: Any = None,
    log_file: Optional[str] = None,
    output_dir: Optional[str] = None,
) -> str:
    """
    Generate a Markdown report from attack results.

    Args:
        results: Dict with phase1/phase2/phase3/phase4 results.
        config: AttackConfig object (for infrastructure details).
        log_file: Path to a log file (if generating from logs).
        output_dir: Where to write the report. Defaults to ../reports/.

    Returns:
        Path to the generated report file.
    """
    if output_dir is None:
        output_dir = str(Path(__file__).parent.parent / "reports")
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report_path = os.path.join(output_dir, f"attack-report-{timestamp}.md")

    lines = []
    lines.append("# The 8-Minute Takeover -- Attack Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if config:
        lines.append(f"**Target Account:** {_safe_get(results, 'phase1.identity.Account', 'N/A')}")
        lines.append(f"**Region:** {config.aws_region}")
        lines.append(f"**S3 Bucket:** {config.bucket_name}")
        lines.append(f"**Lambda Target:** {config.lambda_function_name}")
        lines.append(f"**Admin Target:** {config.admin_user_name}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Phase 1
    p1 = results.get("phase1", {})
    lines.append("## Phase 1: Initial Access")
    lines.append("")
    identity = p1.get("identity", {})
    if identity:
        lines.append(f"**Compromised Identity:** `{identity.get('Arn', 'N/A')}`")
        lines.append(f"**Account ID:** `{identity.get('Account', 'N/A')}`")
    lines.append("")

    bucket_contents = p1.get("bucket_contents", [])
    if bucket_contents:
        lines.append(f"**S3 Objects Found:** {len(bucket_contents)}")
        for obj in bucket_contents:
            lines.append(f"  - `{obj.get('Key', '')}` ({obj.get('Size', 0)} bytes)")
        lines.append("")

    enum_data = p1.get("enumeration", {})
    if enum_data:
        lines.append("**Enumeration Results:**")
        users = enum_data.get("iam_users", [])
        if isinstance(users, list):
            lines.append(f"  - IAM Users: {len(users)}")
            for u in users:
                if isinstance(u, dict):
                    policies_str = ", ".join(u.get("Policies", []))
                    lines.append(f"    - `{u.get('UserName', '')}` -- {policies_str}")
        funcs = enum_data.get("lambda_functions", [])
        if isinstance(funcs, list):
            lines.append(f"  - Lambda Functions: {len(funcs)}")
        secrets = enum_data.get("secrets_manager", [])
        if isinstance(secrets, list):
            lines.append(f"  - Secrets Manager: {len(secrets)} secrets")
        params = enum_data.get("ssm_parameters", [])
        if isinstance(params, list):
            lines.append(f"  - SSM Parameters: {len(params)} parameters")
        lines.append("")

    role_attempts = p1.get("role_attempts", [])
    if role_attempts:
        lines.append("**Role Assumption Attempts:**")
        for attempt in role_attempts:
            lines.append(f"  - `{attempt.get('role', '')}`: {attempt.get('result', '')}")
        lines.append("")

    lines.append("| MITRE Technique | ID |")
    lines.append("|---|---|")
    lines.append("| Data from Cloud Storage | T1530 |")
    lines.append("| Cloud Account Discovery | T1087.004 |")
    lines.append("| Cloud Infrastructure Discovery | T1580 |")
    lines.append("")

    # Phase 2
    p2 = results.get("phase2", {})
    lines.append("## Phase 2: Privilege Escalation")
    lines.append("")
    harvest = p2.get("harvest", {})
    admin_creds = harvest.get("admin_credentials", {})
    if admin_creds:
        lines.append(f"**Admin Key Obtained:** `{admin_creds.get('AccessKeyId', 'N/A')}`")
        lines.append(f"**Lambda Identity:** `{harvest.get('lambda_identity', 'N/A')}`")
    else:
        lines.append("**Result:** FAILED -- no admin credentials obtained")
    lines.append("")
    lines.append("| MITRE Technique | ID |")
    lines.append("|---|---|")
    lines.append("| Serverless Execution | T1648 |")
    lines.append("| Additional Cloud Credentials | T1098.001 |")
    lines.append("")

    # Phase 3
    p3 = results.get("phase3", {})
    if p3:
        lines.append("## Phase 3: Data Exfiltration")
        lines.append("")
        secrets_harvested = p3.get("secrets", [])
        params_harvested = p3.get("parameters", [])
        lines.append(f"**Secrets Manager:** {len(secrets_harvested)} secrets retrieved")
        for s in secrets_harvested:
            name = s.get("Name", "")
            lines.append(f"  - `{name}`")
        lines.append(f"**SSM Parameters:** {len(params_harvested)} parameters retrieved")
        for p in params_harvested:
            lines.append(f"  - `{p.get('Name', '')}` ({p.get('Type', '')})")
        lines.append("")
        lines.append("| MITRE Technique | ID |")
        lines.append("|---|---|")
        lines.append("| Cloud Secrets Mgmt Stores | T1555.006 |")
        lines.append("")

    # Phase 4
    p4 = results.get("phase4", {})
    if p4:
        lines.append("## Phase 4: Impact & Persistence")
        lines.append("")
        bedrock = p4.get("bedrock_logging", {})
        if bedrock:
            logging_status = "Disabled" if not bedrock.get("logging_enabled") else "Enabled"
            lines.append(f"**Bedrock Invocation Logging:** {logging_status}")

        gpu = p4.get("gpu_recon", {})
        if gpu:
            lines.append(f"**GPU Dry Run Result:** {gpu.get('dry_run', 'N/A')}")
            lines.append(f"**Deep Learning AMIs Found:** {gpu.get('ami_count', 0)}")

        backdoor = p4.get("backdoor", {})
        if backdoor:
            bd_key = backdoor.get("access_key", {})
            if bd_key:
                lines.append(f"**Backdoor User Key:** `{bd_key.get('AccessKeyId', 'N/A')}`")
            else:
                lines.append("**Backdoor User:** Created (no key generated)")
        lines.append("")
        lines.append("| MITRE Technique | ID |")
        lines.append("|---|---|")
        lines.append("| Cloud Service Hijacking | T1496.004 |")
        lines.append("| Compute Hijacking | T1496.001 |")
        lines.append("| Create Cloud Account | T1136.003 |")
        lines.append("")

    # CNAPP Detection Summary
    lines.append("## CNAPP Detection Summary")
    lines.append("")
    lines.append("| Component | Detection | Severity |")
    lines.append("|---|---|---|")
    lines.append("| CSPM | Public S3 bucket with BPA disabled | Critical |")
    lines.append("| DSPM | AWS credentials in S3 object | Critical |")
    lines.append("| CDR | Burst enumeration from service account | High |")
    lines.append("| CIEM | Lambda execution role with AdministratorAccess | Critical |")
    lines.append("| CDR | UpdateFunctionCode by non-CI/CD identity | Critical |")
    lines.append("| CDR | CreateAccessKey for admin user from Lambda | Critical |")
    lines.append("| CDR | Bulk GetSecretValue calls | High |")
    lines.append("| CDR | CreateUser + AdministratorAccess | Critical |")
    lines.append("")

    # Remediation
    lines.append("## Remediation Priorities")
    lines.append("")
    lines.append("1. **Enable S3 Block Public Access** at the account level")
    lines.append("2. **Remove credentials from S3 objects** -- use IAM roles instead")
    lines.append("3. **Apply least-privilege to Lambda execution roles** -- EC2-init only needs ec2:CreateTags")
    lines.append("4. **Enable Lambda code signing** -- prevents unauthorized UpdateFunctionCode")
    lines.append("5. **Replace ReadOnlyAccess** on service accounts with scoped policies")
    lines.append("6. **Enable Bedrock invocation logging**")
    lines.append("7. **Set GPU instance service quotas to 0** unless explicitly needed")
    lines.append("8. **Restrict iam:CreateUser and iam:CreateAccessKey** via SCPs")
    lines.append("")

    # Write report
    report_content = "\n".join(lines)
    with open(report_path, "w") as f:
        f.write(report_content)

    return report_path


def generate_report_from_log(log_path: str, output_dir: Optional[str] = None) -> str:
    """
    Generate a report from a previous run's log file.

    Parses the JSONL log to reconstruct what happened.
    """
    if not os.path.exists(log_path):
        print_error(f"Log file not found: {log_path}")
        return ""

    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

    if not events:
        print_error("Log file is empty or has no valid entries")
        return ""

    # Build a minimal results dict from log events
    results = {"phase1": {}, "phase2": {}, "phase3": {}, "phase4": {}}

    for event in events:
        phase = event.get("phase")
        level = event.get("level", "")
        msg = event.get("message", "")
        data = event.get("data", {})

        if level == "phase":
            continue

        # Try to reconstruct results from log data
        if data and phase:
            key = f"phase{phase}"
            if key in results:
                results[key].update(data)

    report_path = generate_report(results, output_dir=output_dir)
    return report_path


def _safe_get(d: dict, path: str, default: Any = None) -> Any:
    """Safely get a nested dict value using dot notation."""
    keys = path.split(".")
    current = d
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, default)
        else:
            return default
    return current
