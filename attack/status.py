"""
status.py -- Lab environment status checker.

Shows the current state of the lab: infrastructure, credentials,
attack progress, and environment health. Useful for debugging and
for knowing what cleanup is needed.
"""
import json
import os
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
import botocore

from utils import console, format_table, print_error, print_info, print_success, print_warning

TERRAFORM_DIR = str(Path(__file__).resolve().parent.parent / "terraform")


def _check_mark(ok: bool) -> str:
    """Return a colored check or X."""
    return "[bright_green]OK[/bright_green]" if ok else "[bright_red]--[/bright_red]"


def check_infrastructure() -> Dict[str, Any]:
    """Check if Terraform infrastructure is deployed."""
    result = {"deployed": False, "resource_count": 0, "deploy_time": None}

    tfstate_path = Path(TERRAFORM_DIR) / "terraform.tfstate"
    if not tfstate_path.exists():
        return result

    try:
        with open(tfstate_path) as f:
            state = json.load(f)
        resources = state.get("resources", [])
        result["deployed"] = len(resources) > 0
        result["resource_count"] = len(resources)

        # Estimate deploy time from state file modification
        mtime = os.path.getmtime(tfstate_path)
        result["deploy_time"] = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
        result["hours_running"] = round((time.time() - mtime) / 3600, 1)
        result["estimated_cost"] = f"${result['hours_running'] * 0.05:.2f}"
    except (json.JSONDecodeError, IOError):
        pass

    return result


def check_aws_credentials() -> Dict[str, Any]:
    """Check if AWS credentials are valid."""
    result = {"valid": False, "account_id": None, "identity": None}
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        result["valid"] = True
        result["account_id"] = identity["Account"]
        result["identity"] = identity["Arn"]
    except Exception:
        pass
    return result


def check_bpa(account_id: str) -> Dict[str, Any]:
    """Check S3 Block Public Access status."""
    result = {"enabled": True, "settings": {}}
    try:
        s3control = boto3.client("s3control")
        resp = s3control.get_public_access_block(AccountId=account_id)
        config = resp.get("PublicAccessBlockConfiguration", {})
        result["settings"] = config
        result["enabled"] = any(config.values())
    except botocore.exceptions.ClientError as exc:
        if "NoSuchPublicAccessBlockConfiguration" in str(exc):
            result["enabled"] = False
        # else leave as True (unknown = assume protected)
    except Exception:
        pass
    return result


def check_attack_progress(account_id: str) -> Dict[str, Any]:
    """
    Detect which attack phases have been run by checking for
    artifacts each phase creates.
    """
    progress = {
        "phase1_recon": False,
        "phase2_escalation": False,
        "phase3_exfiltration": False,
        "phase4_persistence": False,
    }

    try:
        iam = boto3.client("iam")

        # Phase 2 indicator: frick has more than 1 access key
        try:
            frick_keys = iam.list_access_keys(UserName="frick")
            key_count = len(frick_keys.get("AccessKeyMetadata", []))
            if key_count > 1:
                progress["phase2_escalation"] = True
        except botocore.exceptions.ClientError:
            pass

        # Phase 4 indicator: backdoor-admin user exists
        try:
            iam.get_user(UserName="backdoor-admin")
            progress["phase4_persistence"] = True
        except botocore.exceptions.ClientError:
            pass

        # Phase 2 also indicated by Lambda timeout change
        try:
            lam = boto3.client("lambda")
            func = lam.get_function_configuration(FunctionName="EC2-init")
            if func.get("Timeout", 3) > 3:
                progress["phase2_escalation"] = True
        except botocore.exceptions.ClientError:
            pass

    except Exception:
        pass

    return progress


def check_python_env() -> Dict[str, Any]:
    """Check Python environment health."""
    import sys
    result = {
        "python_version": sys.version.split()[0],
        "in_venv": sys.prefix != sys.base_prefix,
    }

    # Check key dependencies
    for pkg in ["boto3", "rich"]:
        try:
            mod = __import__(pkg)
            result[f"{pkg}_version"] = getattr(mod, "__version__", "installed")
        except ImportError:
            result[f"{pkg}_version"] = "MISSING"

    return result


def check_log_files() -> Dict[str, Any]:
    """Check for existing log files."""
    log_dir = Path(__file__).parent.parent / "logs"
    result = {"log_dir_exists": log_dir.exists(), "log_count": 0, "latest": None}
    if log_dir.exists():
        logs = sorted(log_dir.glob("*.jsonl"), reverse=True)
        result["log_count"] = len(logs)
        if logs:
            result["latest"] = logs[0].name
    return result


def run_status() -> Dict[str, Any]:
    """Run all status checks and display results."""
    from rich.table import Table
    from rich import box

    console.print()
    console.print(
        "[bold bright_white]Lab Status[/bold bright_white]",
        style="underline",
    )
    console.print()

    all_status = {}

    # --- AWS Credentials ---
    creds = check_aws_credentials()
    all_status["aws_credentials"] = creds

    # --- Infrastructure ---
    infra = check_infrastructure()
    all_status["infrastructure"] = infra

    # --- BPA ---
    bpa = {"enabled": "unknown"}
    if creds["valid"]:
        bpa = check_bpa(creds["account_id"])
    all_status["bpa"] = bpa

    # --- Attack Progress ---
    progress = {}
    if creds["valid"] and infra["deployed"]:
        progress = check_attack_progress(creds["account_id"])
    all_status["attack_progress"] = progress

    # --- Python Environment ---
    pyenv = check_python_env()
    all_status["python_env"] = pyenv

    # --- Logs ---
    logs = check_log_files()
    all_status["logs"] = logs

    # --- Display ---
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Check", style="bright_cyan", width=28)
    table.add_column("Status", style="white")

    # AWS
    table.add_row(
        "AWS Credentials",
        f"{_check_mark(creds['valid'])}  {creds.get('identity', 'Not configured')}",
    )
    table.add_row(
        "Account ID",
        creds.get("account_id", "N/A"),
    )

    # Infrastructure
    table.add_row(
        "Infrastructure",
        f"{_check_mark(infra['deployed'])}  "
        + (f"{infra['resource_count']} resources" if infra["deployed"] else "Not deployed"),
    )
    if infra.get("hours_running"):
        table.add_row(
            "Running Since",
            f"{infra['deploy_time']}  ({infra['hours_running']}h, ~{infra['estimated_cost']})",
        )

    # BPA
    bpa_status = "Disabled (public bucket will work)" if not bpa.get("enabled") else "Enabled (fallback mode)"
    table.add_row(
        "S3 Block Public Access",
        f"{_check_mark(not bpa.get('enabled', True))}  {bpa_status}",
    )

    # Attack Progress
    if progress:
        phases = [
            ("Phase 1: Recon", progress.get("phase1_recon", False)),
            ("Phase 2: Escalation", progress.get("phase2_escalation", False)),
            ("Phase 3: Exfiltration", progress.get("phase3_exfiltration", False)),
            ("Phase 4: Persistence", progress.get("phase4_persistence", False)),
        ]
        phase_str = "  ".join(
            f"[bright_green]{name}[/bright_green]" if done
            else f"[dim]{name}[/dim]"
            for name, done in phases
        )
        table.add_row("Attack Progress", phase_str)

    # Python
    venv_str = "Active" if pyenv["in_venv"] else "[bright_red]Not in venv[/bright_red]"
    table.add_row(
        "Python Environment",
        f"{_check_mark(pyenv['in_venv'])}  Python {pyenv['python_version']}  ({venv_str})",
    )
    table.add_row(
        "Dependencies",
        f"boto3={pyenv.get('boto3_version', '?')}  rich={pyenv.get('rich_version', '?')}",
    )

    # Logs
    if logs["log_count"] > 0:
        table.add_row(
            "Log Files",
            f"{logs['log_count']} log(s), latest: {logs['latest']}",
        )

    console.print(table)
    console.print()

    return all_status
