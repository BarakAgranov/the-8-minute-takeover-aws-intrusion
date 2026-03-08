"""
EC2-init: Initializes newly launched EC2 instances with standard tags.

This is a LEGITIMATE Lambda function used by the DevOps team.
It is triggered by CloudWatch Events when new EC2 instances launch,
applying standard organizational tags for tracking and cost allocation.

VULNERABILITY: This function is not vulnerable itself. The security
issue is that its EXECUTION ROLE has AdministratorAccess -- far more
permissions than it needs. It only requires ec2:CreateTags, but the
DevOps team gave it admin "to avoid permission errors" (a common
anti-pattern in real organizations).

An attacker who can call UpdateFunctionCode can replace this code
with anything they want, and it will execute with full admin privileges.
"""
import boto3
import json


def lambda_handler(event, context):
    """
    Tags a newly launched EC2 instance with organizational metadata.

    Expected event format (from CloudWatch Events / EventBridge):
    {
        "detail": {
            "instance-id": "i-0123456789abcdef0"
        }
    }
    """
    ec2 = boto3.client("ec2")

    # Extract the instance ID from the event payload.
    # In production, this comes from EventBridge EC2 state-change events.
    instance_id = event.get("detail", {}).get("instance-id", "unknown")

    try:
        # Apply standard tags to the instance.
        # This is the ONLY thing this function needs to do --
        # it only needs ec2:CreateTags permission.
        ec2.create_tags(
            Resources=[instance_id],
            Tags=[
                {"Key": "ManagedBy", "Value": "EC2-init-lambda"},
                {"Key": "InitTime", "Value": context.aws_request_id},
            ],
        )
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "message": "Instance {} initialized".format(instance_id),
                    "request_id": context.aws_request_id,
                }
            ),
        }
    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
