"""
utils.py -- Shared utilities for the 8-Minute Takeover attack scripts.

Provides colored terminal output, retry logic, table formatting,
and Lambda waiter functions used across all attack phases.
"""
import time
import functools
from typing import Any, Callable, Dict, List, Optional, Tuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()


# =============================================================================
# Output Formatting
# =============================================================================

def print_phase_banner(phase_number: int, title: str) -> None:
    """
    Print a prominent colored banner marking the start of an attack phase.

    Args:
        phase_number: The phase number (1-4).
        title: Short title for the phase (e.g., "INITIAL ACCESS").
    """
    banner_colors = {
        1: "bright_cyan",
        2: "bright_red",
        3: "bright_yellow",
        4: "bright_magenta",
    }
    color = banner_colors.get(phase_number, "bright_white")
    console.print()
    console.print(
        Panel(
            f"[bold {color}]PHASE {phase_number}: {title}[/bold {color}]",
            border_style=color,
            box=box.DOUBLE,
            expand=True,
            padding=(1, 2),
        )
    )
    console.print()


def print_step(step_number: int, description: str) -> None:
    """
    Print a numbered step indicator.

    Args:
        step_number: The step number within the current phase.
        description: What this step does.
    """
    console.print(
        f"  [bold bright_white]Step {step_number}:[/bold bright_white] "
        f"[white]{description}[/white]"
    )


def print_detection(cnapp_component: str, description: str) -> None:
    """
    Print what a CNAPP platform would detect at this point in the attack.

    Args:
        cnapp_component: The CNAPP component (CSPM, CDR, CWP, CIEM, DSPM).
        description: What the component would alert on.
    """
    component_colors = {
        "CSPM": "bright_blue",
        "CDR": "bright_red",
        "CWP": "bright_green",
        "CIEM": "bright_yellow",
        "DSPM": "bright_magenta",
        "ASPM": "bright_cyan",
    }
    color = component_colors.get(cnapp_component, "white")
    console.print(
        f"    [dim]>> CNAPP[/dim] [{color}]{cnapp_component}[/{color}] "
        f"[dim]{description}[/dim]"
    )


def print_success(message: str) -> None:
    """Print a success message in green."""
    console.print(f"  [bold bright_green][+][/bold bright_green] {message}")


def print_error(message: str) -> None:
    """Print an error message in red."""
    console.print(f"  [bold bright_red][-][/bold bright_red] {message}")


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    console.print(f"  [bold bright_yellow][!][/bold bright_yellow] {message}")


def print_info(message: str) -> None:
    """Print an informational message in dim white."""
    console.print(f"  [dim][*][/dim] {message}")


# =============================================================================
# Table Formatting
# =============================================================================

def format_table(
    title: str,
    headers: List[str],
    rows: List[List[str]],
    styles: Optional[List[str]] = None,
) -> Table:
    """
    Create a formatted rich Table.

    Args:
        title: Table title displayed above the table.
        headers: Column header names.
        rows: List of rows, where each row is a list of cell values.
        styles: Optional list of column styles (one per header).

    Returns:
        A rich Table object ready for printing.
    """
    table = Table(title=title, box=box.ROUNDED, show_lines=True)
    if styles is None:
        styles = ["bright_white"] * len(headers)
    for header, style in zip(headers, styles):
        table.add_column(header, style=style)
    for row in rows:
        table.add_row(*[str(cell) for cell in row])
    return table


# =============================================================================
# Lambda Waiter
# =============================================================================

def wait_for_lambda_update(
    client: Any,
    function_name: str,
    max_wait: int = 60,
    poll_interval: int = 2,
) -> bool:
    """
    Poll until a Lambda function update is complete.

    After calling UpdateFunctionCode or UpdateFunctionConfiguration,
    the function enters a 'Pending' state. This function polls
    GetFunctionConfiguration until LastUpdateStatus is 'Successful'
    or until the timeout is reached.

    Args:
        client: A boto3 Lambda client.
        function_name: Name of the Lambda function.
        max_wait: Maximum seconds to wait before timing out.
        poll_interval: Seconds between polling attempts.

    Returns:
        True if the update completed successfully, False on timeout.
    """
    start = time.time()
    while time.time() - start < max_wait:
        try:
            response = client.get_function_configuration(
                FunctionName=function_name
            )
            status = response.get("LastUpdateStatus", "Unknown")
            if status == "Successful":
                return True
            if status == "Failed":
                reason = response.get("LastUpdateStatusReason", "Unknown")
                print_error(f"Lambda update failed: {reason}")
                return False
        except Exception as exc:
            print_warning(f"Polling error: {exc}")
        time.sleep(poll_interval)
    print_error(f"Timed out waiting for Lambda update after {max_wait}s")
    return False


# =============================================================================
# Retry Logic
# =============================================================================

def safe_api_call(
    func: Callable,
    max_retries: int = 3,
    retry_delay: float = 2.0,
    **kwargs: Any,
) -> Any:
    """
    Wrapper with retry logic and error handling for AWS API calls.

    Retries on transient errors (throttling, timeouts) and raises
    on permanent errors (access denied, not found).

    Args:
        func: The boto3 API method to call.
        max_retries: Number of retry attempts.
        retry_delay: Base delay between retries (doubles each attempt).
        **kwargs: Arguments passed to the API method.

    Returns:
        The API response.

    Raises:
        Exception: If all retries are exhausted or a non-retryable error occurs.
    """
    import botocore.exceptions

    non_retryable = [
        "AccessDeniedException",
        "AccessDenied",
        "UnauthorizedAccess",
        "ResourceNotFoundException",
        "ValidationException",
        "InvalidParameterValueException",
    ]

    last_error = None
    for attempt in range(max_retries):
        try:
            return func(**kwargs)
        except botocore.exceptions.ClientError as exc:
            error_code = exc.response["Error"]["Code"]
            if error_code in non_retryable:
                raise
            last_error = exc
            if attempt < max_retries - 1:
                delay = retry_delay * (2 ** attempt)
                print_warning(
                    f"API call failed ({error_code}), "
                    f"retrying in {delay:.0f}s... "
                    f"(attempt {attempt + 1}/{max_retries})"
                )
                time.sleep(delay)
        except Exception as exc:
            last_error = exc
            if attempt < max_retries - 1:
                delay = retry_delay * (2 ** attempt)
                print_warning(
                    f"Unexpected error: {exc}, "
                    f"retrying in {delay:.0f}s..."
                )
                time.sleep(delay)
    raise last_error
