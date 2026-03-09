"""
utils.py -- Shared utilities for the 8-Minute Takeover attack scripts.

Provides colored terminal output, structured JSON logging, retry logic,
table formatting, and Lambda waiter functions used across all attack phases.
"""
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

console = Console()

# =============================================================================
# Structured Logging
# =============================================================================
# When enabled, every significant event is written to a JSON-lines file
# in the logs/ directory. Each line is a self-contained JSON object with:
#   timestamp, level, phase, step, message, data (optional)
#
# Enable with: python main.py --auto --log
# Logs are written to: logs/attack-run-YYYYMMDD-HHMMSS.jsonl

_log_file = None
_log_start_time = None

_PROGRESS_FILE = str(Path(__file__).resolve().parent.parent / "logs" / ".attack-progress.json")

def mark_phase_complete(phase: int) -> None:
    """Record that a phase has been completed."""
    progress = {}
    if os.path.exists(_PROGRESS_FILE):
        try:
            with open(_PROGRESS_FILE) as f:
                progress = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    progress[f"phase{phase}"] = True
    os.makedirs(os.path.dirname(_PROGRESS_FILE), exist_ok=True)
    with open(_PROGRESS_FILE, "w") as f:
        json.dump(progress, f)

def get_completed_phases() -> dict:
    """Read which phases have been completed."""
    import json, os
    if os.path.exists(_PROGRESS_FILE):
        try:
            with open(_PROGRESS_FILE) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}

def init_logging(log_dir: Optional[str] = None) -> str:
    """
    Initialize the structured log file.

    Args:
        log_dir: Directory for log files. Defaults to ../logs relative to this script.

    Returns:
        The path to the log file.
    """
    global _log_file, _log_start_time

    if log_dir is None:
        log_dir = str(Path(__file__).resolve().parent.parent / "logs")

    os.makedirs(log_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = os.path.join(log_dir, f"attack-run-{timestamp}.jsonl")

    _log_file = open(log_path, "w")
    _log_start_time = time.time()

    log_event("system", "Logging initialized", data={"log_file": log_path})
    return log_path


def log_event(
    level: str,
    message: str,
    phase: Optional[int] = None,
    step: Optional[int] = None,
    data: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Write a structured event to the log file (if logging is enabled).

    Args:
        level: Event level (info, success, error, warning, detection, phase, step).
        message: Human-readable description of the event.
        phase: Attack phase number (1-4), if applicable.
        step: Step number within the phase, if applicable.
        data: Optional dict of structured data (API responses, credentials, etc).
    """
    if _log_file is None:
        return

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "elapsed_s": round(time.time() - _log_start_time, 2) if _log_start_time else 0,
        "level": level,
        "message": message,
    }
    if phase is not None:
        entry["phase"] = phase
    if step is not None:
        entry["step"] = step
    if data is not None:
        # Sanitize: truncate very long values
        entry["data"] = _truncate_data(data)

    try:
        _log_file.write(json.dumps(entry, default=str) + "\n")
        _log_file.flush()
    except Exception:
        pass  # Never let logging break the attack


def close_logging() -> None:
    """Close the log file."""
    global _log_file
    if _log_file is not None:
        log_event("system", "Logging closed")
        _log_file.close()
        _log_file = None


def _truncate_data(data: Any, max_str_len: int = 500) -> Any:
    """Recursively truncate long string values in log data."""
    if isinstance(data, str):
        return data[:max_str_len] + "..." if len(data) > max_str_len else data
    if isinstance(data, dict):
        return {k: _truncate_data(v, max_str_len) for k, v in data.items()}
    if isinstance(data, list):
        return [_truncate_data(v, max_str_len) for v in data[:20]]
    return data


# =============================================================================
# Current Phase Tracking (for logging context)
# =============================================================================

_current_phase: Optional[int] = None
_current_step: Optional[int] = None


# =============================================================================
# Output Formatting (with integrated logging)
# =============================================================================

def print_phase_banner(phase_number: int, title: str) -> None:
    """Print a prominent colored banner marking the start of an attack phase."""
    global _current_phase, _current_step
    _current_phase = phase_number
    _current_step = None

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
    log_event("phase", f"Phase {phase_number}: {title}", phase=phase_number)


def print_step(step_number: int, description: str) -> None:
    """Print a numbered step indicator."""
    global _current_step
    _current_step = step_number

    console.print(
        f"  [bold bright_white]Step {step_number}:[/bold bright_white] "
        f"[white]{description}[/white]"
    )
    log_event("step", description, phase=_current_phase, step=step_number)


def print_detection(cnapp_component: str, description: str) -> None:
    """Print what a CNAPP platform would detect at this point."""
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
    log_event(
        "detection",
        f"[{cnapp_component}] {description}",
        phase=_current_phase,
        step=_current_step,
    )


def print_success(message: str) -> None:
    """Print a success message in green."""
    console.print(f"  [bold bright_green][+][/bold bright_green] {message}")
    log_event("success", message, phase=_current_phase, step=_current_step)


def print_error(message: str) -> None:
    """Print an error message in red."""
    console.print(f"  [bold bright_red][-][/bold bright_red] {message}")
    log_event("error", message, phase=_current_phase, step=_current_step)


def print_warning(message: str) -> None:
    """Print a warning message in yellow."""
    console.print(f"  [bold bright_yellow][!][/bold bright_yellow] {message}")
    log_event("warning", message, phase=_current_phase, step=_current_step)


def print_info(message: str) -> None:
    """Print an informational message in dim white."""
    console.print(f"  [dim][*][/dim] {message}")
    log_event("info", message, phase=_current_phase, step=_current_step)


# =============================================================================
# Table Formatting
# =============================================================================

def format_table(
    title: str,
    headers: List[str],
    rows: List[List[str]],
    styles: Optional[List[str]] = None,
) -> Table:
    """Create a formatted rich Table."""
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
    """Poll until a Lambda function update is complete."""
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
    """Wrapper with retry logic and error handling for AWS API calls."""
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
                    f"Unexpected error: {exc}, retrying in {delay:.0f}s..."
                )
                time.sleep(delay)
    raise last_error
