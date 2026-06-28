import subprocess
import os
import shutil
from typing import Tuple

def run_cmd(cmd: str, timeout: int = 10) -> Tuple[str, str, int]:
    """
    Runs a shell command safely, catching exceptions and enforcing a timeout.
    Returns (stdout, stderr, exit_code).
    """
    try:
        # Run using bash shell to support piping if needed, but in a safe manner
        result = subprocess.run(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode('utf-8', errors='ignore') if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode('utf-8', errors='ignore') if isinstance(e.stderr, bytes) else (e.stderr or "")
        return stdout.strip(), f"TIMEOUT EXPIRED: {stderr}".strip(), -9
    except Exception as e:
        return "", f"EXCEPTION: {str(e)}", -1

def is_root() -> bool:
    """Checks if the scanner is currently running with root privileges."""
    return os.geteuid() == 0

def has_binary(name: str) -> bool:
    """Checks if a binary is available on the system PATH."""
    return shutil.which(name) is not None

def get_severity_color(severity: str) -> str:
    """Maps severity levels to Rich color tag names."""
    severity = severity.upper()
    if severity == "CRITICAL":
        return "bold red"
    elif severity == "HIGH":
        return "red"
    elif severity == "MEDIUM":
        return "yellow"
    elif severity == "LOW":
        return "cyan"
    elif severity == "INFO":
        return "dim white"
    elif severity == "PASS":
        return "green"
    return "white"
