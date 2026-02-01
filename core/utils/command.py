"""
Command execution utilities.

Provides a clean interface for running shell commands with proper
error handling and result encapsulation.
"""

import subprocess
import logging
from dataclasses import dataclass
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """
    Encapsulates the result of a shell command execution.

    Attributes:
        stdout: Standard output from the command
        stderr: Standard error from the command
        return_code: Exit code of the command
        command: The executed command string
    """

    stdout: str
    stderr: str
    return_code: int
    command: str

    @property
    def success(self) -> bool:
        """Check if command executed successfully."""
        return self.return_code == 0

    @property
    def has_error(self) -> bool:
        """Check if stderr contains error indicators."""
        error_indicators = ["fatal", "error", "Error", "FATAL"]
        return any(indicator in self.stderr for indicator in error_indicators)

    def __bool__(self) -> bool:
        """Allow using result in boolean context."""
        return self.success


def run_command(
    command: str,
    path: Optional[Path | str] = None,
    timeout: Optional[int] = None,
    capture_output: bool = True,
    shell: bool = True,
) -> CommandResult:
    """
    Execute a shell command and return the result.

    Args:
        command: The shell command to execute
        path: Working directory for the command (optional)
        timeout: Maximum execution time in seconds (optional)
        capture_output: Whether to capture stdout/stderr
        shell: Whether to run command through shell

    Returns:
        CommandResult object containing stdout, stderr, and return code

    Examples:
        >>> result = run_command("git status", path="/path/to/repo")
        >>> if result.success:
        ...     print(result.stdout)
    """
    cwd = Path(path) if path else None

    logger.debug(f"Executing command: {command}")
    if cwd:
        logger.debug(f"Working directory: {cwd}")

    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            shell=shell,
            capture_output=capture_output,
            text=True,
            errors="ignore",
            timeout=timeout,
        )

        cmd_result = CommandResult(
            stdout=result.stdout or "",
            stderr=result.stderr or "",
            return_code=result.returncode,
            command=command,
        )

        if cmd_result.has_error:
            logger.warning(f"Command had errors: {cmd_result.stderr}")

        return cmd_result

    except subprocess.TimeoutExpired:
        logger.error(f"Command timed out after {timeout}s: {command}")
        return CommandResult(
            stdout="",
            stderr=f"Command timed out after {timeout} seconds",
            return_code=-1,
            command=command,
        )
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        return CommandResult(
            stdout="",
            stderr=str(e),
            return_code=-1,
            command=command,
        )


def run_command_with_retry(
    command: str,
    path: Optional[Path | str] = None,
    max_retries: int = 3,
    retry_delay: float = 1.0,
) -> CommandResult:
    """
    Execute a command with automatic retry on failure.

    Args:
        command: The shell command to execute
        path: Working directory for the command
        max_retries: Maximum number of retry attempts
        retry_delay: Delay between retries in seconds

    Returns:
        CommandResult from the successful attempt or last failed attempt
    """
    import time

    last_result = None

    for attempt in range(max_retries):
        result = run_command(command, path)

        if result.success:
            return result

        last_result = result
        logger.warning(
            f"Command failed (attempt {attempt + 1}/{max_retries}): {command}"
        )

        if attempt < max_retries - 1:
            time.sleep(retry_delay * (attempt + 1))

    return last_result or CommandResult(
        stdout="",
        stderr="Max retries exceeded",
        return_code=-1,
        command=command,
    )
