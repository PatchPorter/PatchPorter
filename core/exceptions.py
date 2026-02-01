"""
Custom exception classes for SCA-Repair.

This module defines a hierarchy of exceptions for better error handling
and debugging throughout the application.
"""

from typing import Optional


class SCARepairError(Exception):
    """Base exception for all SCA-Repair errors."""

    def __init__(self, message: str, details: Optional[str] = None):
        self.message = message
        self.details = details
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message}\nDetails: {self.details}"
        return self.message


class ConfigurationError(SCARepairError):
    """Raised when there's a configuration problem."""

    pass


class GitOperationError(SCARepairError):
    """Raised when a git operation fails."""

    def __init__(
        self,
        message: str,
        command: Optional[str] = None,
        stderr: Optional[str] = None,
    ):
        self.command = command
        self.stderr = stderr
        details = None
        if command or stderr:
            details = f"Command: {command}\nStderr: {stderr}"
        super().__init__(message, details)


class PatchApplicationError(SCARepairError):
    """Raised when patch application fails."""

    def __init__(
        self,
        message: str,
        patch_path: Optional[str] = None,
        target_path: Optional[str] = None,
    ):
        self.patch_path = patch_path
        self.target_path = target_path
        details = f"Patch: {patch_path}\nTarget: {target_path}"
        super().__init__(message, details)


class LLMInferenceError(SCARepairError):
    """Raised when LLM inference fails."""

    def __init__(
        self,
        message: str,
        model: Optional[str] = None,
        prompt_length: Optional[int] = None,
    ):
        self.model = model
        self.prompt_length = prompt_length
        details = f"Model: {model}\nPrompt length: {prompt_length}"
        super().__init__(message, details)


class FileNotFoundError(SCARepairError):
    """Raised when a required file is not found."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        super().__init__(f"File not found: {file_path}")


class VersionNotFoundError(SCARepairError):
    """Raised when a version cannot be found."""

    def __init__(self, version: str, available_versions: Optional[list] = None):
        self.version = version
        self.available_versions = available_versions
        details = None
        if available_versions:
            details = f"Available versions: {available_versions}"
        super().__init__(f"Version not found: {version}", details)


class TestExecutionError(SCARepairError):
    """Raised when test execution fails."""

    def __init__(
        self,
        message: str,
        test_output: Optional[str] = None,
        error_type: Optional[str] = None,
    ):
        self.test_output = test_output
        self.error_type = error_type
        super().__init__(message, f"Error type: {error_type}")


class LocalizationError(SCARepairError):
    """Raised when fault localization fails."""

    def __init__(
        self,
        message: str,
        commit_id: Optional[str] = None,
        file_path: Optional[str] = None,
    ):
        self.commit_id = commit_id
        self.file_path = file_path
        details = f"Commit: {commit_id}\nFile: {file_path}"
        super().__init__(message, details)


class PromptGenerationError(SCARepairError):
    """Raised when prompt generation fails."""

    def __init__(
        self,
        message: str,
        prompt_type: Optional[str] = None,
        version: Optional[str] = None,
    ):
        self.prompt_type = prompt_type
        self.version = version
        details = f"Prompt type: {prompt_type}\nVersion: {version}"
        super().__init__(message, details)


class APIRequestFailedError(SCARepairError):
    """Raised when an API request fails."""

    def __init__(
        self,
        message: str,
        api_name: Optional[str] = None,
        status_code: Optional[int] = None,
    ):
        self.api_name = api_name
        self.status_code = status_code
        details = f"API: {api_name}\nStatus code: {status_code}"
        super().__init__(message, details)
