"""
Configuration management for SCA-Repair.

This module provides centralized configuration with support for
environment variables and sensible defaults. Sensitive information
like API keys should be set via environment variables.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional
import json
import logging


@dataclass
class LLMConfig:
    """Configuration for LLM providers."""

    # Model lists - API-based models only
    api_models: List[str] = field(
        default_factory=lambda: ["deepseek-api", "gpt4o", "gpt-5", "gemini", "gemini-3-flash-preview", "qwen3-14b", "claude-sonnet-4-5-20250929"]
    )

    # API configurations
    deepseek_api_key: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", "")
    )
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"

    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    openai_base_url: str = field(
        default_factory=lambda: os.getenv(
            "OPENAI_BASE_URL", "https://api.openai.com/v1"
        )
    )

    gemini_api_key: str = field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "")
    )

    # Inference settings
    max_prompt_length: int = 25000
    temperature: float = 0.0
    max_retries: int = 10
    retry_delay_base: int = 2


@dataclass
class GitConfig:
    """Configuration for Git operations."""

    github_token: str = field(
        default_factory=lambda: os.getenv("GITHUB_TOKEN", "")
    )
    default_remote: str = "origin"
    fetch_on_missing_commit: bool = True
    npm_registry: str = "https://registry.npmjs.org"


@dataclass
class PathConfig:
    """Configuration for file paths."""

    # Base paths - Set via environment variable or use current directory
    base_dir: Path = field(
        default_factory=lambda: Path(os.getenv("SCA_REPAIR_BASE", Path(__file__).parent.parent.parent))
    )

    @property
    def src_dir(self) -> Path:
        return self.base_dir / "src"

    @property
    def data_dir(self) -> Path:
        return self.base_dir / "src" / "core" / "data"

    @property
    def logs_dir(self) -> Path:
        return self.base_dir / "logs"

    @property
    def temp_file(self) -> Path:
        return self.src_dir / "temp.txt"

    @property
    def log_file(self) -> Path:
        return self.logs_dir / "logging.log"

    @property
    def error_log_file(self) -> Path:
        return self.src_dir / "error-log" / "record.log"

    @property
    def project_list_file(self) -> Path:
        return self.data_dir / "target-project.txt"


@dataclass
class TestConfig:
    """Configuration for testing."""

    jest_timeout: int = 40
    test_ignore_patterns: List[str] = field(
        default_factory=lambda: ["node_modules"]
    )

    # Error patterns for classification
    syntax_error_patterns: List[str] = field(
        default_factory=lambda: [
            "Jest failed to parse a file",
            "not defined",
            "is not a function",
            "is not a constructor",
        ]
    )


@dataclass
class LocalizationConfig:
    """Configuration for fault localization."""

    methods: List[str] = field(
        default_factory=lambda: [
            "line",
            "function",
            "file",
            "history",
            "similarity",
        ]
    )

    # File patterns to exclude
    exclude_patterns: List[str] = field(
        default_factory=lambda: [
            "min.js",
            "test",
            ".json",
            "dist",
            ".history",
        ]
    )


class Config:
    """
    Main configuration class that aggregates all configuration sections.

    Usage:
        config = Config()
        api_key = config.llm.deepseek_api_key
        log_path = config.paths.log_file
    """

    _instance: Optional["Config"] = None

    def __new__(cls) -> "Config":
        """Singleton pattern to ensure consistent configuration."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self) -> None:
        """Initialize configuration sections."""
        self.llm = LLMConfig()
        self.git = GitConfig()
        self.paths = PathConfig()
        self.test = TestConfig()
        self.localization = LocalizationConfig()
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Setup logging configuration."""
        log_dir = self.paths.logs_dir
        log_dir.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
            handlers=[
                logging.FileHandler(self.paths.log_file),
                logging.StreamHandler(),
            ],
        )

    @classmethod
    def reset(cls) -> None:
        """Reset the singleton instance (useful for testing)."""
        cls._instance = None

    def validate(self) -> List[str]:
        """
        Validate configuration and return list of warnings.

        Returns:
            List of warning messages for missing or invalid configuration.
        """
        warnings = []

        if not self.llm.deepseek_api_key:
            warnings.append(
                "DEEPSEEK_API_KEY not set. DeepSeek API calls will fail."
            )

        if not self.git.github_token:
            warnings.append(
                "GITHUB_TOKEN not set. API rate limiting may apply."
            )

        if not self.paths.base_dir.exists():
            warnings.append(
                f"Base directory does not exist: {self.paths.base_dir}"
            )

        return warnings

    def to_dict(self) -> Dict:
        """Convert configuration to dictionary (excluding sensitive data)."""
        return {
            "llm": {
                "local_models": self.llm.local_models,
                "api_models": self.llm.api_models,
                "max_prompt_length": self.llm.max_prompt_length,
                "temperature": self.llm.temperature,
            },
            "git": {
                "default_remote": self.git.default_remote,
                "npm_registry": self.git.npm_registry,
            },
            "paths": {
                "base_dir": str(self.paths.base_dir),
                "logs_dir": str(self.paths.logs_dir),
            },
            "test": {
                "jest_timeout": self.test.jest_timeout,
                "test_ignore_patterns": self.test.test_ignore_patterns,
            },
        }

    def save_to_file(self, path: Path) -> None:
        """Save non-sensitive configuration to a JSON file."""
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)


# Global configuration instance
config = Config()
