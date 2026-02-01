"""
SCA-Repair: Automated Security Patch Backporting

This package provides a refactored, well-organized implementation
for automatically backporting security patches across JavaScript/Node.js
package versions using LLMs.

Main Components:
    - config: Configuration management
    - exceptions: Custom exception classes
    - project: Core Project class for project metadata
    - utils: Utility functions (git, file, command execution)
    - managers: Pipeline components (meta, localizer, prompt, llm, test, result)
    - pipeline: High-level pipeline orchestration

Usage Example:
    from core import Project, Config, Pipeline
    from core.managers import MetaManager, FaultLocalizer, PromptManager
    
    # Initialize project
    project = Project('/path/to/project')
    config = Config()
    
    # Run pipeline
    pipeline = Pipeline(project, config)
    result = pipeline.run_single(target_version='1.0.0', model='deepseek-api')
"""

from core.config import Config
from core.project import Project
from core.exceptions import (
    SCARepairError,
    GitOperationError,
    PatchApplicationError,
    LLMInferenceError,
    ConfigurationError,
    TestExecutionError,
    LocalizationError,
)
from core.pipeline import Pipeline, PipelineConfig, PipelineResult

# Import managers for convenience
from core.managers import (
    BaseManager,
    MetaManager,
    FaultLocalizer,
    PromptManager,
    LLMHandler,
    TestManager,
    ResultAnalyzer,
    Untangler,
    LocalizationResult,
    BaselineLocalizer,
)

# Import runner for convenience
from core.runner import Runner, quick_run, quick_run_all, quick_stage

__version__ = "2.0.0"
__all__ = [
    # Core classes
    "Config",
    "Project",
    # Pipeline
    "Pipeline",
    "PipelineConfig",
    "PipelineResult",
    # Runner (New)
    "Runner",
    "quick_run",
    "quick_run_all",
    "quick_stage",
    # Managers
    "BaseManager",
    "MetaManager",
    "FaultLocalizer",
    "LocalizationResult",
    "BaselineLocalizer",
    "PromptManager",
    "LLMHandler",
    "TestManager",
    "ResultAnalyzer",
    "Untangler",
    # Exceptions
    "SCARepairError",
    "GitOperationError",
    "PatchApplicationError",
    "LLMInferenceError",
    "ConfigurationError",
    "TestExecutionError",
    "LocalizationError",
]
