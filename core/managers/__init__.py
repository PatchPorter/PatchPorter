"""
Manager modules for SCA-Repair pipeline.

This package contains all the pipeline components:
    - base: Abstract base manager class
    - meta: Repository and metadata management
    - localizer: Fault localization (LLM + history core)
    - baseline_localizer: Baseline localization methods
    - prompt: LLM prompt generation
    - llm: LLM inference handling
    - test: Patch testing and validation
    - result: Result analysis and evaluation
"""

from core.managers.base import BaseManager
from core.managers.meta import MetaManager
from core.managers.localizer import FaultLocalizer, LocalizationResult
from core.managers.baseline_localizer import BaselineLocalizer
from core.managers.prompt import PromptManager
from core.managers.llm import LLMHandler
from core.managers.test import TestManager
from core.managers.result import ResultAnalyzer
from core.managers.untangler import Untangler

__all__ = [
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
]
