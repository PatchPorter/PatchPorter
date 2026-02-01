"""
Pipeline orchestration for SCA-Repair.

Provides high-level functions for running the complete
vulnerability patch backporting pipeline.
"""

import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable, Type
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import dataclass, field

from core.project import Project
from core.config import config
from core.managers.base import BaseManager
from core.managers.meta import MetaManager
from core.managers.localizer import FaultLocalizer
from core.managers.baseline_localizer import BaselineLocalizer
from core.managers.prompt import PromptManager
from core.managers.llm import LLMHandler
from core.managers.test import TestManager
from core.managers.result import ResultAnalyzer
from core.managers.untangler import Untangler
from core.utils.file import read_lines
from core.exceptions import SCARepairError

logger = logging.getLogger(__name__)


@dataclass
class PipelineConfig:
    """Configuration for pipeline execution."""
    
    # Processing settings
    max_workers: int = 16
    use_multiprocessing: bool = False
    
    # Model settings
    models: List[str] = field(
        default_factory=lambda: ["deepseek-api"]
    )
    
    # Localization settings
    localization_methods: List[str] = field(
        default_factory=lambda: ["line", "function", "file"]
    )
    
    # Paths
    project_list_file: Optional[Path] = None
    
    def __post_init__(self):
        if self.project_list_file is None:
            self.project_list_file = config.paths.project_list_file


@dataclass
class PipelineResult:
    """Result of pipeline execution."""
    
    project_id: str
    success: bool
    stages_completed: List[str] = field(default_factory=list)
    error: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)


class Pipeline:
    """
    Main pipeline orchestrator for SCA-Repair.
    
    The pipeline consists of these stages:
    1. Setup - Initialize project and validate structure
    2. Untangle - Simplify patch to security-relevant changes
    3. Localize - Track vulnerable code across versions
    4. Generate - Create LLM prompts for backporting
    5. Infer - Run LLM inference
    6. Test - Validate generated patches
    7. Analyze - Evaluate results
    
    Example:
        pipeline = Pipeline()
        results = pipeline.run_all(model="deepseek-api")
    """
    
    def __init__(self, pipeline_config: Optional[PipelineConfig] = None):
        """
        Initialize pipeline.
        
        Args:
            pipeline_config: Optional configuration override
        """
        self.config = pipeline_config or PipelineConfig()
        self._results: List[PipelineResult] = []
    
    # =========================================================================
    # Project Loading
    # =========================================================================
    
    def get_project_paths(self) -> List[Path]:
        """
        Get list of project paths from configuration.
        
        Returns:
            List of absolute project paths
        """
        if not self.config.project_list_file:
            return []
        
        try:
            lines = read_lines(self.config.project_list_file, skip_empty=True)
            return [Path(line).resolve() for line in lines]
        except Exception as e:
            logger.error(f"Failed to load project list: {e}")
            return []
    
    def load_project(self, path: Path) -> Optional[Project]:
        """
        Load a single project.
        
        Args:
            path: Project path
            
        Returns:
            Project instance or None if loading fails
        """
        try:
            return Project(path)
        except Exception as e:
            logger.error(f"Failed to load project {path}: {e}")
            return None
    
    # =========================================================================
    # Single Project Processing
    # =========================================================================
    
    def run_single(
        self,
        project_path: Path,
        model: str = "deepseek-api",
        stages: Optional[List[str]] = None,
        localization_method: str = "history_llm",
        context_granularity: Optional[str] = None,
    ) -> PipelineResult:
        """
        Run pipeline for a single project.
        
        Args:
            project_path: Path to project
            model: Model to use for inference
            stages: Optional list of stages to run
            localization_method: Localization method to use (default: "line")
            context_granularity: Context granularity (line, structure, function, file), None for dynamic
            
        Returns:
            PipelineResult
        """
        stages = stages or ["localize", "generate", "infer", "test"]
        
        result = PipelineResult(
            project_id=project_path.name,
            success=False,
        )
        
        # Load project
        project = self.load_project(project_path)
        if not project:
            result.error = "Failed to load project"
            return result
        
        # Initialize timing attributes
        project._localization_time = 0
        project._prompt_time = 0
        project._inference_time = 0
        project._inference_tokens = 0

        try:
            # Run stages
            customization = None  # Will be set during prompt generation
            
            if "localize" in stages:
                # Oracle localization: directly use localization.csv
                if localization_method == 'oracle':
                    oracle_file = project.path / 'localization.csv'
                    if not oracle_file.exists():
                        raise Exception(f"Oracle localization file not found: {oracle_file}")
                    logger.info(f"Using Oracle localization from: {oracle_file}")
                # If context_granularity specified, skip localization stage, use existing deepseek localization results
                elif context_granularity:
                    logger.info(f"Using context_granularity={context_granularity}, skipping localization (using existing deepseek results)")
                    # Ensure using deepseek localization results
                    localization_file = project.localization_path / "deepseek-api.csv"
                    if not localization_file.exists():
                        raise Exception(f"Deepseek localization file not found: {localization_file}")
                    # Set model to deepseek-api so subsequent steps use correct localization file
                    model = "deepseek-api"
                else:
                    self._run_localization(project, model, localization_method)
                result.stages_completed.append("localize")
            
            if "generate" in stages:
                customization = self._run_prompt_generation(project, model, localization_method, context_granularity)
                result.stages_completed.append("generate")
            
            if "infer" in stages:
                self._run_inference(project, model)
                result.stages_completed.append("infer")
            
            if "test" in stages:
                # Use customization from generation stage, fallback to 'dynamic' if not available
                test_customization = customization or "dynamic"
                # Pass timing and token info to test manager
                test_results = self._run_testing(
                    project, model, test_customization, localization_method,
                    timing_info={
                        'localization_time': getattr(project, '_localization_time', 0),
                        'prompt_time': getattr(project, '_prompt_time', 0),
                        'inference_time': getattr(project, '_inference_time', 0),
                        'inference_tokens': getattr(project, '_inference_tokens', 0),
                    }
                )
                result.results["test"] = test_results
                result.stages_completed.append("test")
            
            # Determine real success: check test results
            result.success = self._check_real_success(project, model, customization or "dynamic", localization_method)
            
        except Exception as e:
            logger.error(f"Pipeline error for {project_path}: {e}")
            result.error = str(e)
        
        return result
    
    def _run_localization(self, project: Project, model: str, method: str = "history_llm") -> None:
        """Run fault localization stage."""
        localizer = FaultLocalizer(project)
        # Pass model to localization for potential file naming
        localizer.run(method=method, model=model)
    
    def _run_prompt_generation(self, project: Project, model: str, method: str = "history_llm", context_granularity: Optional[str] = None) -> Optional[str]:
        """Run prompt generation stage and return customization method."""
        prompt_mgr = PromptManager(project)
        # Pass model and context_granularity to prompt generation
        result = prompt_mgr.run(method=method, model=model, context_granularity=context_granularity)
        
        # Extract customization from generated file name
        if result:
            # result is a Path object like: dynamic@history_llm.json
            filename = Path(result).stem  # Get filename without extension
            parts = filename.split('@')
            if len(parts) >= 1:
                return parts[0]  # Return customization (e.g., 'dynamic', 'fixed', 'file')
        
        return None
    
    def _run_inference(self, project: Project, model: str) -> None:
        """Run LLM inference stage."""
        llm_handler = LLMHandler(project)
        llm_handler.run(model=model)
    
    def _run_testing(self, project: Project, model: str, customization: str = "dynamic", method: str = "history_llm", timing_info: Optional[Dict[str, float]] = None) -> Dict[str, str]:
        """Run testing stage."""
        test_mgr = TestManager(project)
        return test_mgr.run(model=model, customization=customization, method=method, timing_info=timing_info)
    
    def _check_real_success(self, project: Project, model: str, customization: str = "dynamic", method: str = "history_llm") -> bool:
        """Check if truly fixed based on test results"""
        from core.utils.file import read_json
        
        # Find corresponding result file, support files with and without model name
        if model != "deepseek-api":
            result_file = project.result_path / f"{customization}@{method}-{model}-result.json"
            if not result_file.exists():
                result_file = project.result_path / f"{customization}@{method}-result.json"
        else:
            result_file = project.result_path / f"{customization}@{method}-result.json"
        
        if not result_file.exists():
            logger.warning(f"Result file not found: {result_file}")
            return False
        
        try:
            data = read_json(result_file)
            test_history = data.get("test_history", [])
            
            if not test_history:
                return False
            
            # Get latest test result
            latest_test = test_history[-1]
            result = latest_test.get("result", "")
            
 # Success criteria:True Check
            return result in ["True", "Check"]
            
        except Exception as e:
            logger.error(f"Error checking test results: {e}")
            return False
    
    # =========================================================================
    # Batch Processing
    # =========================================================================
    
    def run_all(
        self,
        model: str = "deepseek-api",
        stages: Optional[List[str]] = None,
        localization_method: str = "history_llm",
        context_granularity: Optional[str] = None,
    ) -> List[PipelineResult]:
        """
        Run pipeline for all projects in configuration.
        
        Args:
            model: Model to use
            stages: Stages to run
            localization_method: Localization method to use (default: "line")
            context_granularity: Context granularity (line, structure, function, file), None for dynamic
            
        Returns:
            List of results
        """
        project_paths = self.get_project_paths()
        logger.info(f"Processing {len(project_paths)} projects")
        
        results = []
        
        for path in project_paths:
            logger.info(f"Processing: {path}")
            result = self.run_single(path, model, stages, localization_method, context_granularity)
            results.append(result)
        
        self._results = results
        return results
    
    def run_parallel(
        self,
        model: str = "deepseek-api",
        stages: Optional[List[str]] = None,
        localization_method: str = "history_llm",
        context_granularity: Optional[str] = None,
    ) -> List[PipelineResult]:
        """
        Run pipeline in parallel for all projects.
        
        Note: Use with caution - some operations may not be thread-safe.
        
        Args:
            model: Model to use
            stages: Stages to run
            localization_method: Localization method to use (default: "line")
            context_granularity: Context granularity (line, structure, function, file), None for dynamic
            
        Returns:
            List of results
        """
        project_paths = self.get_project_paths()
        logger.info(f"Processing {len(project_paths)} projects in parallel")
        
        executor_class = (
            ProcessPoolExecutor if self.config.use_multiprocessing
            else ThreadPoolExecutor
        )
        
        with executor_class(max_workers=self.config.max_workers) as executor:
            futures = [
                executor.submit(self.run_single, path, model, stages, localization_method)
                for path in project_paths
            ]
            results = [f.result() for f in futures]
        
        self._results = results
        return results
    
    # =========================================================================
    # Analysis
    # =========================================================================
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get summary of pipeline results.
        
        Returns:
            Summary statistics
        """
        if not self._results:
            return {}
        
        total = len(self._results)
        successful = sum(1 for r in self._results if r.success)
        failed = total - successful
        
        # Count by stage
        stage_counts = {}
        for result in self._results:
            for stage in result.stages_completed:
                stage_counts[stage] = stage_counts.get(stage, 0) + 1
        
        return {
            "total": total,
            "successful": successful,
            "failed": failed,
            "success_rate": successful / total if total > 0 else 0,
            "stages": stage_counts,
        }
    
    def print_summary(self) -> None:
        """Print summary to console."""
        summary = self.get_summary()
        
        print("=" * 60)
        print("Pipeline Execution Summary")
        print("=" * 60)
        print(f"Total projects: {summary.get('total', 0)}")
        print(f"Successful (real fix): {summary.get('successful', 0)}")
        print(f"Failed: {summary.get('failed', 0)}")
        print(f"Real success rate: {summary.get('success_rate', 0):.1%}")
        print()
        print("Stage completion:")
        for stage, count in summary.get("stages", {}).items():
            print(f"  {stage}: {count}")
        print()
        print("Note: Success means the backported patch passed tests.")
        print("      Completion of all stages does not guarantee success.")
        print("=" * 60)


# =========================================================================
# Convenience Functions
# =========================================================================

def single_process(
    handler_class: Type[BaseManager],
    task: str,
    path: Optional[Path] = None,
    *args,
    **kwargs
) -> Any:
    """
    Run a single task for one or all projects.
    
    Args:
        handler_class: Manager class to use
        task: Method name to call
        path: Optional single project path
        *args: Arguments for the task
        **kwargs: Keyword arguments for the task
        
    Returns:
        Task result(s)
    """
    if path is not None:
        # Single project
        project = Project(path)
        handler = handler_class(project)
        method = getattr(handler, task)
        return method(*args, **kwargs)
    
    # All projects
    pipeline = Pipeline()
    results = []
    
    for project_path in pipeline.get_project_paths():
        logger.info(f"Processing: {project_path}")
        try:
            project = Project(project_path)
            handler = handler_class(project)
            method = getattr(handler, task)
            result = method(*args, **kwargs)
            results.append(result)
        except Exception as e:
            logger.error(f"Error in {project_path}: {e}")
    
    return results


def whole_process(
    path: Optional[Path] = None,
    model: str = "deepseek-api",
    localization_method: str = "history_llm",
) -> None:
    """
    Run complete pipeline.
    
    Args:
        path: Optional single project path
        model: Model to use
        localization_method: Localization method to use (default: "line")
    """
    pipeline = Pipeline()
    
    if path:
        result = pipeline.run_single(path, model, localization_method=localization_method)
        logger.info(f"Result: {result}")
    else:
        results = pipeline.run_all(model, localization_method=localization_method)
        pipeline.print_summary()


# Baseline localization methods
BASELINE_METHODS = {
    "line", "line_log", "history_similarity",
    "direct_llm", "direct_similarity",
    "function", "file", "context", "similarity"
}


def localize(
    model: str = "deepseek-api",
    method: str = "history_llm",
    path: Optional[Path] = None,
) -> None:
    """
    Run localization stage only.
    
    Args:
        model: Model identifier
        method: Localization method to use
            - history_llm: LLM + git history (default, in FaultLocalizer)
            - line: Git blame tracking (baseline)
            - line_log: Git log -L tracking (baseline)
            - history_similarity: Git history + similarity (baseline)
            - direct_llm: Direct LLM matching (baseline)
            - direct_similarity: Direct similarity matching (baseline)
            - function: Function-level (baseline)
            - file: Entire file (baseline)
        path: Optional specific project path
    """
    if method in BASELINE_METHODS:
        # Use baseline localizer
        single_process(BaselineLocalizer, f"localize_{method}", path, model)
    else:
        # Use main localizer for LLM + history
        single_process(FaultLocalizer, "localize_with_history_llm", path, model)


def generate_prompts(
    model: str = "deepseek-api",
    path: Optional[Path] = None,
) -> None:
    """Run prompt generation stage only."""
    single_process(PromptManager, "generate_line_prompts", path, model)


def run_inference(
    model: str = "deepseek-api",
    path: Optional[Path] = None,
) -> None:
    """Run inference stage only."""
    single_process(LLMHandler, "infer_for_model", path, model)


def run_tests(
    model: str = "deepseek-api",
    path: Optional[Path] = None,
) -> None:
    """Run testing stage only."""
    single_process(TestManager, "test_backport", path, model)


def analyze_results(
    model: str = "deepseek-api",
    path: Optional[Path] = None,
) -> None:
    """Run analysis stage only."""
    single_process(ResultAnalyzer, "evaluate_model", path, model)
