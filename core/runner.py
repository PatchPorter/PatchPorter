"""
SCA-Repair Runner API

Provides a concise Python interface for running the tool without using command line.

Quick Start:
    from core.runner import Runner
    
    # Create runner
    runner = Runner()
    
    # Run all projects in batch
    runner.run_all()
    
    # Run a single project
    runner.run_project('/path/to/project')
    
    # Run only localization stage
    runner.run_stage('localize', method='line')
"""

import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

from core import Pipeline, Config, Project
from core.pipeline import (
    localize,
    generate_prompts,
    run_inference,
    run_tests,
    analyze_results,
    PipelineResult,
)
from core.managers import (
    MetaManager,
    FaultLocalizer,
    PromptManager,
    LLMHandler,
    TestManager,
    ResultAnalyzer,
)

logger = logging.getLogger(__name__)


class Runner:
    """
    Unified runner interface
    
    Provides a concise API for running SCA-Repair tool.
    
    Examples:
        >>> runner = Runner()
        >>> runner.run_all(model='deepseek-api')
        >>> runner.run_project('/path/to/project')
        >>> runner.run_stage('localize', method='line')
    """
    
    def __init__(
        self,
        config: Optional[Config] = None,
        log_level: int = logging.INFO,
    ):
        """
        Initialize runner
        
        Args:
            config: Configuration object (None for default)
            log_level: Logging level
        """
        self.config = config or Config()
        self.pipeline = Pipeline()
        
        # Set up logging
        logging.basicConfig(level=log_level)
        logger.setLevel(log_level)
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate configuration"""
        warnings = self.config.validate()
        if warnings:
            logger.warning("Configuration warnings:")
            for warning in warnings:
                logger.warning(f"  {warning}")
    
    # =========================================================================
    # Batch Run
    # =========================================================================
    
    def run_all(
        self,
        model: str = "deepseek-api",
        stages: Optional[List[str]] = None,
        parallel: bool = False,
    ) -> List[PipelineResult]:
        """
        Run all projects (from target-project.txt)
        
        Args:
            model: Model to use
            stages: List of stages to run (None for all)
            parallel: Whether to process in parallel
            
        Returns:
            List of results
            
        Examples:
            >>> runner = Runner()
            >>> results = runner.run_all(model='deepseek-api')
            >>> print(f"Success rate: {sum(r.success for r in results) / len(results)}")
        """
        logger.info(f"Batch processing all projects...")
        logger.info(f"Model: {model}, Stages: {stages or 'all'}")
        
        if parallel:
            results = self.pipeline.run_parallel(model=model, stages=stages)
        else:
            results = self.pipeline.run_all(model=model, stages=stages)
        
        self.pipeline.print_summary()
        return results
    
    def get_project_list(self) -> List[Path]:
        """
        Get list of projects
        
        Returns:
            List of project paths
        """
        return self.pipeline.get_project_paths()
    
    # =========================================================================
    # Single Project Run
    # =========================================================================
    
    def run_project(
        self,
        project_path: str | Path,
        model: str = "deepseek-api",
        stages: Optional[List[str]] = None,
    ) -> PipelineResult:
        """
        Run a single project
        
        Args:
            project_path: Project path
            model: Model to use
            stages: List of stages to run
            
        Returns:
            Execution result
            
        Examples:
            >>> runner = Runner()
            >>> result = runner.run_project(
            ...     '/path/to/project',
            ...     stages=['localize', 'generate']
            ... )
            >>> print(result.success)
        """
        path = Path(project_path)
        
        if not path.exists():
            raise ValueError(f"Project path does not exist: {path}")
        
        logger.info(f"Processing project: {path.name}")
        logger.info(f"Model: {model}, Stages: {stages or 'all'}")
        
        result = self.pipeline.run_single(
            project_path=path,
            model=model,
            stages=stages,
        )
        
        if result.success:
            logger.info(f"SUCCESS - Completed stages: {result.stages_completed}")
        else:
            logger.error(f"FAILED - {result.error}")
        
        return result
    
    # =========================================================================
    # Single Stage Run
    # =========================================================================
    
    def run_stage(
        self,
        stage: str,
        project_path: Optional[str | Path] = None,
        model: str = "deepseek-api",
        method: Optional[str] = None,
    ) -> Any:
        """
        Run a single stage
        
        Args:
            stage: Stage name
                - 'localize': Fault localization
                - 'generate': Generate prompts
                - 'infer': LLM inference
                - 'test': Test validation
                - 'analyze': Result analysis
            project_path: Project path (None for all projects)
            model: Model to use
            method: Localization method (only for localize stage)
            
        Returns:
            Stage execution result
            
        Examples:
            >>> runner = Runner()
            >>> # Run localization on all projects
            >>> runner.run_stage('localize', method='line')
            >>> # Run inference on a single project
            >>> runner.run_stage('infer', project_path='/path/to/project')
        """
        path = Path(project_path) if project_path else None
        
        logger.info(f"Running stage: {stage}")
        if path:
            logger.info(f"Project: {path}")
        else:
            logger.info(f"Processing all projects")
        
        if stage == "localize":
            method = method or "line"
            logger.info(f"Localization method: {method}")
            return localize(model=model, method=method, path=path)
        elif stage == "generate":
            return generate_prompts(model=model, path=path)
        elif stage == "infer":
            return run_inference(model=model, path=path)
        elif stage == "test":
            return run_tests(model=model, path=path)
        elif stage == "analyze":
            return analyze_results(model=model, path=path)
        else:
            raise ValueError(
                f"Unknown stage: {stage}. "
                f"Available stages: localize, generate, infer, test, analyze"
            )
    
    def localize(
        self,
        project_path: Optional[str | Path] = None,
        model: str = "deepseek-api",
        method: str = "line",
    ) -> Any:
        """Fault localization shortcut method"""
        return self.run_stage("localize", project_path, model, method)
    
    def generate(
        self,
        project_path: Optional[str | Path] = None,
        model: str = "deepseek-api",
    ) -> Any:
        """Generate prompts shortcut method"""
        return self.run_stage("generate", project_path, model)
    
    def infer(
        self,
        project_path: Optional[str | Path] = None,
        model: str = "deepseek-api",
    ) -> Any:
        """LLM inference shortcut method"""
        return self.run_stage("infer", project_path, model)
    
    def test(
        self,
        project_path: Optional[str | Path] = None,
        model: str = "deepseek-api",
    ) -> Any:
        """Test validation shortcut method"""
        return self.run_stage("test", project_path, model)
    
    def analyze(
        self,
        project_path: Optional[str | Path] = None,
        model: str = "deepseek-api",
    ) -> Any:
        """Result analysis shortcut method"""
        return self.run_stage("analyze", project_path, model)
    
    # =========================================================================
    # Advanced Interface
    # =========================================================================
    
    def get_project(self, project_path: str | Path) -> Project:
        """
        Get project object
        
        Args:
            project_path: Project path
            
        Returns:
            Project instance
        """
        return Project(Path(project_path))
    
    def get_manager(
        self,
        manager_type: str,
        project_path: str | Path,
    ):
        """
        Get Manager instance
        
        Args:
            manager_type: Manager type
                - 'meta': MetaManager
                - 'localizer': FaultLocalizer
                - 'prompt': PromptManager
                - 'llm': LLMHandler
                - 'test': TestManager
                - 'result': ResultAnalyzer
            project_path: Project path
            
        Returns:
            Manager instance
            
        Examples:
            >>> runner = Runner()
            >>> localizer = runner.get_manager('localizer', '/path/to/project')
            >>> result = localizer.localize_line_based('abc123')
        """
        project = self.get_project(project_path)
        
        managers = {
            "meta": MetaManager,
            "localizer": FaultLocalizer,
            "prompt": PromptManager,
            "llm": LLMHandler,
            "test": TestManager,
            "result": ResultAnalyzer,
        }
        
        manager_class = managers.get(manager_type)
        if not manager_class:
            raise ValueError(
                f"Unknown Manager type: {manager_type}. "
                f"Available types: {', '.join(managers.keys())}"
            )
        
        return manager_class(project)
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get execution summary
        
        Returns:
            Summary statistics
        """
        return self.pipeline.get_summary()
    
    def print_summary(self) -> None:
        """Print execution summary"""
        self.pipeline.print_summary()


# =========================================================================
# Convenience Functions
# =========================================================================

def quick_run(
    project_path: str | Path,
    model: str = "deepseek-api",
) -> PipelineResult:
    """
    Quickly run a single project (complete pipeline)
    
    Args:
        project_path: Project path
        model: Model to use
        
    Returns:
        Execution result
        
    Examples:
        >>> from core.runner import quick_run
        >>> result = quick_run('/path/to/project')
        >>> print(result.success)
    """
    runner = Runner()
    return runner.run_project(project_path, model)


def quick_run_all(model: str = "deepseek-api") -> List[PipelineResult]:
    """
    Quickly run all projects
    
    Args:
        model: Model to use
        
    Returns:
        List of results
        
    Examples:
        >>> from core.runner import quick_run_all
        >>> results = quick_run_all(model='deepseek-api')
        >>> success_rate = sum(r.success for r in results) / len(results)
    """
    runner = Runner()
    return runner.run_all(model)


def quick_stage(
    stage: str,
    project_path: Optional[str | Path] = None,
    model: str = "deepseek-api",
    **kwargs,
) -> Any:
    """
    Quickly run a single stage
    
    Args:
        stage: Stage name
        project_path: Project path (None for all projects)
        model: Model to use
        **kwargs: Additional arguments (e.g., method)
        
    Returns:
        Stage execution result
        
    Examples:
        >>> from core.runner import quick_stage
        >>> # Run localization stage
        >>> quick_stage('localize', method='line')
        >>> # Run inference stage
        >>> quick_stage('infer', project_path='/path/to/project')
    """
    runner = Runner()
    return runner.run_stage(stage, project_path, model, **kwargs)
