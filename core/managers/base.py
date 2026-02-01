"""
Base manager class for SCA-Repair pipeline components.

Provides common interface and functionality for all manager classes.
"""

from abc import ABC, abstractmethod
import logging
from typing import Optional, Any, Dict
from pathlib import Path

from core.project import Project
from core.config import config

logger = logging.getLogger(__name__)


class BaseManager(ABC):
    """
    Abstract base class for all pipeline managers.

    All manager classes should inherit from this base class to ensure
    consistent interface and behavior across the pipeline.

    Attributes:
        project: The Project instance this manager operates on
        config: Global configuration

    Example:
        class MyManager(BaseManager):
            def validate(self) -> bool:
                return self.project.path.exists()

            def execute(self, **kwargs) -> Any:
                # Implementation here
                pass
    """

    def __init__(self, project: Project):
        """
        Initialize the manager with a project.

        Args:
            project: Project instance to operate on
        """
        self._project = project
        self._config = config
        self._logger = logging.getLogger(self.__class__.__name__)

        self._logger.debug(f"Initialized {self.__class__.__name__} for {project}")

    @property
    def project(self) -> Project:
        """Get the associated project."""
        return self._project

    @property
    def project_path(self) -> Path:
        """Shortcut to project path."""
        return self._project.path

    @property
    def npm_project_path(self) -> Path:
        """Shortcut to npm project path."""
        return self._project.npm_project_path

    @abstractmethod
    def validate(self) -> bool:
        """
        Validate preconditions for this manager.

        Returns:
            True if all preconditions are met

        Raises:
            SCARepairError: If validation fails with detailed message
        """
        pass

    @abstractmethod
    def execute(self, **kwargs) -> Any:
        """
        Execute the main task of this manager.

        Args:
            **kwargs: Task-specific arguments

        Returns:
            Task result (type depends on implementation)

        Raises:
            SCARepairError: If execution fails
        """
        pass

    def run(self, **kwargs) -> Any:
        """
        Run the manager with validation.

        This is the main entry point that validates preconditions
        before executing the task.

        Args:
            **kwargs: Arguments passed to execute()

        Returns:
            Result from execute()

        Raises:
            SCARepairError: If validation or execution fails
        """
        self._logger.info(f"Running {self.__class__.__name__}")

        if not self.validate():
            raise RuntimeError(
                f"{self.__class__.__name__} validation failed for {self.project}"
            )

        try:
            result = self.execute(**kwargs)
            self._logger.info(f"{self.__class__.__name__} completed successfully")
            return result
        except Exception as e:
            self._logger.error(f"{self.__class__.__name__} failed: {e}")
            raise

    def get_status(self) -> Dict[str, Any]:
        """
        Get the current status of this manager.

        Returns:
            Dictionary with status information
        """
        return {
            "manager": self.__class__.__name__,
            "project": str(self.project),
            "valid": self.validate(),
        }

    def cleanup(self) -> None:
        """
        Cleanup any resources used by this manager.

        Override this method if the manager creates temporary files
        or other resources that need cleanup.
        """
        pass

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.project})"


class ManagerPipeline:
    """
    Orchestrates multiple managers in a pipeline.

    Example:
        pipeline = ManagerPipeline(project)
        pipeline.add(MetaManager)
        pipeline.add(FaultLocalizer)
        pipeline.add(PromptManager)
        results = pipeline.run_all()
    """

    def __init__(self, project: Project):
        """
        Initialize the pipeline with a project.

        Args:
            project: Project to run the pipeline on
        """
        self.project = project
        self._managers: list = []
        self._results: Dict[str, Any] = {}
        self._logger = logging.getLogger(self.__class__.__name__)

    def add(
        self,
        manager_class: type,
        **init_kwargs,
    ) -> "ManagerPipeline":
        """
        Add a manager to the pipeline.

        Args:
            manager_class: Manager class to instantiate
            **init_kwargs: Additional kwargs for manager init

        Returns:
            Self for chaining
        """
        self._managers.append((manager_class, init_kwargs))
        return self

    def run_all(self, **execute_kwargs) -> Dict[str, Any]:
        """
        Run all managers in the pipeline.

        Args:
            **execute_kwargs: Arguments passed to each manager's execute()

        Returns:
            Dictionary mapping manager names to their results
        """
        self._results = {}

        for manager_class, init_kwargs in self._managers:
            name = manager_class.__name__
            self._logger.info(f"Running pipeline step: {name}")

            try:
                manager = manager_class(self.project, **init_kwargs)
                result = manager.run(**execute_kwargs)
                self._results[name] = {
                    "success": True,
                    "result": result,
                }
            except Exception as e:
                self._logger.error(f"Pipeline step {name} failed: {e}")
                self._results[name] = {
                    "success": False,
                    "error": str(e),
                }
                # Optionally continue or break on error
                break

        return self._results

    def get_results(self) -> Dict[str, Any]:
        """Get results from the last pipeline run."""
        return self._results

    @property
    def success(self) -> bool:
        """Check if all pipeline steps succeeded."""
        return all(r.get("success", False) for r in self._results.values())
