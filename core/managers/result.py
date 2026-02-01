"""
Result Analyzer for SCA-Repair.

Handles evaluation of backporting results and metric calculation.
"""

import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, field

from core.managers.base import BaseManager
from core.project import Project
from core.config import config
from core.utils.file import read_file, read_lines, write_file

logger = logging.getLogger(__name__)


@dataclass
class EvaluationMetrics:
    """Metrics for evaluation."""
    
    total: int = 0
    success: int = 0
    failure: int = 0
    syntax_error: int = 0
    localization_error: int = 0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate."""
        if self.total == 0:
            return 0.0
        return self.success / self.total
    
    @property
    def failure_rate(self) -> float:
        """Calculate failure rate."""
        if self.total == 0:
            return 0.0
        return self.failure / self.total


@dataclass
class ProjectResult:
    """Result for a single project."""
    
    project_id: str
    status: str
    cwe_type: str = ""
    porting_type: str = ""
    
    @property
    def is_success(self) -> bool:
        """Check if result is successful."""
        return self.status in ["True", "Check"]


class ResultAnalyzer(BaseManager):
    """
    Analyzer for backporting results.
    
    Responsibilities:
    - Aggregate results across projects
    - Calculate evaluation metrics
    - Generate analysis reports
    - Compare different approaches
    """
    
    def __init__(self, project: Project):
        """Initialize ResultAnalyzer."""
        super().__init__(project)
        
        self._result_path = self.project.result_path
        self._model_list = config.llm.api_models + config.llm.local_models[:3]
    
    def validate(self) -> bool:
        """Validate that results exist."""
        return self._result_path.exists()
    
    def execute(self, **kwargs) -> Any:
        """Execute analysis."""
        model = kwargs.get("model")
        if model:
            return self.evaluate_model(model)
        return self.evaluate_all()
    
    # =========================================================================
    # Model Evaluation
    # =========================================================================
    
    def evaluate_model(self, model: str) -> EvaluationMetrics:
        """
        Evaluate results for a specific model.
        
        Args:
            model: Model identifier
            
        Returns:
            EvaluationMetrics for the model
        """
        # Result file format: {model}-result.txt
        # This remains unchanged as it's already model-specific
        result_file = self._result_path / f"{model}-result.txt"
        
        if not result_file.exists():
            logger.warning(f"Result file not found: {result_file}")
            return EvaluationMetrics()
        
        metrics = EvaluationMetrics()
        
        try:
            lines = read_lines(result_file, skip_empty=True)
        except Exception:
            return metrics
        
        for line in lines:
            if model not in line:
                continue
            
            metrics.total += 1
            
            if "True" in line:
                metrics.success += 1
            elif "False#0" in line:
                metrics.failure += 1
            elif "False#1" in line:
                metrics.syntax_error += 1
            elif "False#3" in line:
                metrics.localization_error += 1
            else:
                metrics.failure += 1
        
        return metrics
    
    def evaluate_all(self) -> Dict[str, EvaluationMetrics]:
        """
        Evaluate results for all models.
        
        Returns:
            Dictionary mapping model names to metrics
        """
        results = {}
        
        for model in self._model_list:
            metrics = self.evaluate_model(model)
            if metrics.total > 0:
                results[model] = metrics
                logger.info(
                    f"{model}: {metrics.success}/{metrics.total} "
                    f"({metrics.success_rate:.2%})"
                )
        
        return results
    
    # =========================================================================
    # Aggregate Analysis
    # =========================================================================
    
    @staticmethod
    def aggregate_json_results(
        project_paths: List[Path],
        output_file: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """
        Aggregate JSON results from multiple projects.
        
        Args:
            project_paths: List of project directory paths
            output_file: Optional output file for aggregated results
            
        Returns:
            Aggregated statistics
        """
        all_results = []
        
        for project_path in project_paths:
            result_dir = project_path / "result"
            if not result_dir.exists():
                continue
            
            # Find all JSON result files
            for json_file in result_dir.glob("*-result.json"):
                try:
                    from core.utils.file import read_json
                    result_data = read_json(json_file)
                    result_data["project_path"] = str(project_path)
                    
                    # Handle new format with test_history
                    if "test_history" in result_data:
                        # Use the latest test result
                        latest_test = result_data["test_history"][-1]
                        # Merge metadata with latest test
                        merged_result = {
                            "project_id": result_data["project_id"],
                            "package_name": result_data.get("package_name"),
                            "customization": result_data.get("customization"),
                            "localization_method": result_data.get("localization_method"),
                            "model": result_data.get("model"),
                            "version": latest_test["version"],
                            "result": latest_test["result"],
                            "success": latest_test["success"],
                            "timestamp": latest_test["timestamp"],
                            "target_commit": latest_test.get("target_commit"),
                            "patch_commit": latest_test.get("patch_commit"),
                            "error_type": latest_test.get("error_type"),
                            "total_tests": result_data.get("total_tests", 1),
                            "success_count": result_data.get("success_count", 1),
                            "project_path": str(project_path),
                        }
                        all_results.append(merged_result)
                    else:
                        # Old format - single test
                        all_results.append(result_data)
                        
                except Exception as e:
                    logger.warning(f"Failed to read {json_file}: {e}")
        
        # Calculate statistics
        stats = ResultAnalyzer._calculate_aggregate_stats(all_results)
        
        # Save if output file specified
        if output_file:
            from core.utils.file import write_json
            write_json(output_file, {
                "total_projects": len(set(r["project_id"] for r in all_results)),
                "total_tests": len(all_results),
                "statistics": stats,
                "results": all_results,
            })
            logger.info(f"Saved aggregated results to {output_file}")
        
        return stats
    
    @staticmethod
    def _calculate_aggregate_stats(results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate aggregate statistics from results."""
        if not results:
            return {}
        
        # Group by configuration
        by_config = defaultdict(list)
        for r in results:
            # Get configuration info, with fallbacks for older formats
            customization = r.get('customization', 'unknown')
            localization = r.get('localization_method', 'unknown')
            model = r.get('model', 'unknown')
            key = f"{customization}@{localization}-{model}"
            by_config[key].append(r)
        
        # Calculate stats for each configuration
        config_stats = {}
        for config, config_results in by_config.items():
            total = len(config_results)
            success = sum(1 for r in config_results if r.get('success', False))
            
            config_stats[config] = {
                "total": total,
                "success": success,
                "failure": total - success,
                "success_rate": success / total if total > 0 else 0,
                "projects": list(set(r.get("project_id", "unknown") for r in config_results)),
            }
        
        # Overall stats
        total = len(results)
        success = sum(1 for r in results if r.get('success', False))
        
        return {
            "overall": {
                "total": total,
                "success": success,
                "failure": total - success,
                "success_rate": success / total if total > 0 else 0,
            },
            "by_configuration": config_stats,
        }
    
    @staticmethod
    def count_results(
        result_path: Path,
        model: str,
    ) -> Tuple[int, int]:
        """
        Count success and total results for a model.
        
        Args:
            result_path: Path to result file
            model: Model identifier
            
        Returns:
            Tuple of (success_count, total_count)
        """
        try:
            lines = read_lines(result_path, skip_empty=True)
        except Exception:
            return 0, 0
        
        # Filter lines for this model
        lines = [
            line for line in lines
            if model in line or len(line.split(" ")) == 2
        ]
        
        total = len(lines)
        success = len([l for l in lines if "True" in l])
        
        return success, total
    
    @staticmethod
    def get_effectiveness_results(result_file: Path) -> Dict[str, ProjectResult]:
        """
        Parse effectiveness results from file.
        
        Args:
            result_file: Path to result file
            
        Returns:
            Dictionary mapping project IDs to results
        """
        type_dict = ResultAnalyzer._get_porting_type_info()
        results = {}
        
        try:
            content = read_file(result_file)
        except Exception:
            return results
        
        lines = [l.strip() for l in content.split("\n") if l.strip()]
        
        for i in range(0, len(lines) - 1, 2):
            if i + 1 >= len(lines):
                break
            
            path_line = lines[i]
            status_line = lines[i + 1]
            
            pkg_name = path_line.split("/")[-1]
            cwe_type = path_line.split("/")[-2]
            status = status_line.split(" ")[0]
            
            results[pkg_name] = ProjectResult(
                project_id=pkg_name,
                status=status,
                cwe_type=cwe_type,
                porting_type=type_dict.get(pkg_name, ""),
            )
        
        return results
    
    @staticmethod
    def _get_porting_type_info() -> Dict[str, str]:
        """Load porting type information from file."""
        type_file = Path("./patches/record.txt")
        type_dict = {}
        
        if not type_file.exists():
            return type_dict
        
        try:
            lines = read_lines(type_file, skip_empty=True)
            for line in lines:
                parts = line.split(",")
                if len(parts) == 2:
                    type_dict[parts[0]] = parts[1]
        except Exception:
            pass
        
        return type_dict
    
    # =========================================================================
    # Comparison Analysis
    # =========================================================================
    
    @staticmethod
    def compare_methods(
        result_files: Dict[str, Path],
    ) -> Dict[str, Dict[str, float]]:
        """
        Compare multiple methods/models.
        
        Args:
            result_files: Dictionary mapping method names to result file paths
            
        Returns:
            Comparison metrics
        """
        comparisons = {}
        
        for method, path in result_files.items():
            results = ResultAnalyzer.get_effectiveness_results(path)
            
            success_count = sum(1 for r in results.values() if r.is_success)
            total_count = len(results)
            
            comparisons[method] = {
                "success": success_count,
                "total": total_count,
                "rate": success_count / total_count if total_count > 0 else 0,
            }
        
        return comparisons
    
    @staticmethod
    def analyze_by_category(
        results: Dict[str, ProjectResult],
        category_key: str = "cwe_type",
    ) -> Dict[str, EvaluationMetrics]:
        """
        Analyze results grouped by category.
        
        Args:
            results: Dictionary of project results
            category_key: Category to group by ('cwe_type' or 'porting_type')
            
        Returns:
            Metrics by category
        """
        by_category = defaultdict(EvaluationMetrics)
        
        for result in results.values():
            if category_key == "cwe_type":
                category = result.cwe_type
            else:
                category = result.porting_type
            
            by_category[category].total += 1
            if result.is_success:
                by_category[category].success += 1
            else:
                by_category[category].failure += 1
        
        return dict(by_category)
    
    # =========================================================================
    # Report Generation
    # =========================================================================
    
    def generate_report(
        self,
        output_path: Optional[Path] = None,
    ) -> str:
        """
        Generate a summary report.
        
        Args:
            output_path: Optional path to save report
            
        Returns:
            Report as string
        """
        lines = [
            "=" * 60,
            "SCA-Repair Evaluation Report",
            "=" * 60,
            "",
            f"Project: {self.project.project_id}",
            f"CVE: {self.project.cve_id or 'N/A'}",
            "",
            "-" * 40,
            "Results by Model:",
            "-" * 40,
        ]
        
        all_metrics = self.evaluate_all()
        
        for model, metrics in sorted(all_metrics.items()):
            lines.append(
                f"  {model:30s}: {metrics.success}/{metrics.total} "
                f"({metrics.success_rate:.1%})"
            )
        
        lines.extend([
            "",
            "=" * 60,
        ])
        
        report = "\n".join(lines)
        
        if output_path:
            write_file(output_path, report)
        
        return report


# =========================================================================
# Standalone Analysis Functions
# =========================================================================

def count_file_accuracy(key: str, result_file: str = "./case-analysis/result.txt") -> float:
    """
    Count accuracy for a specific method from aggregated results.
    
    Args:
        key: Method/model key to filter
        result_file: Path to result file
        
    Returns:
        Accuracy rate
    """
    try:
        lines = read_lines(Path(result_file), skip_empty=True)
    except Exception:
        return 0.0
    
    true_count = 0
    total_count = 0
    
    for line in lines:
        if key in line:
            total_count += 1
            if "True" in line:
                true_count += 1
    
    if total_count == 0:
        return 0.0
    
    return true_count / total_count


def case_study(file_path: Path) -> None:
    """
    Sort case study results by success/failure.
    
    Args:
        file_path: Path to case analysis file
    """
    import ast
    
    try:
        lines = read_lines(file_path, skip_empty=True)
    except Exception:
        return
    
    true_cases = []
    false_cases = []
    
    for line in lines:
        try:
            item = ast.literal_eval(line)
            if item[1]:
                true_cases.append(item)
            else:
                false_cases.append(item)
        except Exception:
            continue
    
    true_cases.sort(key=lambda x: x[0])
    false_cases.sort(key=lambda x: x[0])
    
    with open(file_path, "w") as f:
        for item in true_cases:
            print(item, file=f)
        for item in false_cases:
            print(item, file=f)


def evaluation() -> None:
    """Run full evaluation across all methods and models."""
    model_list = ["deepseek-api"]
    method_list = ["file", "similarity", "history"]
    
    results = []
    
    for method in method_list:
        for model in model_list:
            key = f"{model} {method}"
            accuracy = count_file_accuracy(key)
            results.append((method, model, accuracy))
    
    results.sort(key=lambda x: x[2])
    
    for method, model, accuracy in results:
        print(f"{method:15s} {model:20s}: {accuracy:.2%}")


def get_duplicated_packages(data_file: str = "data/target-project.txt") -> List[str]:
    """Find packages that appear more than once in the dataset."""
    try:
        lines = read_lines(Path(data_file), skip_empty=True)
    except Exception:
        return []
    
    package_names = [
        line.split("/")[-1].split("_")[0]
        for line in lines
    ]
    
    counts = Counter(package_names)
    return [pkg for pkg, count in counts.items() if count >= 2]
