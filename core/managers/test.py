"""
Test Manager for SCA-Repair.

Handles patch application testing and result validation.
"""

import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

from core.managers.base import BaseManager
from core.project import Project
from core.config import config
from core.utils.command import run_command
from core.utils.file import (
    read_file,
    read_lines,
    write_file,
    read_json,
    write_json,
    ensure_directory,
)
from core.utils.git import checkout_commit
from core.exceptions import TestExecutionError

logger = logging.getLogger(__name__)


class TestResult:
    """Result of a test execution."""
    
    # Result codes
    TRUE = "True"           # PoC failed to trigger (SUCC - vuln fixed)
    FALSE_PASS = "False#0"  # PoC succeeded (FAIL - vuln still exists)
    FALSE_SYNTAX = "False#1"  # Syntax error in generated code (FAILURE)
    FALSE_UNDEFINED = "False#2"  # Reference error (undefined) (FAILURE)
    FALSE_LOCALIZATION = "False#3"  # Localization failed (FAILURE)
    FALSE_TOO_LONG = "False#4"  # File too long (FAILURE)
    CHECK = "Check"         # Needs manual verification
    
    @staticmethod
    def is_success(result: str) -> bool:
        """Check if result indicates successful backport."""
        # SUCCESS: True means PoC failed to trigger vulnerability (patch worked)
        return result == TestResult.TRUE
    
    @staticmethod
    def is_failure(result: str) -> bool:
        """Check if result indicates failed backport."""
        # FAILURE: False#X (PoC passed or errors) or Check (needs verification)
        return result != TestResult.TRUE


class TestManager(BaseManager):
    """
    Manager for testing backported patches.
    
    Responsibilities:
    - Apply generated patches to target versions
    - Run Jest tests to validate patches
    - Collect and report test results
    - Handle various failure modes
    """
    
    def __init__(self, project: Project):
        """Initialize TestManager."""
        super().__init__(project)
        
        self._prompt_path = self.project.prompt_path
        self._result_path = self.project.result_path
        self._output_path = self.project_path / "output-result"
        self._target_file_name = self.project.target_file_name
        self._patch_path = self.project.final_patch_path
        
        ensure_directory(self._result_path)
        ensure_directory(self._output_path)
    
    def validate(self) -> bool:
        """Validate that project is ready for testing."""
        return (
            self._prompt_path.exists()
            and self.project.npm_project_path.exists()
        )
    
    def execute(self, **kwargs) -> Any:
        """Execute testing for a model."""
        model = kwargs.get("model", "deepseek-api")
        customization = kwargs.get("customization", None)
        method = kwargs.get("method", None)
        timing_info = kwargs.get("timing_info", None)
        return self.test_backport(model, customization=customization, method=method, timing_info=timing_info)
    
    # =========================================================================
    # Backport Testing
    # =========================================================================
    
    def test_backport(
        self, 
        model: str,
        customization: Optional[str] = None,
        method: Optional[str] = None,
        timing_info: Optional[Dict[str, float]] = None,
    ) -> Dict[str, str]:
        """
        Test backported patches for a specific model.
        
        Args:
            model: Model identifier
            customization: Customization method (e.g., 'dynamic', 'fixed', 'file')
            method: Localization method (e.g., 'history_llm', 'line', 'function')
            timing_info: Dict with timing and token statistics
            
        Returns:
            Dictionary mapping versions to test results
        """
        results = {}
        challenge_version = self.project.get_challenge_version()
        
        # Build glob pattern based on configuration
        if customization and method:
            # Support both with and without model name in filename
            # Try model-specific file first, then fall back to generic
            if model != "deepseek-api":
                pattern_with_model = f"{customization}@{method}-{model}.json"
                files_with_model = list(self._prompt_path.glob(pattern_with_model))
                if files_with_model:
                    prompt_files = files_with_model
                else:
                    # Fall back to generic pattern
                    pattern = f"{customization}@{method}.json"
                    prompt_files = list(self._prompt_path.glob(pattern))
            else:
                pattern = f"{customization}@{method}.json"
                prompt_files = list(self._prompt_path.glob(pattern))
        else:
            # Test all prompts (legacy behavior)
            pattern = "*.json"
            prompt_files = list(self._prompt_path.glob(pattern))
        
        for prompt_file in prompt_files:
            # New format: {customization}@{method}.json
            # Check if model output exists in the file
            output_key = f"{model}-output"
            try:
                json_content = read_json(prompt_file)
                if output_key not in json_content:
                    continue
            except Exception:
                continue
            
            logger.info(f"Testing prompt file: {prompt_file.name}")
            
            try:
                # Test and get detailed result
                result_data = self._test_single_prompt_detailed(prompt_file, model, timing_info)
                if result_data:
                    version = result_data["version"]
                    status = result_data["result"]
                    results[version] = status
                    
                    # Save to individual JSON file: {prompt_name}[-{model}]-result.json
                    # Include model name if it's not already in prompt file name
                    prompt_stem = prompt_file.stem
                    if f"-{model}" not in prompt_stem and model != "deepseek-api":
                        result_json = self._result_path / f"{prompt_stem}-{model}-result.json"
                    else:
                        result_json = self._result_path / f"{prompt_stem}-result.json"
                    self._append_test_result(result_json, result_data)
                    
                    logger.info(f"Saved result: {result_json.name} -> {status}")
            except Exception as e:
                logger.error(f"Error testing {prompt_file}: {e}")
                continue
        
        return results
    
    def _test_single_prompt_detailed(
        self,
        prompt_file: Path,
        model: str,
        timing_info: Optional[Dict[str, float]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Test a single prompt file and return detailed results.
        
        Args:
            prompt_file: Path to prompt JSON file
            model: Model identifier
            timing_info: Dict with timing and token statistics
            
        Returns:
            Dictionary with detailed test results or None
        """
        from datetime import datetime
        
        try:
            json_content = read_json(prompt_file)
        except Exception as e:
            logger.error(f"Failed to read {prompt_file}: {e}")
            return None
        
        version = json_content.get("version")
        commit_id = self.project.find_commit_by_version(version)
        
        if not commit_id:
            logger.warning(f"Could not find commit for version {version}")
            return None
        
        # Get target file path
        target_file_name = self.project.get_responding_file_name(commit_id)
        if not target_file_name:
            return self._create_result_record(
                prompt_file, model, version, commit_id,
                TestResult.FALSE_LOCALIZATION, "", "Localization failed"
            )
        
        target_file_path = self.project.npm_project_path / target_file_name
        
        # Checkout version
        self.project.checkout(commit_id)
        
        # Check for model output
        output_key = f"{model}-output"
        if output_key not in json_content:
            logger.warning(f"No output for {model} in {prompt_file}")
            self.project.checkout(".")
            return None
        
        # Apply the backported code
        success = self._apply_backport(
            json_content,
            target_file_path,
            model,
        )
        
        logger.debug(f"Backport apply success: {success}")
        
        if not success:
            self.project.checkout(".")
            return self._create_result_record(
                prompt_file, model, version, commit_id,
                TestResult.FALSE_SYNTAX, "", "Syntax error in generated code"
            )
        
        # Run tests and capture output
        # Run jest in the project root (not in node_modules) to find test files
        jest_cmd_result = run_command(
            f"timeout 40s jest --testPathIgnorePatterns=\"node_modules\" --forceExit",
            path=self.project_path,  # Use project root, not npm_project_path
        )
        
        logger.debug(f"Jest command result type: {type(jest_cmd_result)}")
        logger.debug(f"Jest command result: {jest_cmd_result}")
        
        # Get result tag based on output (same logic as project.run_jest)
        stderr = jest_cmd_result.stderr if jest_cmd_result is not None else ""
        stdout = jest_cmd_result.stdout if jest_cmd_result is not None else ""
        
        logger.debug(f"Jest stdout length: {len(stdout)}")
        logger.debug(f"Jest stderr length: {len(stderr)}")
        
        # Determine result based on jest output
        if "Received" in stderr and "Expected" in stderr:
            jest_result = "True"
        elif "PASS" in stderr:
            jest_result = "False#0"
        elif any(pattern in stderr for pattern in config.test.syntax_error_patterns):
            jest_result = "False#1"
        else:
            jest_result = "Check"
        
        # Combine stdout and stderr for complete output (no truncation)
        jest_output = ""
        if stdout:
            jest_output += f"=== STDOUT ===\n{stdout}\n\n"
        if stderr:
            jest_output += f"=== STDERR ===\n{stderr}"
        
        logger.debug(f"Jest output length after combination: {len(jest_output)}")
        logger.debug(f"Jest output preview: {jest_output[:200]}")
        
        # Save output file matching prompt naming: {prompt_name}[-{model}]-result.js
        prompt_stem = prompt_file.stem
        if f"-{model}" not in prompt_stem and model != "deepseek-api":
            output_file = self._output_path / f"{prompt_stem}-{model}-result.js"
        else:
            output_file = self._output_path / f"{prompt_stem}-result.js"
        run_command(f"cp {target_file_path} {output_file}")
        
        # Restore original state
        self.project.checkout(".")
        
        # Determine error type
        error_type = None
        if jest_result.startswith("False"):
            error_type = jest_result
        
        # Create detailed result record with timing info
        return self._create_result_record(
            prompt_file, model, version, commit_id,
            jest_result, jest_output, error_type, timing_info
        )
    
    def _append_test_result(
        self,
        result_file: Path,
        new_result: Dict[str, Any],
    ) -> None:
        """
        Append test result to history file.
        
        Args:
            result_file: Path to result JSON file
            new_result: New test result to append
        """
        # Read existing results
        if result_file.exists():
            try:
                existing_data = read_json(result_file)
                # Ensure test_history exists
                if "test_history" not in existing_data:
                    # Convert old format to new format
                    existing_data = {
                        "project_id": existing_data.get("project_id"),
                        "package_name": existing_data.get("package_name"),
                        "customization": existing_data.get("customization"),
                        "localization_method": existing_data.get("localization_method"),
                        "model": existing_data.get("model"),
                        "test_history": [
                            {
                                "version": existing_data.get("version"),
                                "result": existing_data.get("result"),
                                "success": existing_data.get("success"),
                                "timestamp": existing_data.get("timestamp"),
                                "target_commit": existing_data.get("target_commit"),
                                "patch_commit": existing_data.get("patch_commit"),
                                "jest_output": existing_data.get("jest_output"),
                                "error_type": existing_data.get("error_type"),
                            }
                        ]
                    }
            except Exception as e:
                logger.warning(f"Failed to read existing results: {e}")
                existing_data = None
        else:
            existing_data = None
        
        # Create new structure
        if existing_data:
            # Append to existing history - preserve all fields including timing/tokens
            existing_data["test_history"].append(new_result)
            
            # Update metadata
            existing_data["last_test"] = new_result["timestamp"]
            existing_data["total_tests"] = len(existing_data["test_history"])
            existing_data["success_count"] = sum(
                1 for t in existing_data["test_history"] if t["success"]
            )
        else:
            # Create new structure - preserve all fields including timing/tokens
            existing_data = {
                "project_id": new_result["project_id"],
                "package_name": new_result["package_name"],
                "customization": new_result["customization"],
                "localization_method": new_result["localization_method"],
                "model": new_result["model"],
                "test_history": [new_result],
                "last_test": new_result["timestamp"],
                "total_tests": 1,
                "success_count": 1 if new_result["success"] else 0,
            }
        
        # Save updated data
        write_json(result_file, existing_data)
    
    def _test_single_prompt_with_details(
        self,
        prompt_file: Path,
        model: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Test a single prompt file and return detailed results.
        
        Args:
            prompt_file: Path to prompt JSON file
            model: Model identifier
            
        Returns:
            Dictionary with detailed test results
        """
        start_time = datetime.now()
        
        try:
            json_content = read_json(prompt_file)
        except Exception as e:
            logger.error(f"Failed to read {prompt_file}: {e}")
            return None
        
        version = json_content.get("version")
        commit_id = self.project.find_commit_by_version(version)
        
        if not commit_id:
            logger.warning(f"Could not find commit for version {version}")
            return None
        
        # Parse prompt file name: {customization}@{method}.json
        file_parts = prompt_file.stem.split("@")
        customization_method = file_parts[0] if len(file_parts) > 0 else "unknown"
        localization_method = file_parts[1] if len(file_parts) > 1 else "unknown"
        
        # Get target file path
        target_file_name = self.project.get_responding_file_name(commit_id)
        if not target_file_name:
            return self._create_test_record(
                prompt_file.name,
                customization_method,
                localization_method,
                model,
                version,
                commit_id,
                TestResult.FALSE_LOCALIZATION,
                start_time,
                error_msg="Target file not found"
            )
        
        target_file_path = self.project.npm_project_path / target_file_name
        
        # Checkout version
        self.project.checkout(commit_id)
        
        # Check for model output
        output_key = f"{model}-output"
        if output_key not in json_content:
            logger.warning(f"No output for {model} in {prompt_file}")
            return None
        
        # Apply the backported code
        success = self._apply_backport(
            json_content,
            target_file_path,
            model,
        )
        
        if not success:
            self.project.checkout(".")
            return self._create_test_record(
                prompt_file.name,
                customization_method,
                localization_method,
                model,
                version,
                commit_id,
                TestResult.FALSE_SYNTAX,
                start_time,
                error_msg="Failed to apply backport"
            )
        
        # Run tests
        result = self.project.run_jest()
        
        # Save output file
        prompt_stem = prompt_file.stem
        output_file = self._output_path / f"{prompt_stem}-{model}-result.js"
        run_command(f"cp {target_file_path} {output_file}")
        
        # Restore original state
        self.project.checkout(".")
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        return self._create_test_record(
            prompt_file.name,
            customization_method,
            localization_method,
            model,
            version,
            commit_id,
            result,
            start_time,
            end_time=end_time,
            duration=duration,
            output_file=output_file.name
        )
    
    def _create_test_record(
        self,
        prompt_file: str,
        customization_method: str,
        localization_method: str,
        model: str,
        version: str,
        commit_id: str,
        status: str,
        start_time: datetime,
        end_time: Optional[datetime] = None,
        duration: Optional[float] = None,
        output_file: Optional[str] = None,
        error_msg: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a structured test record."""
        record = {
            "prompt_file": prompt_file,
            "customization_method": customization_method,
            "localization_method": localization_method,
            "model": model,
            "version": version,
            "commit_id": commit_id,
            "status": status,
            "success": TestResult.is_success(status),
            "timestamp": start_time.isoformat(),
        }
        
        if end_time:
            record["end_time"] = end_time.isoformat()
        if duration is not None:
            record["duration_seconds"] = round(duration, 2)
        if output_file:
            record["output_file"] = output_file
        if error_msg:
            record["error"] = error_msg
        
        return record
    
    def _save_json_results(
        self,
        test_records: List[Dict[str, Any]],
        result_file: Path,
        model: str,
    ) -> None:
        """
        Save test results in structured JSON format.
        
        Args:
            test_records: List of test record dictionaries
            result_file: Path to JSON result file
            model: Model identifier
        """
        if not test_records:
            return
        
        # Calculate summary statistics
        total_tests = len(test_records)
        successful = sum(1 for r in test_records if r["success"])
        failed = total_tests - successful
        
        # Group by status
        status_counts = {}
        for record in test_records:
            status = record["status"]
            status_counts[status] = status_counts.get(status, 0) + 1
        
        # Group by method combination
        method_stats = {}
        for record in test_records:
            key = f"{record['customization_method']}@{record['localization_method']}"
            if key not in method_stats:
                method_stats[key] = {"total": 0, "success": 0, "failed": 0}
            method_stats[key]["total"] += 1
            if record["success"]:
                method_stats[key]["success"] += 1
            else:
                method_stats[key]["failed"] += 1
        
        # Create full result structure
        result_data = {
            "project_id": self.project.project_id,
            "project_path": str(self.project_path),
            "package_name": self.project.name,
            "package_version": self.project.version,
            "challenge_version": self.project.get_challenge_version(),
            "model": model,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_tests": total_tests,
                "successful": successful,
                "failed": failed,
                "success_rate": round(successful / total_tests, 4) if total_tests > 0 else 0,
                "status_counts": status_counts,
                "method_statistics": method_stats,
            },
            "test_results": test_records,
        }
        
        write_json(result_file, result_data)
        logger.info(f"Saved detailed results to {result_file}")
    
    def _create_result_record(
        self,
        prompt_file: Path,
        model: str,
        version: str,
        commit_id: str,
        result: str,
        jest_output: str,
        error_type: Optional[str] = None,
        timing_info: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """
        Create a structured result record.
        
        Args:
            prompt_file: Path to prompt file
            model: Model identifier
            version: Target version
            commit_id: Target commit ID
            result: Test result (True/False#X)
            jest_output: Raw jest output
            error_type: Error type if failed
            timing_info: Dict with timing and token statistics
            
        Returns:
            Structured result dictionary
        """
        from datetime import datetime
        
        # Parse prompt file name to get customization and localization method
        prompt_stem = prompt_file.stem
        parts = prompt_stem.split("@")
        customization = parts[0] if len(parts) > 0 else "unknown"
        localization_method = parts[1] if len(parts) > 1 else "unknown"
        
        record = {
            "project_id": str(self.project.project_id),
            "package_name": self.project.name,
            "version": version,
            "customization": customization,
            "localization_method": localization_method,
            "model": model,
            "result": result,
            "success": TestResult.is_success(result),  # Use correct success check
            "timestamp": datetime.now().isoformat(),
            "target_commit": commit_id,
            "patch_commit": self.project.patch_commit_id,
            "jest_output": jest_output[:10000] if jest_output else "",  # Increased limit for full test output
            "error_type": error_type,
        }
        
        # Add timing and token information if available
        if timing_info:
            record["timing"] = {
                "localization_seconds": timing_info.get('localization_time', 0),
                "prompt_generation_seconds": timing_info.get('prompt_time', 0),
                "inference_seconds": timing_info.get('inference_time', 0),
                "total_seconds": (
                    timing_info.get('localization_time', 0) +
                    timing_info.get('prompt_time', 0) +
                    timing_info.get('inference_time', 0)
                ),
            }
            record["tokens"] = {
                "total_tokens": timing_info.get('inference_tokens', 0),
            }
        
        return record
    
    def _apply_backport(
        self,
        json_content: Dict[str, Any],
        target_file_path: Path,
        model: str,
    ) -> bool:
        """
        Apply backported code to target file.
        
        Args:
            json_content: Parsed prompt JSON
            target_file_path: Path to target file
            model: Model identifier
            
        Returns:
            True if successful
        """
        output_key = f"{model}-output"
        prompts = json_content.get("prompt", [])
        outputs = json_content.get(output_key, [])
        
        if len(prompts) != len(outputs):
            logger.warning("Prompt/output count mismatch")
            return False
        
        # Sort by line number (descending) to avoid offset issues
        indexed = []
        for i, prompt_item in enumerate(prompts):
            line_list = prompt_item.get("line", [0])
            # Handle empty line list (for additions without specific line numbers)
            line = line_list[0] if line_list else -1
            indexed.append((line, i))
        indexed.sort(reverse=True)
        
        try:
            target_content = read_file(target_file_path)
        except Exception as e:
            logger.error(f"Could not read target file: {e}")
            return False
        
        for line_num, idx in indexed:
            output = outputs[idx]
            context = prompts[idx].get("context", "")
            
            # Filter LLM output
            filtered_output = self._filter_llm_output(output)
            
            # Heuristic post-processing: if context ends with newline, ensure filtered_output also ends with newline
            # This prevents LLM generated code from merging with the next line
            if context and context.endswith('\n') and not filtered_output.endswith('\n'):
                filtered_output += '\n'
            
            if context and target_content.count(context) == 1:
                target_content = target_content.replace(context, filtered_output)
            elif line_num == -1 and context:
                # Special handling for end-of-file
                # Try to match without trailing newline if file doesn't end with one
                context_stripped = context.rstrip('\n')
                if not target_content.endswith('\n') and context.endswith('\n'):
                    # File doesn't end with newline, but context does
                    # Append at the end preserving structure
                    if target_content.endswith(context_stripped):
                        # Replace the last occurrence and add proper spacing
                        target_content = (
                            target_content[:-len(context_stripped)] +
                            context_stripped + '\n' +  # Keep original closing with newline
                            filtered_output
                        )
                    else:
                        logger.warning(f"Context mismatch at EOF: expected {repr(context_stripped)}, got {repr(target_content[-20:])}")
                else:
                    # Use last occurrence
                    last_index = target_content.rfind(context)
                    if last_index != -1:
                        target_content = (
                            target_content[:last_index] +
                            filtered_output +
                            target_content[last_index + len(context):]
                        )
                    else:
                        logger.warning(f"Context not found for line -1: {context[:50]}")
            else:
                # Handle multiple occurrences
                target_content = self._replace_nearest(
                    target_content,
                    line_num,
                    context,
                    filtered_output,
                )
        
        try:
            write_file(target_file_path, target_content)
            return True
        except Exception as e:
            logger.error(f"Could not write target file: {e}")
            return False
    
    # =========================================================================
    # Baseline Testing
    # =========================================================================
    
    def test_baseline(
        self,
        baseline: str,
        baseline_file: Path,
    ) -> Optional[str]:
        """
        Test a baseline approach.
        
        Args:
            baseline: Baseline identifier
            baseline_file: Path to baseline results JSON
            
        Returns:
            Test result string
        """
        baseline_data = self._get_baseline_result(baseline_file)
        if not baseline_data:
            return "CompilationError"
        
        target_before, target_after = baseline_data
        if not target_before:
            return "CompilationError"
        
        # Filter output
        if "```" in target_after:
            target_after = target_after[:target_after.find("```")]
        
        # Get challenge commit
        challenge_commit = self.project.get_challenge_commit()
        target_file_name = self.project.get_responding_file_name(challenge_commit)
        target_file_path = self.project.npm_project_path / target_file_name
        
        # Apply baseline
        self.project.checkout(challenge_commit)
        self._apply_baseline_replacement(
            target_before,
            target_after,
            target_file_path,
        )
        
        result = self.project.run_jest()
        
        # Save output
        output_file = self._output_path / f"{baseline}-result.js"
        run_command(f"cp {target_file_path} {output_file}")
        
        self.project.checkout(".")
        
        return result
    
    def _get_baseline_result(
        self,
        baseline_file: Path,
    ) -> Optional[Tuple[str, str]]:
        """Get baseline results for this project."""
        try:
            json_content = read_json(baseline_file)
        except Exception:
            return None
        
        project_id = self.project.project_id
        
        for key, value in json_content.items():
            if project_id in key:
                return (
                    value.get("target_before"),
                    value.get("target_after"),
                )
        
        return None
    
    def _apply_baseline_replacement(
        self,
        target_before: str,
        target_after: str,
        target_file_path: Path,
    ) -> None:
        """Apply baseline replacement to file."""
        try:
            content = read_file(target_file_path)
            content = content.replace(target_before, target_after)
            write_file(target_file_path, content)
        except Exception as e:
            logger.error(f"Baseline replacement failed: {e}")
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    @staticmethod
    def _filter_llm_output(content: str) -> str:
        """
        Filter LLM output to extract code.
        
        Removes markdown code blocks and other formatting.
        
        Args:
            content: Raw LLM output
            
        Returns:
            Cleaned code content
        """
        left_index = content.find("```")
        if left_index == -1:
            return content
        
        # Skip language identifier
        if content[left_index:left_index + len("```javascript")] == "```javascript":
            left_index += len("```javascript")
        else:
            left_index += len("```")
        
        content = content[left_index:]
        
        right_index = content.rfind("```")
        if right_index == -1:
            return content
        
        # Only remove blank lines at both ends, keep newlines in content
        # This preserves the original code structure
        return content[:right_index].strip('\n')
    
    @staticmethod
    def _replace_nearest(
        content: str,
        target_line: int,
        old_text: str,
        new_text: str,
    ) -> str:
        """
        Replace text occurrence nearest to target line.
        
        Args:
            content: Full file content
            target_line: Target line number
            old_text: Text to replace
            new_text: Replacement text
            
        Returns:
            Modified content
        """
        # Find all occurrences
        indices = []
        search_start = 0
        
        while True:
            idx = content.find(old_text, search_start)
            if idx == -1:
                break
            indices.append(idx)
            search_start = idx + 1
        
        if not indices:
            return content
        
        # Find nearest to target line
        line_distances = [
            abs(target_line - content[:idx].count("\n") - 1)
            for idx in indices
        ]
        
        nearest_idx = indices[line_distances.index(min(line_distances))]
        
        return (
            content[:nearest_idx] +
            new_text +
            content[nearest_idx + len(old_text):]
        )
    
    def localization_check(self, version: str) -> bool:
        """Check if target file exists for version."""
        commit_id = self.project.find_commit_by_version(version)
        if not commit_id:
            return False
        
        target_file = self.project.get_responding_file_name(commit_id)
        if not target_file:
            return False
        
        target_path = self.project.npm_project_path / target_file
        return target_path.exists()
    
    def length_check(self, version: str, max_lines: int = 500) -> bool:
        """Check if target file is within length limit."""
        commit_id = self.project.find_commit_by_version(version)
        content = self.project.get_target_file_content(commit_id)
        
        if not content:
            return False
        
        line_count = content.count("\n")
        return line_count <= max_lines
