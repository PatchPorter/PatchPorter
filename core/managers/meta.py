"""
Metadata manager for SCA-Repair.

Handles repository setup, version management, and project metadata operations.
"""

import json
import logging
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple

from core.managers.base import BaseManager
from core.project import Project
from core.utils.command import run_command
from core.utils.file import (
    read_file,
    read_lines,
    write_file,
    read_json,
    write_json,
    ensure_directory,
)
from core.utils.git import (
    checkout_commit,
    get_file_at_commit,
)
from core.exceptions import SCARepairError

logger = logging.getLogger(__name__)


class MetaManager(BaseManager):
    """
    Manager for project metadata and repository operations.

    Responsibilities:
    - Clone and setup npm packages
    - Manage version mappings
    - Identify challenge versions
    - Output prompts and results
    """

    def __init__(self, project: Project):
        """Initialize MetaManager."""
        super().__init__(project)
        self._target_path = self.project_path / "target"

    def validate(self) -> bool:
        """Validate that project structure exists."""
        return (
            self.project_path.exists()
            and self.project.npm_project_path.exists()
        )

    def execute(self, **kwargs) -> Any:
        """Execute metadata operations based on kwargs."""
        operation = kwargs.get("operation", "info")

        if operation == "info":
            return self.get_project_info()
        elif operation == "store_challenge":
            return self.store_challenge_version()
        elif operation == "output_targets":
            return self.output_target_files()

        return None

    # =========================================================================
    # Version Management
    # =========================================================================

    def get_challenge_version(self) -> Optional[str]:
        """Get the challenge (oldest vulnerable) version."""
        return self.project.get_challenge_version()

    def store_challenge_version(self) -> Optional[str]:
        """
        Identify and store the challenge version.

        The challenge version is the oldest vulnerable version that
        requires backporting.

        Returns:
            The challenge version string, or None if not found
        """
        challenge_version = self._identify_challenge_version()

        if challenge_version is None:
            self._logger.warning(
                f"{self.project_path} has no challenge version"
            )
            return None

        challenge_path = self.project_path / "challenge-version.txt"
        write_file(challenge_path, challenge_version)

        self._logger.info(f"Stored challenge version: {challenge_version}")
        return challenge_version

    def _identify_challenge_version(self) -> Optional[str]:
        """
        Identify the challenge version from vulnerable versions.

        Returns:
            The oldest vulnerable version string
        """
        vul_versions = self.project.vulnerable_version_map

        if not vul_versions:
            return None

        # Return the last (oldest) version
        versions = list(vul_versions.values())
        return versions[-1] if versions else None

    def output_challenge_version(self) -> None:
        """Print the challenge version info."""
        challenge_version = self.get_challenge_version()
        print(f"{challenge_version} - {self.project_path}")

    # =========================================================================
    # Prompt and Result Output
    # =========================================================================

    def output_prompt(self, model: str) -> None:
        """
        Output formatted prompts for a specific model.

        Args:
            model: Model identifier
        """
        challenge_version = self.get_challenge_version()
        prompt_refined_path = self.project_path / "prompt-refined"
        ensure_directory(prompt_refined_path)

        output_file = prompt_refined_path / f"{model}-prompt.txt"
        result_file = self.project.result_path / f"{model}-result.txt"

        # Load results if available
        results = []
        try:
            result_lines = read_lines(result_file, skip_empty=True)
            results = [line.split(" ") for line in result_lines]
        except FileNotFoundError:
            pass

        # Process prompt files
        prompt_path = self.project.prompt_path
        output_lines = []

        for file_name in prompt_path.iterdir():
            if not file_name.suffix == ".json":
                continue

            parts = file_name.name.split("@")
            if len(parts) < 2 or parts[1] != model:
                continue

            try:
                json_content = read_json(file_name)
            except Exception as e:
                self._logger.warning(f"Failed to read {file_name}: {e}")
                continue

            prompts = json_content.get("prompt", [])
            llm_outputs = {
                k[:-7]: v  # Remove "-output" suffix
                for k, v in json_content.items()
                if k.endswith("-output")
            }

            output_lines.append(file_name.name)
            for i, prompt_data in enumerate(prompts):
                output_lines.append(prompt_data.get("prompt", ""))

                for llm_name, outputs in llm_outputs.items():
                    output_lines.append("-" * 30)
                    output_lines.append(f"{llm_name}:")

                    # Find matching result
                    for result in results:
                        if len(result) >= 3 and result[2] in llm_name:
                            output_lines.append(result[0])
                            break

                    if i < len(outputs):
                        output_lines.append(outputs[i])

                output_lines.append("*" * 50)
            output_lines.append("#" * 100)

        write_file(output_file, "\n".join(output_lines))

    def output_result(self, model: str) -> None:
        """
        Output formatted results for a specific model.

        Args:
            model: Model identifier
        """
        result_file = f"./case-analysis/{model}-result.txt"
        challenge_version = self.get_challenge_version()

        prompt_path = self.project.prompt_path
        result_path = self.project.result_path / f"{model}-result.txt"

        output_lines = []

        for file_name in prompt_path.iterdir():
            if not file_name.suffix == ".json":
                continue

            parts = file_name.name.split("@")
            if len(parts) < 2 or parts[1] != model:
                continue

            try:
                results = read_lines(result_path, skip_empty=True)
                for result in results:
                    output_lines.append(f"{self.project_path} {result}")
            except FileNotFoundError:
                pass

        # Append to global result file
        if output_lines:
            with open(result_file, "a") as f:
                for line in output_lines:
                    print(line, file=f)

    # =========================================================================
    # Target File Operations
    # =========================================================================

    def output_target_files(self) -> None:
        """
        Output target files for all vulnerable versions.

        Creates a directory with target files for versions where
        the patch cannot be directly applied.
        """
        ensure_directory(self._target_path)

        # Clean existing files
        run_command(f"rm -rf {self._target_path}/*", path=self.project_path)

        for commit_id, version in self.project.vulnerable_version_map.items():
            self.project.checkout(commit_id)

            # Try direct patch application
            apply_result = run_command(
                "git apply ../../final-patch.diff",
                path=self.project.npm_project_path,
            )

            if "not apply" not in apply_result.stderr:
                continue

            # Try fuzzy patch
            fuzz_result = run_command(
                "patch -p1 --fuzz=10 < ../../final-patch.diff",
                path=self.project.npm_project_path,
            )

            if "FAILED" not in fuzz_result.stdout:
                continue

            # Reset and save target file
            run_command("git checkout .", path=self.project.npm_project_path)

            target_file = self._target_path / f"{version}-{self.project.target_file_name}"
            try:
                content = read_file(self.project.target_file_path)
                write_file(target_file, content)
            except FileNotFoundError:
                self._logger.warning(f"Target file not found for {version}")

    def output_patch_target_file(self) -> None:
        """Output pre-patch, post-patch, and target files."""
        target_commit = self.project.get_challenge_commit()
        patch_path = self.project.unidiff_patch[0].path if self.project.unidiff_patch else ""

        # Target file
        target_file = self.project_path / "target.js"
        target_content = get_file_at_commit(
            target_commit,
            patch_path,
            self.project.npm_project_path,
        )
        if target_content:
            write_file(target_file, target_content)

        # Pre-patch file
        pre_file = self.project_path / "pre.js"
        pre_content = get_file_at_commit(
            f"{self.project.patch_commit_id}^",
            patch_path,
            self.project.npm_project_path,
        )
        if pre_content:
            write_file(pre_file, pre_content)

        # Post-patch file
        post_file = self.project_path / "post.js"
        post_content = get_file_at_commit(
            self.project.patch_commit_id,
            patch_path,
            self.project.npm_project_path,
        )
        if post_content:
            write_file(post_file, post_content)

    # =========================================================================
    # Information Methods
    # =========================================================================

    def get_project_info(self) -> Dict[str, Any]:
        """
        Get comprehensive project information.

        Returns:
            Dictionary with project metadata
        """
        return {
            "name": self.project.name,
            "version": self.project.version,
            "cve_id": self.project.cve_id,
            "patch_url": self.project.patch_url,
            "patch_commit": self.project.patch_commit_id,
            "challenge_version": self.get_challenge_version(),
            "vulnerable_version_count": self.project.vulnerable_version_count,
            "target_file": self.project.target_file_name,
        }

    def count_changed_lines(self, patch_path: Path) -> int:
        """
        Count total changed lines in a patch.

        Args:
            patch_path: Path to patch file

        Returns:
            Total number of added + removed lines
        """
        try:
            from unidiff import PatchSet

            patch_set = PatchSet.from_filename(str(patch_path))
            total = 0

            for patched_file in patch_set:
                total += patched_file.added + patched_file.removed

            return total
        except Exception as e:
            self._logger.warning(f"Failed to count lines: {e}")
            return 0

    def get_chunk_count(self, patch_path: Path) -> int:
        """
        Count number of chunks (hunks) in a patch.

        Args:
            patch_path: Path to patch file

        Returns:
            Number of hunks
        """
        try:
            from unidiff import PatchSet

            patch_set = PatchSet.from_filename(str(patch_path))
            return sum(len(list(pf)) for pf in patch_set)
        except Exception as e:
            self._logger.warning(f"Failed to count chunks: {e}")
            return 0

    def test_pre_post_patch(self) -> Tuple[str, str]:
        """
        Test both pre-patch and post-patch states.

        Returns:
            Tuple of (pre_result, post_result)
        """
        self.project.checkout_before_patch()
        pre_result = self.project.run_jest()

        self.project.checkout_patch()
        post_result = self.project.run_jest()

        self._logger.info(f"Pre: {pre_result}, Post: {post_result}")
        return pre_result, post_result

    def match_cve(self, cve_id: str) -> bool:
        """
        Check if this project matches a CVE ID.

        Args:
            cve_id: CVE identifier to match

        Returns:
            True if project matches the CVE
        """
        if self.project.cve_id == cve_id:
            self._logger.info(
                f"Matched CVE {cve_id}: {self.project_path} - {self.project.patch_url}"
            )
            return True
        return False
