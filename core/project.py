"""
Project class for SCA-Repair.

The Project class is the core data structure that manages all information
about a vulnerability repair project, including paths, versions, patches,
and metadata.
"""

import json
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

from core.config import config
from core.utils.command import run_command
from core.utils.git import (
    checkout_commit,
    get_parent_commit,
    is_commit_earlier,
    get_file_at_commit,
    list_files_at_commit,
    get_commit_history,
)
from core.utils.file import (
    read_file,
    read_lines,
    write_file,
    read_json,
    write_json,
    ensure_directory,
)
from core.utils.similarity import calculate_bleu, find_most_similar
from core.exceptions import (
    SCARepairError,
    VersionNotFoundError,
)

logger = logging.getLogger(__name__)


@dataclass
class VersionInfo:
    """Information about a specific version."""

    commit_id: str
    version: str

    def __hash__(self):
        return hash(self.commit_id)

    def __eq__(self, other):
        if isinstance(other, VersionInfo):
            return self.commit_id == other.commit_id
        return False


@dataclass
class PatchInfo:
    """Information about the security patch."""

    url: str
    commit_id: str
    content: str
    target_file: str

    @property
    def parent_commit(self) -> Optional[str]:
        """Lazily computed parent commit."""
        return None  # Will be computed when needed


class Project:
    """
    Core project class managing vulnerability repair project data.

    This class provides a clean interface to access all project-related
    information including paths, versions, patches, and metadata.

    Attributes:
        path: Absolute path to the project directory
        name: Package name
        version: Package version
        cve_id: CVE identifier (if available)

    Example:
        >>> project = Project("/path/to/dataset/redos/package_1.0.0")
        >>> print(project.name)
        'package'
        >>> project.checkout("abc123")
    """

    def __init__(self, project_path: str | Path):
        """
        Initialize a Project instance.

        Args:
            project_path: Absolute path to the project directory

        Raises:
            ValueError: If project path format is invalid
        """
        self._path = Path(project_path).resolve()
        self._parse_project_info()
        self._setup_paths()
        self._load_metadata()
        self._name_history_cache: Optional[List[Tuple[str, str]]] = None

        logger.info(f"Initialized project: {self.name}@{self.version}")

    def _parse_project_info(self) -> None:
        """Parse project name and version from path."""
        dir_name = self._path.name

        # Expected format: package_version
        if "_" not in dir_name:
            raise ValueError(
                f"Invalid project directory format: {dir_name}. "
                "Expected format: 'package_version'"
            )

        # Split from the last underscore to handle packages with underscores
        parts = dir_name.rsplit("_", 1)
        self._name = parts[0]
        self._version = parts[1] if len(parts) > 1 else "unknown"

    def _setup_paths(self) -> None:
        """Setup all project-related paths."""
        # Core paths
        self._npm_path = self._path / "node_modules"
        self._npm_prj_path = self._npm_path / self._name
        self._package_json_path = self._path / "package.json"

        # Patch paths
        self._patch_path = self._path / "patch.diff"
        self._final_patch_path = self._path / "final-patch.diff"

        # Data paths
        self._localization_path = self._path / "localization"
        self._prompt_path = self._path / "prompt"
        self._result_path = self._path / "result"
        self._output_path = self._path / "output-result"

        # Version info paths
        self._version_map_path = self._path / "version-map.txt"
        self._vul_version_map_path = self._path / "vulnerable_versions.txt"
        self._challenge_version_path = self._path / "challenge-version.txt"
        self._name_history_path = self._path / "name_history.json"

        # Ensure directories exist
        for dir_path in [
            self._localization_path,
            self._prompt_path,
            self._result_path,
            self._output_path,
        ]:
            ensure_directory(dir_path)

    def _load_metadata(self) -> None:
        """Load project metadata from package.json."""
        try:
            pkg_data = read_json(self._package_json_path)
            self._cve_id = pkg_data.get("id")
            self._patch_url = self._normalize_patch_url(
                pkg_data.get("fixCommit", "")
            )
        except Exception as e:
            logger.warning(f"Failed to load package.json: {e}")
            self._cve_id = None
            self._patch_url = ""

    @staticmethod
    def _normalize_patch_url(url: str) -> str:
        """Convert GitHub PR commit URL to regular commit URL."""
        pattern = r"(https://github\.com/.+?/.+?)/pull/\d+/commits/([a-f0-9]+)"
        match = re.match(pattern, url)
        if match:
            return f"{match.group(1)}/commit/{match.group(2)}"
        return url

    # =========================================================================
    # Properties - Basic Info
    # =========================================================================

    @property
    def path(self) -> Path:
        """Project directory path."""
        return self._path

    @property
    def name(self) -> str:
        """Package name."""
        return self._name

    @property
    def version(self) -> str:
        """Package version."""
        return self._version

    @property
    def project_id(self) -> str:
        """Unique project identifier (name_version)."""
        return f"{self._name}_{self._version}"

    @property
    def cve_id(self) -> Optional[str]:
        """CVE identifier."""
        return self._cve_id

    # =========================================================================
    # Properties - Paths
    # =========================================================================

    @property
    def npm_path(self) -> Path:
        """Path to node_modules directory."""
        return self._npm_path

    @property
    def npm_project_path(self) -> Path:
        """Path to the package within node_modules."""
        return self._npm_prj_path

    @property
    def patch_path(self) -> Path:
        """Path to original patch file."""
        return self._patch_path

    @property
    def final_patch_path(self) -> Path:
        """Path to cleaned/final patch file."""
        return self._final_patch_path

    @property
    def localization_path(self) -> Path:
        """Path to localization data directory."""
        return self._localization_path

    @property
    def prompt_path(self) -> Path:
        """Path to prompt data directory."""
        return self._prompt_path

    @property
    def result_path(self) -> Path:
        """Path to result data directory."""
        return self._result_path

    # =========================================================================
    # Properties - Patch Info
    # =========================================================================

    @property
    def patch_url(self) -> str:
        """URL to the security patch commit."""
        return self._patch_url

    @property
    def patch_commit_id(self) -> str:
        """Extract commit ID from patch URL."""
        if not self._patch_url:
            return ""
        return self._patch_url.split("/")[-1].split("#")[0]

    @property
    def patch_parent_commit(self) -> Optional[str]:
        """Get parent commit of the patch."""
        return get_parent_commit(self.patch_commit_id, self._npm_prj_path)

    @property
    def patch_content(self) -> str:
        """Read patch content from file."""
        try:
            return read_file(self._final_patch_path)
        except FileNotFoundError:
            return ""

    @property
    def unidiff_patch(self) -> list:
        """Parse patch as unidiff PatchSet."""
        try:
            import unidiff
            return list(unidiff.PatchSet.from_string(self.patch_content))
        except Exception as e:
            logger.warning(f"Failed to parse patch: {e}")
            return []

    @property
    def target_file_name(self) -> str:
        """Get the target file name from patch."""
        patches = self.unidiff_patch
        if patches:
            return Path(patches[0].path).name
        return ""

    @property
    def target_file_path(self) -> Path:
        """Get full path to target file."""
        patches = self.unidiff_patch
        if patches:
            return self._npm_prj_path / patches[0].path
        return self._npm_prj_path

    # =========================================================================
    # Version Management
    # =========================================================================

    def _load_version_map(self, path: Path) -> Dict[str, str]:
        """Load version map from file."""
        version_map = {}
        try:
            for line in read_lines(path, skip_empty=True):
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    version_map[parts[0]] = parts[1]
        except FileNotFoundError:
            logger.warning(f"Version map not found: {path}")
        return version_map

    @property
    def version_map(self) -> Dict[str, str]:
        """Map of all commit IDs to version numbers."""
        return self._load_version_map(self._version_map_path)

    @property
    def vulnerable_version_map(self) -> Dict[str, str]:
        """Map of vulnerable commit IDs to version numbers."""
        return self._load_version_map(self._vul_version_map_path)

    @property
    def vulnerable_version_count(self) -> int:
        """Number of vulnerable versions."""
        return len(self.vulnerable_version_map)

    def get_challenge_version(self) -> Optional[str]:
        """Get the challenge (oldest vulnerable) version."""
        try:
            return read_file(self._challenge_version_path).strip()
        except FileNotFoundError:
            return None

    def get_challenge_commit(self) -> Optional[str]:
        """Get commit ID for challenge version."""
        version = self.get_challenge_version()
        if version:
            return self.find_commit_by_version(version)
        return None

    def get_oldest_vulnerable_version(self) -> Optional[str]:
        """Get the oldest vulnerable version's commit."""
        try:
            lines = read_lines(self._vul_version_map_path, skip_empty=True)
            if lines:
                return lines[-1].split(" ")[0]
        except FileNotFoundError:
            pass
        return None

    def find_commit_by_version(self, version: str) -> Optional[str]:
        """Find commit ID for a given version."""
        for commit, ver in self.version_map.items():
            if ver == version:
                return commit
        return None

    def find_version_by_commit(self, commit: str) -> Optional[str]:
        """Find version for a given commit ID."""
        return self.version_map.get(commit)

    # =========================================================================
    # Git Operations
    # =========================================================================

    def checkout(self, commit_or_ref: str) -> bool:
        """
        Checkout a specific commit or reference.

        Args:
            commit_or_ref: Commit hash or git reference

        Returns:
            True if checkout was successful
        """
        result = checkout_commit(commit_or_ref, self._npm_prj_path)
        return not result.has_error

    def checkout_patch(self) -> bool:
        """Checkout the patch commit."""
        return self.checkout(self.patch_commit_id)

    def checkout_before_patch(self) -> bool:
        """Checkout the commit before the patch."""
        parent = self.patch_parent_commit
        if parent:
            return self.checkout(parent)
        return False

    def get_file_at_commit(self, commit: str, file_path: str) -> Optional[str]:
        """Get file content at a specific commit."""
        return get_file_at_commit(commit, file_path, self._npm_prj_path)

    def get_target_file_content(self, commit: str) -> Optional[str]:
        """Get target file content at a specific commit."""
        file_name = self.get_responding_file_name(commit)
        if file_name:
            return get_file_at_commit(commit, file_name, self._npm_prj_path)
        return None

    def get_target_file_lines(self, commit: str) -> List[str]:
        """Get target file content as list of lines."""
        content = self.get_target_file_content(commit)
        if content:
            lines = content.splitlines()
            if content.endswith("\n"):
                lines.append("")
            return [line + "\n" for line in lines]
        return []

    # =========================================================================
    # File Name Resolution
    # =========================================================================

    def get_responding_file_name(self, commit_id: str) -> Optional[str]:
        """
        Find the corresponding file name at a specific commit.

        Since files can be renamed or moved across versions, this method
        uses BLEU similarity to find the most matching file.

        Args:
            commit_id: Target commit ID

        Returns:
            File path at the target commit, or None if not found
        """
        if not commit_id or not commit_id.strip():
            return None

        # Get reference file content from patch version
        patches = self.unidiff_patch
        if not patches:
            return None

        reference_path = patches[0].path
        reference_content = get_file_at_commit(
            self.patch_commit_id,
            reference_path,
            self._npm_prj_path,
        )

        if not reference_content:
            return None

        # Get list of JS files at target commit
        all_files = list_files_at_commit(commit_id, self._npm_prj_path)
        js_files = [
            f for f in all_files
            if f.endswith(".js")
            and "test" not in f.lower()
            and "dist" not in f.lower()
            and "min.js" not in f
            and ".history" not in f
        ]

        if not js_files:
            return None

        if len(js_files) == 1:
            return js_files[0]

        # Use BLEU similarity to find best match
        file_contents = []
        for f in js_files:
            content = get_file_at_commit(commit_id, f, self._npm_prj_path)
            file_contents.append(content or "")

        best_idx, _ = find_most_similar(reference_content, file_contents)
        return js_files[best_idx] if best_idx >= 0 else None

    def get_name_history(self) -> List[Tuple[str, str]]:
        """
        Get the rename history of the target file.

        Returns:
            List of (commit, file_path) tuples
        """
        if self._name_history_cache is not None:
            return self._name_history_cache

        try:
            data = read_json(self._name_history_path)
            self._name_history_cache = [tuple(item) for item in data]
        except (FileNotFoundError, json.JSONDecodeError):
            patches = self.unidiff_patch
            if patches:
                self._name_history_cache = get_commit_history(
                    patches[0].path,
                    self._npm_prj_path,
                    self.patch_commit_id,
                )
                self._save_name_history()
            else:
                self._name_history_cache = []

        return self._name_history_cache

    def _save_name_history(self) -> None:
        """Save name history to file."""
        if self._name_history_cache:
            write_json(self._name_history_path, self._name_history_cache)

    # =========================================================================
    # Testing
    # =========================================================================

    def run_jest(self, timeout: int = 40) -> str:
        """
        Run Jest tests for the project.

        Returns:
            Test result tag:
            - 'True': Test detected the vulnerability (expected behavior differs)
            - 'False#0': Tests pass (patch may have fixed the issue)
            - 'False#1': Syntax error in code
            - 'Check': Needs manual verification
        """
        logger.info(f"Running Jest tests for {self.name}")

        result = run_command(
            f"timeout {timeout}s jest --testPathIgnorePatterns=\"node_modules\" --forceExit",
            path=self._path,
        )

        stderr = result.stderr
        syntax_errors = config.test.syntax_error_patterns

        if "Received" in stderr and "Expected" in stderr:
            return "True"
        elif "PASS" in stderr:
            return "False#0"
        elif any(pattern in stderr for pattern in syntax_errors):
            return "False#1"

        return "Check"

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_hunks(self) -> list:
        """Get all hunks from the patch."""
        hunks = []
        for patch in self.unidiff_patch:
            for hunk in patch:
                hunks.append(hunk)
        return hunks

    def backup_node_modules(self) -> None:
        """Backup node_modules directory."""
        run_command(
            "cp -r node_modules node_modules_bk",
            path=self._path,
        )

    def restore_node_modules(self) -> None:
        """Restore node_modules from backup."""
        run_command(
            "rm -rf node_modules && cp -r node_modules_bk node_modules",
            path=self._path,
        )

    def __repr__(self) -> str:
        return f"Project({self.project_id})"

    def __str__(self) -> str:
        return f"{self.name}@{self.version}"
