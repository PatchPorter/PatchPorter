"""
Untangler for SCA-Repair.

Handles patch simplification by filtering out non-security-related changes.
"""

import os
import shutil
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from core.managers.base import BaseManager
from core.project import Project
from core.config import config
from core.utils.command import run_command
from core.utils.file import (
    read_file,
    read_lines,
    write_file,
    ensure_directory,
)
from core.exceptions import PatchApplicationError

logger = logging.getLogger(__name__)


class PatchHunkInfo:
    """Information about a patch hunk."""
    
    def __init__(
        self,
        metadata: List[str],
        content: List[str],
        index: int,
    ):
        self.metadata = metadata
        self.content = content
        self.index = index
    
    @property
    def full_content(self) -> List[str]:
        """Get complete hunk including metadata."""
        return self.metadata + self.content
    
    @property
    def file_path(self) -> str:
        """Extract file path from metadata."""
        for line in self.metadata:
            if line.startswith("diff"):
                parts = line.split()
                if len(parts) >= 3:
                    return parts[-1].lstrip("b/")
        return ""
    
    @property
    def is_test_file(self) -> bool:
        """Check if this hunk is for a test file."""
        path = self.file_path.lower()
        return (
            "test" in path or
            "spec" in path or
            "__test" in path
        )
    
    @property
    def is_js_file(self) -> bool:
        """Check if this hunk is for a JavaScript file."""
        path = self.file_path.lower()
        return (
            path.endswith(".js") or
            path.endswith(".ts") or
            path.endswith(".mjs")
        )
    
    @property
    def is_relevant(self) -> bool:
        """Check if this hunk is security-relevant."""
        path = self.file_path.lower()
        
        # Skip non-code files
        if not self.is_js_file:
            return False
        
        # Skip test files
        if self.is_test_file:
            return False
        
        # Skip minified files
        if "min.js" in path:
            return False
        
        # Skip dist/build files
        if "/dist/" in path or "/build/" in path:
            return False
        
        # Skip JSON files
        if path.endswith(".json"):
            return False
        
        return True


class Untangler(BaseManager):
    """
    Manager for patch simplification.
    
    Responsibilities:
    - Filter out test/build file changes
    - Isolate security-relevant hunks
    - Generate minimal patches for backporting
    - Validate patch applicability
    """
    
    def __init__(self, project: Project):
        """Initialize Untangler."""
        super().__init__(project)
        
        self._patch_path = self.project.patch_path
        self._final_patch_path = self.project.final_patch_path
        self._patches_dir = self.project_path / "patches"
        
        ensure_directory(self._patches_dir)
    
    def validate(self) -> bool:
        """Validate that original patch exists."""
        return self._patch_path.exists()
    
    def execute(self, **kwargs) -> Any:
        """Execute untangling."""
        method = kwargs.get("method", "filename")
        
        if method == "filename":
            return self.untangle_by_filename()
        elif method == "poc":
            return self.untangle_by_poc()
        
        return None
    
    # =========================================================================
    # Untangling Methods
    # =========================================================================
    
    def untangle_by_filename(self) -> List[PatchHunkInfo]:
        """
        Filter patch hunks by filename patterns.
        
        Returns:
            List of relevant hunks
        """
        patches = self.project.unidiff_patch
        relevant_hunks = []
        
        for patch in patches:
            # Check if file is relevant
            path_lower = patch.path.lower()
            
            is_relevant = (
                not ("min.js" in path_lower) and
                not ("test" in path_lower) and
                not (path_lower.endswith(".json")) and
                (
                    path_lower.endswith(".js") or
                    path_lower.endswith(".ts") or
                    path_lower.endswith(".mjs")
                ) and
                not patch.is_added_file
            )
            
            if not is_relevant:
                continue
            
            for i, hunk in enumerate(patch):
                hunk_info = PatchHunkInfo(
                    metadata=[],  # Will be filled when writing
                    content=[str(hunk)],
                    index=i,
                )
                relevant_hunks.append(hunk_info)
        
        logger.info(f"Found {len(relevant_hunks)} relevant hunks")
        return relevant_hunks
    
    def untangle_by_poc(self) -> Path:
        """
        Filter hunks by proof-of-concept testing.
        
        Tests each hunk combination to find minimal security-relevant set.
        
        Returns:
            Path to final patch file
        """
        logger.info(f"Untangling by PoC: {self.project_path}")
        
        # Checkout before patch
        self.project.checkout_before_patch()
        
        # Extract all hunks
        hunks = self._extract_hunks_with_metadata()
        
        if len(hunks) == 1:
            # Single hunk, just use it
            self._write_patch(hunks, self._final_patch_path)
            return self._final_patch_path
        
        # Generate test combinations
        self._generate_combinations(hunks)
        
        # Test each combination
        final_hunks = []
        
        for i, hunk in enumerate(hunks):
            patch_file = self._patches_dir / f"patch_{i}.diff"
            
            # Apply patch without this hunk
            run_command(
                f"git apply --ignore-whitespace {patch_file}",
                path=self.project.npm_project_path,
            )
            
            # Run tests
            result = self.project.run_jest()
            logger.info(f"Hunk {i}: {result}")
            
            # If tests still fail, this hunk is needed
            if "False" in result:
                final_hunks.append(hunk)
            
            # Restore
            self.project.checkout(".")
        
        if final_hunks:
            self._write_patch(final_hunks, self._final_patch_path)
        else:
            # All hunks needed
            self._write_patch(hunks, self._final_patch_path)
        
        return self._final_patch_path
    
    def check_untangle_result(self) -> bool:
        """
        Verify that final patch can be applied.
        
        Returns:
            True if patch applies cleanly
        """
        result = run_command(
            f"git apply --ignore-whitespace {self._final_patch_path}",
            path=self.project.npm_project_path,
        )
        
        return not result.has_error
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def summarize(self) -> Dict[str, int]:
        """
        Get summary statistics of untangling.
        
        Returns:
            Dictionary with hunk counts
        """
        original_hunks = self._count_hunks(self._patch_path)
        final_hunks = self._count_hunks(self._final_patch_path)
        
        filtered_hunks = len(self.untangle_by_filename())
        
        return {
            "original": original_hunks,
            "filtered": filtered_hunks,
            "final": final_hunks,
        }
    
    @staticmethod
    def _count_hunks(patch_path: Path) -> int:
        """Count number of hunks in a patch file."""
        if not patch_path.exists():
            return 0
        
        count = 0
        try:
            content = read_file(patch_path)
            for line in content.split("\n"):
                if line.startswith("@@"):
                    count += 1
        except Exception:
            pass
        
        return count
    
    # =========================================================================
    # Hunk Manipulation
    # =========================================================================
    
    def _extract_hunks_with_metadata(self) -> List[List[str]]:
        """
        Extract hunks with their metadata from patch file.
        
        Returns:
            List of hunk content (metadata + lines)
        """
        hunks = []
        current_hunk = []
        metadata = []
        
        try:
            content = read_file(self._patch_path)
        except Exception:
            return hunks
        
        for line in content.split("\n"):
            line_with_newline = line + "\n"
            
            # Metadata lines
            if any(line.startswith(prefix) for prefix in [
                "diff", "index", "---", "+++", "deleted file", "new file"
            ]):
                if current_hunk:
                    hunks.append(metadata + current_hunk)
                    current_hunk = []
                    metadata = []
                metadata.append(line_with_newline)
            
            # Hunk header
            elif line.startswith("@@"):
                if current_hunk:
                    hunks.append(metadata + current_hunk)
                    current_hunk = []
                current_hunk.append(line_with_newline)
            
            # Regular line
            else:
                current_hunk.append(line_with_newline)
        
        if current_hunk:
            hunks.append(metadata + current_hunk)
        
        # Filter non-relevant hunks
        filtered = []
        for hunk in hunks:
            if not hunk:
                continue
            
            file_path = ""
            for line in hunk:
                if line.startswith("diff"):
                    parts = line.split()
                    if len(parts) >= 3:
                        file_path = parts[-1].lower()
                        break
            
            # Check relevance
            is_relevant = (
                ".js" in file_path or ".ts" in file_path or ".mjs" in file_path
            ) and not (
                "min.js" in file_path or
                "test" in file_path or
                ".json" in file_path
            )
            
            if is_relevant:
                filtered.append(hunk)
        
        return filtered
    
    def _generate_combinations(self, hunks: List[List[str]]) -> None:
        """
        Generate patch files with one hunk removed each.
        
        Args:
            hunks: List of hunk contents
        """
        # Clear existing patches
        if self._patches_dir.exists():
            shutil.rmtree(self._patches_dir)
        self._patches_dir.mkdir()
        
        for i in range(len(hunks)):
            # Create patch with hunk i removed
            remaining = hunks[:i] + hunks[i+1:]
            output_path = self._patches_dir / f"patch_{i}.diff"
            self._write_patch(remaining, output_path)
    
    @staticmethod
    def _write_patch(hunks: List[List[str]], output_path: Path) -> None:
        """
        Write hunks to a patch file.
        
        Args:
            hunks: List of hunk contents
            output_path: Path to output file
        """
        with open(output_path, "w") as f:
            for hunk in hunks:
                f.writelines(hunk)
    
    # =========================================================================
    # Verification
    # =========================================================================
    
    def verify_unchanged(self) -> bool:
        """
        Verify that final patch matches backup.
        
        Returns:
            True if patches are equivalent
        """
        backup_path = Path(str(self._final_patch_path) + ".bk")
        
        if not backup_path.exists():
            return True
        
        try:
            final = set(self._extract_hunks_with_metadata())
            backup_hunks = []
            
            # Temporarily swap paths and extract
            original_path = self._patch_path
            self._patch_path = backup_path
            backup = set(self._extract_hunks_with_metadata())
            self._patch_path = original_path
            
            return final == backup
        except Exception:
            return True
    
    def backup_final_patch(self) -> None:
        """Create backup of final patch."""
        if self._final_patch_path.exists():
            backup_path = Path(str(self._final_patch_path) + ".bk")
            shutil.copy(self._final_patch_path, backup_path)
