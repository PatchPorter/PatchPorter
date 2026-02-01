"""
Fault localizer for SCA-Repair.

Handles tracking vulnerable code across different versions using
Git history and AST analysis.
"""

import os
import re
import ast
import json
import logging
from io import StringIO
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass
from functools import cmp_to_key
from difflib import SequenceMatcher

from tree_sitter import Language, Parser
import tree_sitter_javascript

try:
    import Levenshtein
except ImportError:
    Levenshtein = None

from core.managers.base import BaseManager
from core.project import Project
from core.utils.command import run_command
from core.utils.file import (
    read_file,
    read_lines,
    write_file,
    ensure_directory,
)
from core.utils.git import (
    get_parent_commit,
    is_commit_earlier,
    get_file_at_commit,
    run_git_blame,
    parse_git_blame_output,
    get_nearest_ancestor_commit,
    get_diff_between_commits,
)
from core.exceptions import LocalizationError

logger = logging.getLogger(__name__)


@dataclass
class LocalizationResult:
    """Result of fault localization for a version."""

    commit_id: str
    line_numbers: List[int]
    hunk_index: int
    file_path: Optional[str] = None
    confidence: float = 1.0


class FaultLocalizer(BaseManager):
    """
    Manager for fault localization across versions.

    Responsibilities:
    - Track how vulnerable code evolved across versions
    - Map line numbers from patch version to target version
    - Use git blame and diff analysis for tracking
    - Support multiple localization strategies
    """

    def __init__(self, project: Project):
        """Initialize FaultLocalizer."""
        super().__init__(project)

        self._patch_commit = self.project.patch_commit_id
        self._pre_patch_commit = get_parent_commit(
            self._patch_commit,
            self.project.npm_project_path,
        )
        self._localization_path = self.project.localization_path
        
        # Additional instance variables for tracking
        self.hunks = []
        self.hunk_headers = []
        self.source_functions = []
        # {version1: [foo1, ...], version2: [foo1,...]}
        self.target_functions = {}
        self.challenge_commit = self.project.get_challenge_commit()
        self.source_lines = []
        self.fault_context = []
        self.current_line = ""

    def validate(self) -> bool:
        """Validate that project has required patch info."""
        return (
            bool(self._patch_commit)
            and bool(self._pre_patch_commit)
            and self.project.final_patch_path.exists()
        )

    def execute(self, **kwargs) -> Any:
        """
        Execute localization based on method.
        
        This class handles the LLM + history localization method.
        For baseline methods, use BaselineLocalizer.
        
        Available methods in this class:
        - history_llm: Git history + LLM matching (default)
        - line_llm: Alias for history_llm
        
        For baseline methods (line, line_log, history_similarity,
        direct_llm, direct_similarity, function, file), use
        BaselineLocalizer from core.managers.baseline_localizer.
        """
        import time
        start_time = time.time()
        
        method = kwargs.get("method", "history_llm")
        model = kwargs.get("model", "deepseek-api")

        # LLM + History method (main method in this class)
        if method in ("history_llm", "line_llm", "line"):
            result = self.localize_with_history_llm(model)
            elapsed = time.time() - start_time
            self._logger.info(f"Localization completed in {elapsed:.2f}s")
            self.project._localization_time = elapsed
            return result

        # For backward compatibility, delegate to BaselineLocalizer
        self._logger.warning(
            f"Method '{method}' should use BaselineLocalizer. "
            "Delegating to baseline localizer."
        )
        from core.managers.baseline_localizer import BaselineLocalizer
        baseline = BaselineLocalizer(self.project)
        result = baseline.execute(**kwargs)
        elapsed = time.time() - start_time
        self._logger.info(f"Localization completed in {elapsed:.2f}s")
        self.project._localization_time = elapsed
        return result

    # =========================================================================
    # LLM + History-based Localization (Core Method)
    # =========================================================================

    # =========================================================================
    # Git History + LLM Matching
    # =========================================================================

    def localize_with_history_llm(self, model: str) -> List[LocalizationResult]:
        """
        Localize vulnerable lines using LLM-assisted git history tracking.
        
        This method uses LLM to map code changes between versions when
        simple diff-based mapping fails.

        Args:
            model: Model identifier for LLM inference and output file naming

        Returns:
            List of LocalizationResult for each hunk
        """
        self._logger.info(f"=== Starting History+LLM Localization (model: {model}) ===")
        output_file = self._localization_path / f"{model}.csv"
        results = []
        csv_lines = []  # Collect all CSV lines to write at once

        # Get line numbers from patch
        self._logger.debug(f"Fetching pre-patch content from commit {self._pre_patch_commit[:8]}")
        pre_patch_content = run_command(
            f'git show {self._pre_patch_commit}:{self.project.get_responding_file_name(self._pre_patch_commit)}',
            path=self.project.npm_project_path
        ).stdout

        self._logger.debug("Extracting target line numbers from patch")
        hunk_lines_list = self._get_target_line_numbers_for_llm(pre_patch_content)
        self._logger.info(f"Found {len(hunk_lines_list)} chunks to process")

        for index, hunk_lines in enumerate(hunk_lines_list):
            self._logger.info(f"\n{'='*60}")
            self._logger.info(f"Processing Chunk {index + 1}/{len(hunk_lines_list)}")
            self._logger.info(f"{'='*60}")
            if hunk_lines[-1] == 'unused':
                self._logger.debug(f"Chunk {index}: Marked as unused, skipping")
                continue
            
            # Convert to range format (handle -1 for file-end additions)
            if hunk_lines[0] == -1 and hunk_lines[1] == -1:
                hunk_lines = ([-1], hunk_lines[-1])
            else:
                hunk_lines = (list(range(hunk_lines[0], hunk_lines[1] + 1)), hunk_lines[-1])
            self._logger.info(f"Chunk {index}: Lines {hunk_lines[0][0]}-{hunk_lines[0][-1] if hunk_lines[0] and hunk_lines[0][0] != -1 else 'file-end'} (type: {hunk_lines[1]})")

            # Track through history using LLM
            self._logger.debug(f"Chunk {index}: Starting git history tracking")
            changed_commits = self._get_changed_commit_lines_llm(hunk_lines, model)
            self._logger.info(f"Chunk {index}: Tracked through {len(changed_commits) if changed_commits else 0} commits in history")

            # Check if tracking succeeded
            if not changed_commits:
                self._logger.warning(f"Chunk {index}: No commit history found, skipping")
                continue

            self._logger.debug(f"Chunk {index}: Raw changed_commits: {changed_commits[:3] if len(changed_commits) > 3 else changed_commits}")
            
            # Map to challenge version
            try:
                changed_commits = [(i[0], i[1][0], i[2]) for i in changed_commits]
                self._logger.debug(f"Chunk {index}: Extracted {len(changed_commits)} commit mappings")
            except (IndexError, TypeError) as e:
                self._logger.error(f"Chunk {index}: Failed to extract commit data: {e}")
                self._logger.error(f"Chunk {index}: changed_commits structure: {changed_commits}")
                continue

            challenge_commit = self.project.get_challenge_commit()
            self._logger.debug(f"Chunk {index}: Challenge commit: {challenge_commit[:8] if challenge_commit else 'None'}")
            
            if not challenge_commit:
                self._logger.warning("No challenge commit found")
                continue

            # If directly located to challenge commit, use its line number result directly
            direct_match = next(
                (item for item in changed_commits if item[0] == challenge_commit),
                None
            )
            if direct_match is not None:
                base_lineno = direct_match[1]
                changed_lines = base_lineno if isinstance(base_lineno, list) else [base_lineno]
                self._logger.info(
                    f"Chunk {index}: Direct match on challenge commit, using lines {changed_lines}"
                )
                result = LocalizationResult(
                    commit_id=challenge_commit,
                    line_numbers=changed_lines,
                    hunk_index=index,
                )
                results.append(result)
                continue

            self._logger.debug(f"Chunk {index}: Finding nearest ancestor among {len(changed_commits)} commits")
            nearest_idx = get_nearest_ancestor_commit(
                challenge_commit,
                [i[0] for i in changed_commits],
                self.project.npm_project_path,
            )
            self._logger.debug(f"Chunk {index}: Nearest ancestor index: {nearest_idx}")

            if nearest_idx is None:
                # No direct ancestor found
                if changed_commits and len(changed_commits) > 0:
                    try:
                        # Check if this is a file-end addition marker
                        if hunk_lines[1] == 'add' and hunk_lines[0] == [-1]:
                            changed_lines = [-1]
                            self._logger.info(f"Chunk {index}: File-end addition, using -1 marker")
                        elif changed_commits[-1][1] == -1:
                            changed_lines = [-1]
                            self._logger.info(f"Chunk {index}: Using -1 marker for additions")
                        else:
                            # Write empty list to CSV so prompt generation can handle it
                            changed_lines = []
                            self._logger.warning(f"Chunk {index}: No ancestor found, writing empty localization")
                    except (IndexError, TypeError) as e:
                        self._logger.error(f"Chunk {index}: Cannot determine line mapping: {e}")
                        continue
                else:
                    # No commits tracked - check if this is a file-end addition
                    if hunk_lines[1] == 'add' and hunk_lines[0] == [-1]:
                        changed_lines = [-1]
                        self._logger.info(f"Chunk {index}: File-end addition, using -1 marker")
                    else:
                        self._logger.warning(f"Chunk {index}: No commits to process")
                        continue
            else:
                base_commit, base_lineno, base_file_name = changed_commits[nearest_idx]
                self._logger.debug(f"Chunk {index}: Base commit {base_commit[:8]}, line {base_lineno}")
                
                # If base_commit and challenge_commit are same, use base_lineno directly
                if base_commit == challenge_commit or base_commit in challenge_commit or challenge_commit in base_commit:
                    self._logger.info(f"Chunk {index}: Base commit same as challenge commit, using base lines directly")
                    changed_lines = base_lineno if isinstance(base_lineno, list) else [base_lineno]
                else:
                    # Only need to do diff mapping when commits differ
                    diff_content = run_command(
                        f'git diff {base_commit}:{self.project.get_responding_file_name(base_commit)} '
                        f'{challenge_commit}:{self.project.get_responding_file_name(challenge_commit)}',
                        path=self.project.npm_project_path
                    ).stdout
                    
                    from core.utils.parsing import parse_line_number_mapping
                    changed_lines = parse_line_number_mapping(diff_content, base_lineno)
                    changed_lines = sorted(list(set(changed_lines)))
                self._logger.info(f"Chunk {index}: Mapped to lines {changed_lines}")

            result = LocalizationResult(
                commit_id=challenge_commit,
                line_numbers=changed_lines,
                hunk_index=index,
            )
            
            # Output detailed localization results
            self._logger.info(f"Chunk {index} Localization Result:")
            self._logger.info(f"  - Target commit: {challenge_commit[:8]}")
            self._logger.info(f"  - Localized lines: {changed_lines}")
            self._logger.info(f"  - Total lines: {len(changed_lines)}")
            if changed_lines and changed_lines[0] != -1:
                self._logger.info(f"  - Line range: {min(changed_lines)}-{max(changed_lines)}")
            self._logger.info(f"{'='*60}\n")
            
            results.append(result)
            csv_lines.append(f'{challenge_commit}##{changed_lines}##{index}')

        # Write all results at once (overwrite mode)
        if csv_lines:
            with open(output_file, 'w') as f:
                f.write('\n'.join(csv_lines) + '\n')
            self._logger.info(f"Wrote {len(csv_lines)} localization results to {output_file}")
        else:
            self._logger.warning(f"No localization results to write")

        return results

    def _get_target_line_numbers_for_llm(self, pre_patch_content: str) -> List[Any]:
        """
        Extract target line numbers for LLM-based localization.
        
        This parses the patch to extract modification ranges, grouping
        continuous deleted/added lines together.
        
        Args:
            pre_patch_content: Content of file before patch
            
        Returns:
            List of tuples (old_start, old_end, type) for each modification block
        """
        patches = self.project.unidiff_patch
        if not patches:
            return []

        modifications = []
        
        for patched_file in patches:
            file_name = patched_file.path
            
            for hunk in patched_file:
                current_delete = []
                current_add = []
                
                for line in hunk:
                    if 'No newline at end of file' in line.value:
                        continue
                    
                    if line.is_removed:
                        current_delete.append(line.value.strip('\n'))
                    elif line.is_added:
                        current_add.append(line.value.strip('\n'))
                    else:
                        # Context line - flush accumulated changes
                        if current_delete and current_add:
                            old_start = line.source_line_no - len(current_delete)
                            old_end = old_start + len(current_delete) - 1
                            modifications.append({
                                "type": "change",
                                "old_start": old_start,
                                "old_end": old_end,
                                "old_lines": current_delete,
                                "new_lines": current_add,
                                "file": file_name
                            })
                        elif current_delete:
                            old_start = line.source_line_no - len(current_delete)
                            old_end = old_start + len(current_delete) - 1
                            modifications.append({
                                "type": "delete",
                                "old_start": old_start,
                                "old_end": old_end,
                                "old_lines": current_delete,
                                "new_lines": [],
                                "file": file_name
                            })
                        elif current_add:
                            old_start = line.source_line_no
                            old_end = line.source_line_no
                            modifications.append({
                                "type": "add",
                                "old_start": old_start,
                                "old_end": old_end,
                                "old_lines": [],
                                "new_lines": current_add,
                                "file": file_name
                            })
                        current_delete = []
                        current_add = []

                # Handle remaining changes at end of hunk
                if current_delete and current_add:
                    old_start = hunk.source_start + hunk.source_length - len(current_delete)
                    old_end = old_start + len(current_delete) - 1
                    modifications.append({
                        "type": "change",
                        "old_start": old_start,
                        "old_end": old_end,
                        "old_lines": current_delete,
                        "new_lines": current_add,
                        "file": file_name
                    })
                elif current_delete:
                    old_start = hunk.source_start + hunk.source_length - len(current_delete)
                    old_end = old_start + len(current_delete) - 1
                    modifications.append({
                        "type": "delete",
                        "old_start": old_start,
                        "old_end": old_end,
                        "old_lines": current_delete,
                        "new_lines": [],
                        "file": file_name
                    })
                elif current_add:
                    old_start = hunk.source_start + hunk.source_length
                    old_end = hunk.source_start + hunk.source_length
                    modifications.append({
                        "type": "add",
                        "old_start": old_start,
                        "old_end": old_end,
                        "old_lines": [],
                        "new_lines": current_add,
                        "file": file_name
                    })

        # Post-process 'add' type modifications
        pre_file_lines = pre_patch_content.split('\n')
        pre_file_length = len(pre_file_lines)
        
        for mod in modifications:
            if mod['type'] == 'add':
                # Skip empty lines at add position
                if mod["old_end"] < pre_file_length:
                    while pre_file_lines[mod['old_end'] - 1].strip() == '':
                        mod['old_end'] += 1
                        mod["old_start"] += 1
                        if mod["old_end"] >= pre_file_length:
                            break
                
                # Handle end of file case
                if (mod["old_end"] > pre_file_length or 
                    (mod["old_end"] == pre_file_length and pre_file_lines[-1].strip() == '')):
                    mod["old_start"] = -1
                    mod["old_end"] = -1

        return [(m["old_start"], m["old_end"], m["type"]) for m in modifications]

    def _get_changed_commit_lines_llm(
        self,
        hunk_lines: Tuple[List[int], str],
        model: str,
    ) -> List[Tuple[str, Tuple[List[int], str], str]]:
        """
        Track line changes through git history using LLM for mapping.
        
        The flow is:
        1. Use git blame to find commit B that last modified lines in commit A
        2. Map lines from A to B using simple diff offset (no LLM needed)
        3. Map lines from B to C (B's parent) using LLM (since B modified those lines)
        4. Repeat until we reach the oldest commit
        
        Args:
            hunk_lines: Tuple of (line_numbers, hunk_type)
            model: Model identifier for LLM
            
        Returns:
            List of (commit, lines, file_path) tuples
        """
        from core.utils.parsing import parse_line_number_mapping
        
        self._logger.debug("Starting commit history traversal")
        history = []
        before_lines = hunk_lines
        before_commit = self._pre_patch_commit
        before_file_path = self.project.get_responding_file_name(before_commit)
        
        if before_lines[0][0] != -1:
            current_line_content = self.get_line_content(
                before_commit,
                before_file_path,
                before_lines[0]
            )
            self.current_line = '\n'.join(current_line_content)
            self._logger.debug(f"Initial lines: {before_lines[0]}, content length: {len(self.current_line)} chars")

        iteration = 0
        while True:
            iteration += 1
            self._logger.debug(f"History iteration {iteration}: Analyzing commit {before_commit[:8]}")
            self._logger.debug(f"  Current lines to track: {before_lines[0]}")
            self._logger.debug(f"  File path: {before_file_path}")
            # Get blame commit - this finds commit B that last modified lines in commit A
            if before_lines[0][0] == -1:
                history.append((before_commit, before_lines, before_file_path))
                self._logger.debug(f"Iteration {iteration}: Lines marked as -1, ending traversal")
                break

            logger.info(f"Iteration {iteration}: Running git blame on commit {before_commit[:8]} for lines {before_lines[0]} in file {before_file_path}")
            current_commit = self._get_blame_commit(
                before_commit,
                before_file_path,
                before_lines[0]
            )
            
            if current_commit:
                self._logger.debug(f"Iteration {iteration}: Blame found commit {current_commit[:8]}")
            else:
                self._logger.debug(f"Iteration {iteration}: No blame commit found, ending traversal")

            if current_commit is None or current_commit == before_commit:
                # Even if traced to boundary commit or cannot continue, still record current before_commit
 # challenge versioncommit
                self._logger.debug(f"Iteration {iteration}: Reached end of history (blame={current_commit[:8] if current_commit else 'None'}), recording before_commit")
                history.append((before_commit, before_lines, before_file_path))
                break

            # Step 1: Map lines from before_commit (A) to current_commit (B) using simple diff offset
            # This is because git blame tells us B modified these lines, so we just need line offset
            current_file_path = self.project.get_responding_file_name(current_commit)
            self._logger.debug(f"Iteration {iteration}: Diffing {before_commit[:8]} -> {current_commit[:8]}")
            diff_content = run_command(
                f'git diff {before_commit}:{before_file_path} {current_commit}:{current_file_path}',
                path=self.project.npm_project_path
            ).stdout
            
            after_lines = parse_line_number_mapping(diff_content, before_lines[0])
            after_lines = (after_lines, before_lines[-1])
            self._logger.debug(f"Iteration {iteration}: Mapped lines: {before_lines[0]} -> {after_lines[0]}")
            
            # Move to parent commit of current_commit (B -> C)
            parent_commit = get_parent_commit(
                current_commit,
                self.project.npm_project_path
            )
            parent_file_path = self.project.get_responding_file_name(parent_commit)
            self._logger.debug(f"Iteration {iteration}: Got parent commit {parent_commit[:8] if parent_commit else 'None'}")
            
            # Record current position
            history.append((current_commit, after_lines, current_file_path))

            # Check if file was added (might be a rename/move)
            git_info = run_command(
                f'git show {current_commit} --name-status',
                path=self.project.npm_project_path
            ).stdout
            
            if f'A\t{current_file_path}' in git_info:
                self._logger.debug(f"Iteration {iteration}: File was added in {current_commit[:8]}, checking for rename/move")
                
                # Try to find if this is a file rename/move by checking for deleted files
                renamed_file = self._detect_file_rename(
                    current_commit,
                    current_file_path,
                    after_lines[0],
                    git_info
                )
                
                if renamed_file:
                    self._logger.info(f"Iteration {iteration}: Detected file rename: {renamed_file} -> {current_file_path}")
                    # Update file path to continue tracking the old file
                    current_file_path = renamed_file
                    parent_file_path = renamed_file
                    # Don't break, continue tracking with the renamed file
                else:
                    self._logger.debug(f"Iteration {iteration}: No rename detected, file truly added, stopping")
                    break

            # Check if we've gone too far back
            challenge_commit = self.project.get_challenge_commit()
            is_earlier = is_commit_earlier(
                challenge_commit,
                current_commit,
                self.project.npm_project_path
            )
            self._logger.debug(f"Iteration {iteration}: is_commit_earlier({challenge_commit[:8]}, {current_commit[:8]}) = {is_earlier}")
            if not is_earlier:
                self._logger.debug(f"Iteration {iteration}: Current commit {current_commit[:8]} is NOT earlier than challenge {challenge_commit[:8]}, stopping")
                break

            if not parent_commit:
                self._logger.debug(f"Iteration {iteration}: No parent commit, stopping")
                break

            # Step 2: Map lines from current_commit (B) to parent_commit (C) using LLM
            # This is because B actually modified the code, so we need semantic matching
            self._logger.debug(f"Iteration {iteration}: Calling LLM to map lines from {current_commit[:8]} to {parent_commit[:8]}")
            before_lines = self._get_line_map_llm(
                current_commit,
                after_lines,
                parent_commit,
                model
            )

            if before_lines is None or len(before_lines[0]) == 0:
                self._logger.debug(f"Iteration {iteration}: LLM mapping returned empty")
                # Check if parent is challenge commit - if so, save it before stopping
                if parent_commit == challenge_commit:
                    self._logger.debug(f"Iteration {iteration}: Parent {parent_commit[:8]} is challenge commit, saving before stopping")
                    # For the challenge commit, we use the lines that would have been tracked
                    # even though LLM couldn't map them (they might not exist yet in this version)
                    history.append((parent_commit, (after_lines, 'add'), parent_file_path))
                else:
                    self._logger.debug(f"Iteration {iteration}: Stopping traversal")
                break

            self._logger.debug(f"Iteration {iteration}: LLM mapped to lines {before_lines[0]} in parent commit")
            before_commit = parent_commit
            before_file_path = parent_file_path

        return history

    def _get_line_map_llm(
        self,
        current_commit: str,
        current_hunk_lines: Tuple[List[int], str],
        before_commit: str,
        model: str,
    ) -> Optional[Tuple[List[int], str]]:
        """
        Map lines between commits using LLM assistance.
        
        Args:
            current_commit: Current commit hash
            current_hunk_lines: Current line numbers and type
            before_commit: Previous commit hash
            model: Model identifier
            
        Returns:
            Mapped line numbers and type, or None if mapping fails
        """
        self._logger.debug(f"Line mapping: {current_commit[:8]} -> {before_commit[:8]}")
        temp_type = current_hunk_lines[-1]
        current_file_path = self.project.get_responding_file_name(current_commit)
        before_file_path = self.project.get_responding_file_name(before_commit)

        if before_file_path is None:
            return None

        # Get diff content
        commit_content = run_command(
            f'git diff {before_commit}:{before_file_path} {current_commit}:{current_file_path}',
            path=self.project.npm_project_path
        ).stdout

        rev_commit_content = run_command(
            f'git diff {current_commit}:{current_file_path} {before_commit}:{before_file_path}',
            path=self.project.npm_project_path
        ).stdout

        current_file_content = run_command(
            f'git show {current_commit}:{current_file_path}',
            path=self.project.npm_project_path
        ).stdout

        before_file_content = run_command(
            f'git show {before_commit}:{before_file_path}',
            path=self.project.npm_project_path
        ).stdout

        # Get function range for context
        function_range = self._get_function_range(
            current_file_content,
            before_file_content,
            current_hunk_lines[0]
        )

        # Filter target lines
        target_lines = self._line_filter(current_hunk_lines[0], commit_content)
        current_line_content = self.get_line_content(
            current_commit,
            current_file_path,
            target_lines
        )

        # Get removed lines for LLM mapping
        removed_lines, line_number_map = self._get_removed_lines(commit_content, function_range)
        
        if len(removed_lines) == 0:
            function_range = [-1, -1]
            removed_lines, line_number_map = self._get_removed_lines(commit_content, function_range)

        before_lines = []

        if len(removed_lines) > 0:
            # Use LLM to map lines (pass both code list and line number mapping)
            before_lines = self._llm_map_lines(
                (removed_lines, line_number_map),
                current_line_content,
                model
            )

            # Validate LLM output (check if line numbers are valid)
            valid_line_numbers = set(line_number_map.values())
            
            feedback_count = 0
            while feedback_count < 5:
                all_valid = all(line in valid_line_numbers for line in before_lines)
                if all_valid:
                    break
                
                before_lines = self._llm_map_lines(
                    (removed_lines, line_number_map),
                    current_line_content,
                    model,
                    feedback=before_lines
                )
                feedback_count += 1

        # Handle empty results
        if len(before_lines) == 0:
            # Try to find renamed lines (when code moved between files)
            renamed_lines = self._find_rename_line(current_commit, current_line_content)
            if renamed_lines:
                before_lines = renamed_lines
                # Re-fetch content after potential file rename detection
                before_file_content = run_command(
                    f'git show {before_commit}:{before_file_path}',
                    path=self.project.npm_project_path
                ).stdout
        
        if len(before_lines) == 0:
            if current_hunk_lines[-1] == 'add':
                before_line = self._get_add_place(
                    commit_content,
                    current_line_content,
                    target_lines
                )
                if before_line is None:
                    return None
                
                before_file_lines = before_file_content.split('\n')
                before_file_length = len(before_file_lines)
                
                if before_line > before_file_length or \
                   (before_line == before_file_length and before_file_lines[-1].strip() == ''):
                    before_line = -1
                
                before_lines = [before_line]
            else:
                before_lines_result = self._get_add_lines(commit_content, target_lines)
                temp_type = 'add'
                if before_lines_result is None:
                    return None
                before_lines = before_lines_result
        else:
            # before_lines is already a list of line numbers from LLM
            # No need for _exactly_map anymore since LLM returns line numbers directly
            
            # Optional: Filter lines using LLM for 1-to-n mapping
            # Note: _filter_1nmap_lines expects code text, so we need to convert line numbers back
            if len(before_lines) > 1:
                # Convert line numbers to code text for filtering
                before_file_lines = before_file_content.split('\n')
                line_texts = []
                for line_no in before_lines:
                    if 1 <= line_no <= len(before_file_lines):
                        line_texts.append(before_file_lines[line_no - 1].strip())
                
                # Filter and convert back to line numbers
                filtered_texts = self._filter_1nmap_lines(line_texts, model)
                filtered_line_numbers = []
                for text in filtered_texts:
                    for line_no in before_lines:
                        if 1 <= line_no <= len(before_file_lines):
                            if before_file_lines[line_no - 1].strip() == text:
                                filtered_line_numbers.append(line_no)
                                break
                before_lines = filtered_line_numbers if filtered_line_numbers else before_lines
            
            before_lines.sort()

        # Handle remaining lines
        rest_lines = [i for i in current_hunk_lines[0] if i not in target_lines]
        from core.utils.parsing import parse_line_number_mapping
        rest_lines = parse_line_number_mapping(rev_commit_content, rest_lines)
        before_lines.extend(rest_lines)

        return (before_lines, temp_type)

    def _llm_map_lines(
        self,
        removed_lines: str,
        current_hunk_lines: List[str],
        model: str,
        feedback: Optional[List[str]] = None,
        feedback_error: bool = False,
    ) -> List[str]:
        """
        Use LLM to map code lines between versions.
        
        Args:
            removed_lines: Tuple of (removed_code_list, line_number_map)
                - removed_code_list: List of removed code strings
                - line_number_map: Dict mapping code to line numbers
            current_hunk_lines: Current line contents
            model: Model identifier
            feedback: Previous invalid output for feedback
            feedback_error: Whether previous output had format error
            
        Returns:
            List of mapped line numbers (as integers)
        """
        from core.managers.llm import LLMHandler
        
        # Extract code list and line number mapping
        if isinstance(removed_lines, tuple):
            removed_code_list, line_number_map = removed_lines
            removed_lines_str = '\n'.join(removed_code_list)
        else:
            # Backward compatibility: if string is passed directly
            removed_lines_str = removed_lines
            line_number_map = {}
        
        target_content = '\n'.join(current_hunk_lines)
        
        prompt = f'''As a JavaScript code semantics expert, you are required to identify the code snippet from the target codebase that is most semantically similar to the given code. Please try to find corresponding code for each line as much as possible.

Input: Target codebase and given code.

Output:
The code from the target codebase that is most semantically similar to the given code.

Output Format Requirements:
1. Output a Python-style list where each element contains only one line of content, e.g., ["line A content", "line B content" ... "line N content"].
2. The output code must be from the target codebase, not the given code.
3. Do not use ``` or any explanatory text.
4. If no match is found, output [].

Now, process the following input:

Target codebase:

{removed_lines_str}

Given code:

{target_content}

The most semantically similar lines:
'''
        
        if feedback is not None:
            prompt += f'''
Please note that in your last response, you output code ({feedback}) that was not in the target codebase. Do not make this mistake again. Please output code that is exactly the same as in the target codebase.
'''

        if feedback_error:
            prompt += '''Please note that your returned result does not conform to our output format (Output a Python-style list where each element contains only one line of content, e.g., ["line A content", "line B content" ... "line N content"]). Please re-output it.'''

        # Invoke LLM
        self._logger.debug(f"LLM mapping: {len(current_hunk_lines)} lines, prompt length: {len(prompt)} chars")
        self._logger.debug(f"========== LLM Mapping Prompt ==========")
        self._logger.debug(f"{prompt}")
        self._logger.debug(f"========== End Prompt ==========")
        
        llm_handler = LLMHandler(self.project)
        llm_output = llm_handler.infer(prompt, model)
        
        self._logger.debug(f"LLM output length: {len(llm_output)} chars")
        self._logger.debug(f"========== LLM Mapping Output ==========")
        self._logger.debug(f"{llm_output}")
        self._logger.debug(f"========== End Output ==========")

        try:
            import ast
            result = ast.literal_eval(
                llm_output[llm_output.find('['):llm_output.rfind(']')+1]
            )
            # Result should be a list of code strings
            if isinstance(result, list):
                # Map code strings to line numbers using line_number_map
                line_numbers = []
                for code_str in result:
                    if isinstance(code_str, str):
                        # Look up line number in the mapping
                        if code_str in line_number_map:
                            line_numbers.append(line_number_map[code_str])
                        else:
                            # Fallback: search in removed_code_list to get position
                            # This handles cases where LLM returns slightly different formatting
                            self._logger.warning(f"Code not found in map: '{code_str}', searching in list")
                            for i, code in enumerate(removed_code_list):
                                if code.strip() == code_str.strip():
                                    if code in line_number_map:
                                        line_numbers.append(line_number_map[code])
                                    break
                
                self._logger.debug(f"LLM mapping result: {len(line_numbers)} lines matched (from {len(result)} code strings)")
                return line_numbers
            else:
                self._logger.warning(f"LLM output is not a list: {type(result)}")
                return []
        except Exception as e:
            self._logger.warning(f"Failed to parse LLM output: {e}")
            # Retry with feedback_error if not already retrying
            if not feedback_error:
                return self._llm_map_lines(
                    removed_lines,
                    current_hunk_lines,
                    model,
                    feedback=None,
                    feedback_error=True
                )
            return []

    def _get_function_range(
        self,
        contentA: str,
        contentB: str,
        linosA: List[int]
    ) -> List[int]:
        """Get function range containing given line numbers.
        
        Uses tree-sitter to parse JavaScript and find the function that
        contains the target lines, then finds the corresponding function
        in the target version.
        
        Args:
            contentA: Content of file A (with the lines we're tracking)
            contentB: Content of file B (target to find function range in)
            linosA: Line numbers in file A
            
        Returns:
            [start_line, end_line] of function in B, or [-1, -1] if not found
        """
        function_dictA = self._ast_parse_functions(contentA)
        function_dictB = self._ast_parse_functions(contentB)
        
        # Find the function in A that contains our lines
        map_function = self._get_map_function(linosA, function_dictA)
        
        if map_function is None:
            return [-1, -1]
        
        # Find the same function in B by name
        for line_range, (func_name, func_body) in function_dictB.items():
            if map_function == func_name:
                return list(line_range)
        
        return [-1, -1]

    def _ast_parse_functions(self, source_content: str) -> Dict[Tuple[int, int], Tuple[str, str]]:
        """Parse JavaScript source and extract function ranges.
        
        Args:
            source_content: JavaScript source code
            
        Returns:
            Dict mapping (start_line, end_line) to (function_name, function_body)
        """
        try:
            import tree_sitter_javascript
            from tree_sitter import Language, Parser
            
            source_bytes = source_content.encode('utf-8')
            JS_LANGUAGE = Language(tree_sitter_javascript.language())
            parser = Parser(JS_LANGUAGE)
            tree = parser.parse(source_bytes)
            
            function_ranges = {}
            
            def extract_functions(node, code):
                if node.type == 'function_declaration':
                    name_node = node.child_by_field_name('name')
                    if name_node:
                        func_name = code[name_node.start_byte:name_node.end_byte].decode('utf8')
                        func_body = code[node.start_byte:node.end_byte].decode('utf8')
                        start_line = node.start_point[0] + 1
                        end_line = node.end_point[0] + 1
                        function_ranges[(start_line, end_line)] = (func_name, func_body)
                        
                elif node.type == 'function_expression':
                    parent = node.parent
                    func_name = 'Anonymous Function'
                    
                    if parent.type == 'assignment_expression':
                        left_node = parent.child_by_field_name('left')
                        if left_node.type == 'identifier':
                            func_name = left_node.text.decode('utf8')
                        elif left_node.type == 'member_expression':
                            obj = left_node.child_by_field_name('object').text.decode('utf8')
                            prop = left_node.child_by_field_name('property').text.decode('utf8')
                            func_name = f"{obj}.{prop}"
                    elif parent.type == 'variable_declarator':
                        name_node = parent.child_by_field_name('name')
                        if name_node:
                            func_name = code[name_node.start_byte:name_node.end_byte].decode('utf8')
                    elif parent.type == 'pair':
                        key_node = parent.child_by_field_name('key')
                        if key_node:
                            func_name = code[key_node.start_byte:key_node.end_byte].decode('utf8')
                    
                    source_node = parent if func_name != 'Anonymous Function' else node
                    func_body = code[source_node.start_byte:source_node.end_byte].decode('utf8')
                    start_line = source_node.start_point[0] + 1
                    end_line = source_node.end_point[0] + 1
                    function_ranges[(start_line, end_line)] = (func_name, func_body)
                    
                elif node.type == 'arrow_function':
                    func_name = 'Anonymous Arrow Function'
                    if node.parent:
                        name_node = node.parent.child_by_field_name('name')
                        if not name_node:
                            name_node = node.parent.child_by_field_name('key')
                        if name_node:
                            func_name = code[name_node.start_byte:name_node.end_byte].decode('utf8')
                    
                    func_body = code[node.start_byte:node.end_byte].decode('utf8')
                    start_line = node.start_point[0] + 1
                    end_line = node.end_point[0] + 1
                    function_ranges[(start_line, end_line)] = (func_name, func_body)
                    
                elif node.type == 'method_definition':
                    name_node = node.child_by_field_name('name')
                    if name_node:
                        func_name = code[name_node.start_byte:name_node.end_byte].decode('utf8')
                        func_body = code[node.start_byte:node.end_byte].decode('utf8')
                        start_line = node.start_point[0] + 1
                        end_line = node.end_point[0] + 1
                        function_ranges[(start_line, end_line)] = (func_name, func_body)
                
                for child in node.children:
                    extract_functions(child, code)
            
            extract_functions(tree.root_node, source_bytes)
            return function_ranges
            
        except Exception as e:
            self._logger.warning(f"Failed to parse functions: {e}")
            return {}

    def _get_map_function(
        self,
        linos: List[int],
        function_dict: Dict[Tuple[int, int], Tuple[str, str]]
    ) -> Optional[str]:
        """Find the outermost function containing the given line numbers.
        
        Args:
            linos: Line numbers to locate
            function_dict: Dict from _ast_parse_functions
            
        Returns:
            Function name or None if not found
        """
        target_functions = []
        
        for line in linos:
            target_function = None
            target_range = None
            
            for line_range, (func_name, func_body) in function_dict.items():
                start, end = line_range
                if start <= line <= end:
                    # Skip anonymous functions
                    if 'Anonymous' in func_name:
                        continue
                    
                    if target_function is None:
                        target_function = (line_range, (func_name, func_body))
                        target_range = line_range
                    elif start >= target_range[0] and end <= target_range[1]:
                        # More specific (inner) function
                        target_function = (line_range, (func_name, func_body))
                        target_range = line_range
            
            if target_function is not None:
                target_functions.append(target_function)
        
        # Find the outermost function that contains all target lines
        for func in target_functions:
            if func is None:
                continue
            
            func_range = func[0]
            is_outermost = all(
                func_range[0] <= other[0][0] and func_range[1] >= other[0][1]
                for other in target_functions if other is not None
            )
            
            if is_outermost:
                return func[1][0]  # Return function name
        
        return None

    def _line_filter(self, lines: List[int], diff_content: str) -> List[int]:
        """Filter lines to only include those that were actually added in the diff.
        
        This identifies which lines in the target version correspond to
        added lines in the diff, helping focus LLM matching on changed code.
        
        Args:
            lines: Line numbers to filter
            diff_content: Unified diff content
            
        Returns:
            Line numbers that correspond to added lines in the diff
        """
        from io import StringIO
        from unidiff import PatchSet
        
        try:
            patch_set = PatchSet(StringIO(diff_content))
            added_lines = []
            
            for patched_file in patch_set:
                for hunk in patched_file:
                    for line in hunk:
                        if line.is_added:
                            target_line = line.target_line_no
                            if target_line in lines:
                                added_lines.append(target_line)
            
            return added_lines if added_lines else lines
        except Exception:
            return lines

    def _get_removed_lines(
        self,
        diff_content: str,
        function_range: List[int]
    ) -> Tuple[List[str], Dict[str, int]]:
        """Extract removed lines from diff within function range.
        
        This extracts lines that were deleted in the diff, optionally
        constrained to a specific function range for more focused matching.
        Returns pure code lines without line numbers, plus a mapping dict.
        
        Args:
            diff_content: Unified diff content
            function_range: [start_line, end_line] or [-1, -1] for no constraint
            
        Returns:
            Tuple of (removed_lines, line_number_map)
            - removed_lines: List of code strings (e.g., ["var x;", "};"])
            - line_number_map: Dict mapping code to line number (e.g., {"var x;": 19, "};": 18})
        """
        from io import StringIO
        from unidiff import PatchSet
        
        if function_range == [-1, -1]:
            line_range = range(1, 100000)
        else:
            line_range = range(function_range[0], function_range[1] + 1)
        
        removed_lines = []
        line_number_map = {}
        
        try:
            patch_set = PatchSet(StringIO(diff_content))
            
            for patch in patch_set:
                for hunk in patch:
                    for line in hunk:
                        if line.is_removed and line.source_line_no in line_range:
                            code = line.value.strip()
                            removed_lines.append(code)
                            # Store mapping from code to line number
                            # For duplicate code, keep the first occurrence
                            if code not in line_number_map:
                                line_number_map[code] = line.source_line_no
        except Exception:
            # Fallback to simple parsing (without line numbers)
            for line in diff_content.split('\n'):
                if line.startswith('-') and not line.startswith('---'):
                    removed_lines.append(line[1:].strip())
        
        return removed_lines, line_number_map

    def _exactly_map(
        self,
        target_content: str,
        lines: List[str],
        function_range: List[int]
    ) -> List[int]:
        """Map line contents to line numbers in target using similarity matching.
        
        Uses SequenceMatcher to find lines with >95% similarity, allowing
        for minor formatting differences.
        
        Args:
            target_content: Content of target file
            lines: Line contents to find
            function_range: [start_line, end_line] or [-1, -1] for no constraint
            
        Returns:
            Line numbers in target that match the given lines
        """
        from difflib import SequenceMatcher
        
        def normalize(s: str) -> str:
            return s.strip().replace(" ", "")
        
        if function_range == [-1, -1]:
            line_range = range(1, 100000)
        else:
            line_range = range(function_range[0], function_range[1] + 1)
        
        target_lines = [line.strip() for line in target_content.splitlines()]
        result = []
        remaining_lines = lines.copy()  # Track which lines still need to be matched
        
        for i, target_line in enumerate(target_lines, start=1):
            if i not in line_range:
                continue
            
            for line in remaining_lines:
                similarity = SequenceMatcher(
                    None,
                    normalize(line),
                    normalize(target_line)
                ).ratio()
                
                if similarity > 0.95:
                    result.append(i)
                    remaining_lines.remove(line)  # Remove matched line to avoid duplicate matching
                    break
        
        result.sort()
        return result

    def _get_add_place(
        self,
        diff_content: str,
        line_content: List[str],
        target_lines: List[int]
    ) -> Optional[int]:
        """Find where added lines should be placed."""
        from core.utils.parsing import parse_unidiff
        from io import StringIO
        from unidiff import PatchSet
        
        try:
            patch = PatchSet(StringIO(diff_content))
            max_line = max(target_lines)
            
            for patched_file in patch:
                for hunk in patched_file:
                    for line in hunk:
                        if (line.target_line_no is not None and 
                            line.target_line_no > max_line and 
                            line.source_line_no is not None):
                            return line.source_line_no
        except Exception:
            pass
        
        return None

    def _get_add_lines(
        self,
        diff_content: str,
        target_lines: List[int]
    ) -> Optional[List[int]]:
        """Get line numbers for added code."""
        from unidiff import PatchSet
        from io import StringIO
        
        try:
            patch = PatchSet(StringIO(diff_content))
            max_line = max(target_lines) if target_lines else 0
            
            for patched_file in patch:
                for hunk in patched_file:
                    for line in hunk:
                        if (line.target_line_no is not None and 
                            line.target_line_no > max_line and 
                            line.source_line_no is not None):
                            return [line.source_line_no]
        except Exception:
            pass
        
        return None

    def _detect_file_rename(
        self,
        commit: str,
        added_file: str,
        target_lines: List[int],
        git_status: str
    ) -> Optional[str]:
        """
        Detect if a file addition is actually a file rename/move.
        
        When a file is added and another file is deleted in the same commit,
        this checks if they contain similar content to identify renames.
        
        Args:
            commit: Commit hash where file was added
            added_file: Path of the added file
            target_lines: Line numbers we're tracking in the added file
            git_status: Output from 'git show --name-status'
            
        Returns:
            Path of the original file if rename detected, None otherwise
        """
        try:
            # Extract deleted files from git status
            deleted_files = []
            for line in git_status.split('\n'):
                if line.startswith('D\t'):
                    deleted_file = line[2:].strip()
                    # Only consider .js files
                    if deleted_file.endswith('.js'):
                        deleted_files.append(deleted_file)
            
            if not deleted_files:
                self._logger.debug(f"No deleted files found in commit {commit[:8]}")
                return None
            
            self._logger.debug(f"Found {len(deleted_files)} deleted files: {deleted_files}")
            
            # Get content of target lines from the added file
            try:
                added_content = run_command(
                    f'git show {commit}:{added_file}',
                    path=self.project.npm_project_path
                ).stdout
                added_lines = added_content.split('\n')
                
                # Get content around target lines for comparison
                target_content = []
                for line_no in target_lines:
                    if 0 < line_no <= len(added_lines):
                        target_content.append(added_lines[line_no - 1].strip())
                
                if not target_content:
                    self._logger.debug("No target content to compare")
                    return None
                    
            except Exception as e:
                self._logger.warning(f"Failed to read added file content: {e}")
                return None
            
            # Check each deleted file for similarity
            from difflib import SequenceMatcher
            best_match = None
            best_similarity = 0.0
            
            for deleted_file in deleted_files:
                try:
                    # Get parent commit to read deleted file
                    parent_commit = get_parent_commit(commit, self.project.npm_project_path)
                    if not parent_commit:
                        continue
                        
                    deleted_content = run_command(
                        f'git show {parent_commit}:{deleted_file}',
                        path=self.project.npm_project_path
                    ).stdout
                    deleted_lines = deleted_content.split('\n')
                    
                    # Strategy 1: Check if target lines exist in deleted file
                    target_match_count = 0
                    for target_line in target_content:
                        for deleted_line in deleted_lines:
                            if SequenceMatcher(None, target_line, deleted_line.strip()).ratio() > 0.8:
                                target_match_count += 1
                                break
                    
                    target_similarity = target_match_count / len(target_content) if target_content else 0
                    
                    # Strategy 2: Calculate overall file similarity (for context)
                    file_similarity = SequenceMatcher(
                        None,
                        added_content,
                        deleted_content
                    ).ratio()
                    
                    # Combined score: prioritize target line matches
                    combined_similarity = target_similarity * 0.7 + file_similarity * 0.3
                    
                    self._logger.debug(
                        f"Comparison with {deleted_file}: "
                        f"target={target_similarity:.2f}, file={file_similarity:.2f}, "
                        f"combined={combined_similarity:.2f}"
                    )
                    
                    if combined_similarity > best_similarity:
                        best_similarity = combined_similarity
                        best_match = deleted_file
                        
                except Exception as e:
                    self._logger.debug(f"Failed to compare with {deleted_file}: {e}")
                    continue
            
            # Consider it a rename if similarity > 0.4 (lowered threshold for refactored code)
            if best_match and best_similarity > 0.4:
                self._logger.info(f"Detected rename: {best_match} -> {added_file} (similarity: {best_similarity:.2f})")
                return best_match
            else:
                self._logger.debug(f"Best similarity {best_similarity:.2f} below threshold, not a rename")
                return None
                
        except Exception as e:
            self._logger.warning(f"Error detecting file rename: {e}")
            return None

    def _find_rename_line(
        self,
        commit: str,
        line_content: List[str]
    ) -> List[str]:
        """
        Find lines that were moved/renamed between files in a commit.
        
        When code is refactored from one file to another, this method
        identifies the moved lines by checking if the commit modifies
        multiple JS files and finding similar content.
        
        Args:
            commit: Commit hash to check
            line_content: Content of lines to find
            
        Returns:
            List of matched line contents, or empty list if not found
        """
        from difflib import SequenceMatcher
        from io import StringIO
        from unidiff import PatchSet
        
        try:
            # Get commit diff, filtering to JS files
            commit_output = run_command(
                f'git show {commit}',
                path=self.project.npm_project_path
            ).stdout
            
            commit_content = self._filter_js_hunks(commit_output)
            if not commit_content:
                return []
            
            patch_set = PatchSet(StringIO(commit_content))
            
            # Check if multiple JS files were modified
            js_file_count = sum(
                1 for pf in patch_set 
                if pf.source_file.endswith('.js')
            )
            
            if js_file_count < 2:
                return []
            
            result_lines = []
            target_file = None
            
            for patched_file in patch_set:
                # Collect removed lines from each file
                removed_lines = []
                for hunk in patched_file:
                    for line in hunk:
                        if line.is_removed:
                            removed_lines.append((line.value.strip(), line.source_line_no))
                
                # Check if any of our target lines match removed lines
                for target_line in line_content:
                    for removed_line, line_number in removed_lines:
                        similarity = SequenceMatcher(
                            None,
                            target_line,
                            removed_line
                        ).ratio()
                        
                        if similarity >= 0.9:
                            result_lines.append(removed_line)
                            target_file = patched_file.source_file
            
            if result_lines and target_file:
                # Update project's name history for file tracking
                current_file = self.project.get_responding_file_name(commit)
                if hasattr(self.project, 'name_history'):
                    self.project.name_history.append((commit, current_file))
                    
                    # Get rename history for the target file
                    if hasattr(self.project, 'get_target_name_history'):
                        import os
                        target_path = target_file[2:] if target_file.startswith('./') else target_file
                        rename_history = self.project.get_target_name_history(
                            os.path.join(self.project.npm_project_path, target_path)
                        )
                        self.project.name_history.extend(rename_history)
                    
                    if hasattr(self.project, 'write_name_history'):
                        self.project.write_name_history()
            
            return result_lines
            
        except Exception as e:
            self._logger.warning(f"Error finding rename lines: {e}")
            return []

    def _filter_js_hunks(self, git_show_output: str) -> str:
        """
        Filter git show output to only include JavaScript file hunks.
        
        Args:
            git_show_output: Output from git show command
            
        Returns:
            Filtered diff content with only JS files
        """
        import re
        
        file_pattern = re.compile(r'^diff --git a/(.*) b/(.*)$')
        
        js_file = False
        result = []
        
        for line in git_show_output.splitlines():
            file_match = file_pattern.match(line)
            if file_match:
                js_file = file_match.group(1).endswith('.js')
                if js_file:
                    result.append(line)
            elif js_file:
                result.append(line)
        
        return '\n'.join(result)

    def _filter_1nmap_lines(self, lines: List[str], model: str) -> List[str]:
        """
        Filter mapped lines to keep only those functionally related to current line.
        
        This is used when LLM maps to multiple lines (1-to-n mapping) and we need
        to filter out unrelated lines using semantic analysis.
        
        Args:
            lines: List of candidate line contents
            model: Model identifier for LLM
            
        Returns:
            Filtered list of related line contents
        """
        result_lines = []
        for line in lines:
            if self.is_related_llm(self.current_line, line, model):
                result_lines.append(line)
        return result_lines

    def is_related_llm(
        self,
        code_blockA: str,
        code_blockB: str,
        model: str
    ) -> bool:
        """
        Use LLM to determine if two code blocks are functionally related.
        
        This method is called by _filter_1nmap_lines() to validate that mapped
        lines are semantically related to the original vulnerable code.
        
        Args:
            code_blockA: First code block (typically the vulnerable code)
            code_blockB: Second code block (candidate mapped code)
            model: Model identifier
            
        Returns:
            True if related, False otherwise
        """
        from core.managers.llm import LLMHandler
        
        prompt = f'''Please understand the following two code blocks and analyze whether there is functional reuse between them. Output yes or no only and do not output other content.

Code Block A:{code_blockA}

Code Block B:{code_blockB}'''

        llm_handler = LLMHandler(self.project)
        llm_output = llm_handler.infer(prompt, model)  # Fix parameter order: content first, model second

        if 'yes' in llm_output.lower():
            return True
        elif 'no' in llm_output.lower():
            return False
        
        return False

    def _get_target_line_numbers(self) -> List[Dict[str, Any]]:
        """
        Extract target line numbers from patch hunks.

        Returns:
            List of dicts with line info for each hunk
        """
        patches = self.project.unidiff_patch
        if not patches:
            return []

        # Get pre-patch file content
        pre_patch_file = self.project.get_responding_file_name(self._pre_patch_commit)
        if not pre_patch_file:
            return []

        results = []
        for patch in patches:
            for hunk in patch:
                # Collect removed/modified line numbers
                source_lines = []
                target_lines = []
                current_source = hunk.source_start
                current_target = hunk.target_start
                hunk_type = "modify"

                has_removed = False
                has_added = False

                for line in hunk:
                    if line.is_removed:
                        source_lines.append(current_source)
                        current_source += 1
                        has_removed = True
                    elif line.is_added:
                        target_lines.append(current_target)
                        current_target += 1
                        has_added = True
                    else:
                        current_source += 1
                        current_target += 1

                if has_added and not has_removed:
                    hunk_type = "add"
                elif has_removed and not has_added:
                    hunk_type = "remove"

                results.append({
                    "lines": source_lines if source_lines else target_lines,
                    "type": hunk_type,
                    "source_start": hunk.source_start,
                    "source_end": hunk.source_start + hunk.source_length - 1,
                })

        return results

    def _track_lines_through_history(
        self,
        line_numbers: List[int],
        model: str,
    ) -> List[Tuple[str, List[int], str]]:
        """
        Track lines backwards through git history.

        Args:
            line_numbers: Starting line numbers
            model: Model identifier

        Returns:
            List of (commit, lines, file_path) tuples
        """
        history = []
        current_lines = line_numbers
        current_commit = self._pre_patch_commit
        current_file = self.project.get_responding_file_name(current_commit)

        if not current_file:
            return []

        while True:
            if not current_lines or current_lines[0] == -1:
                history.append((current_commit, [-1], current_file))
                break

            # Get blame info
            blame_commit = self._get_blame_commit(
                current_commit,
                current_file,
                current_lines,
            )

            if not blame_commit or blame_commit == current_commit:
                break

            # Map lines to after-state
            next_file = self.project.get_responding_file_name(blame_commit)
            if not next_file:
                break

            # Get diff and map lines
            diff = get_diff_between_commits(
                current_commit,
                blame_commit,
                current_file,
                next_file,
                self.project.npm_project_path,
            )

            next_lines = self._map_lines_through_diff(diff, current_lines)
            history.append((current_commit, current_lines, current_file))

            # Move to next iteration
            current_commit = get_parent_commit(
                blame_commit,
                self.project.npm_project_path,
            )
            current_lines = next_lines
            current_file = next_file

            if not current_commit:
                break

        return history

    def _get_blame_commit(
        self,
        commit: str,
        file_path: str,
        line_numbers: List[int],
    ) -> Optional[str]:
        """
        Get the most recent blame commit for given lines.

        Args:
            commit: Commit to blame at
            file_path: File path
            line_numbers: Line numbers to blame

        Returns:
            Most recent commit hash or None
        """
        self._logger.debug(f"Git blame: commit={commit[:8]}, file={file_path}, lines={line_numbers}")
        all_commits = []

        for line in line_numbers:
            blame_cmd = f"git blame -L {line},{line} {commit} -- {file_path}"
            self._logger.debug(f"Executing: {blame_cmd}")
            
            blame_output = run_git_blame(
                commit,
                file_path,
                line,
                self.project.npm_project_path,
            )
            
            self._logger.debug(f"Blame output for line {line}:")
            self._logger.debug(f"  {blame_output.strip() if blame_output else '(empty)'}")
            
            commits = parse_git_blame_output(blame_output)
            self._logger.debug(f"  Parsed commits: {commits}")
            all_commits.extend(commits)

        if not all_commits:
            self._logger.warning(f"No commits found in blame output for lines {line_numbers}")
            return None
        
        self._logger.debug(f"All blame commits collected: {all_commits}")

        # Find most recent commit
        result = None
        for c in all_commits:
            if result is None:
                result = c
            elif not is_commit_earlier(c, result, self.project.npm_project_path):
                result = c
        
        self._logger.info(f"Selected most recent blame commit: {result[:8] if result else 'None'}")
        return result

    def _map_lines_through_diff(
        self,
        diff_content: str,
        source_lines: List[int],
    ) -> List[int]:
        """
        Map source line numbers to target through diff.

        Args:
            diff_content: Unified diff content
            source_lines: Line numbers in source

        Returns:
            Corresponding line numbers in target
        """
        if not diff_content:
            return source_lines

        # Parse diff to build line mapping
        # This is a simplified implementation
        from core.utils.parsing import parse_line_number_mapping

        return parse_line_number_mapping(diff_content, source_lines)

    def _map_to_target_version(
        self,
        target_commit: str,
        history: List[Tuple[str, List[int], str]],
        hunk_index: int,
    ) -> Optional[LocalizationResult]:
        """
        Map localization to target version.

        Args:
            target_commit: Target commit to map to
            history: Tracking history
            hunk_index: Index of the hunk

        Returns:
            LocalizationResult or None
        """
        if not history:
            return None

        # Find nearest ancestor
        commits = [h[0] for h in history]
        nearest_idx = get_nearest_ancestor_commit(
            target_commit,
            commits,
            self.project.npm_project_path,
        )

        if nearest_idx is None:
            if history[-1][1] and history[-1][1][0] == -1:
                return LocalizationResult(
                    commit_id=target_commit,
                    line_numbers=[-1],
                    hunk_index=hunk_index,
                )
            return None

        base_commit, base_lines, base_file = history[nearest_idx]

        # Get diff from base to target
        target_file = self.project.get_responding_file_name(target_commit)
        if not target_file:
            return None

        diff = get_diff_between_commits(
            base_commit,
            target_commit,
            base_file,
            target_file,
            self.project.npm_project_path,
        )

        mapped_lines = self._map_lines_through_diff(diff, base_lines)
        mapped_lines = sorted(set(mapped_lines))

        return LocalizationResult(
            commit_id=target_commit,
            line_numbers=mapped_lines,
            hunk_index=hunk_index,
            file_path=target_file,
        )
    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_line_content(
        self,
        commit: str,
        file_path: str,
        line_numbers: List[int],
    ) -> List[str]:
        """
        Get content of specific lines at a commit.

        Args:
            commit: Commit hash
            file_path: File path
            line_numbers: Line numbers to extract

        Returns:
            List of line contents
        """
        content = get_file_at_commit(
            commit,
            file_path,
            self.project.npm_project_path,
        )

        if not content:
            return []

        lines = content.splitlines()
        return [
            lines[n - 1] if 0 < n <= len(lines) else ""
            for n in line_numbers
        ]

    def load_localization_results(self, model: str) -> Dict[str, List[int]]:
        """
        Load saved localization results.

        Args:
            model: Model identifier

        Returns:
            Dict mapping commit to line numbers
        """
        result_file = self._localization_path / f"{model}.csv"

        if not result_file.exists():
            return {}

        results = {}
        for line in read_lines(result_file, skip_empty=True):
            parts = line.split("##")
            if len(parts) >= 2:
                commit = parts[0]
                lines = eval(parts[1]) if parts[1] else []
                results[commit] = lines

        return results

