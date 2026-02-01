"""
Baseline localizers for SCA-Repair.

Contains various baseline localization methods for comparison:
- Git blame-based line tracking
- Git log -L based tracking
- Similarity-based matching (with and without history)
- Direct LLM matching (without history)
- Function-level localization
- File-level localization (entire file baseline)
"""

import os
import re
import logging
from io import StringIO
from pathlib import Path
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass
from difflib import SequenceMatcher

from unidiff import PatchSet
from tree_sitter import Language, Parser
import tree_sitter_javascript

try:
    import Levenshtein
except ImportError:
    Levenshtein = None

from core.managers.base import BaseManager
from core.project import Project
from core.utils.command import run_command
from core.utils.file import read_file, read_lines
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

# Import shared components from main localizer
from core.managers.localizer import (
    LocalizationResult,
    FaultLocalizer,
)

logger = logging.getLogger(__name__)


class BaselineLocalizer(FaultLocalizer):
    """
    Baseline localization methods for comparison experiments.
    
    Inherits from FaultLocalizer to reuse common utilities and
    provides various baseline methods:
    
    - localize_by_line: Git blame-based tracking
    - localize_by_line_log: Git log -L tracking
    - localize_with_history_similarity: History + similarity matching
    - localize_direct_similarity: Direct similarity matching
    - localize_direct_llm: Direct LLM matching
    - localize_by_function: Function-level localization
    - localize_by_file: File-level localization
    """

    def _get_continuous_hunk_content(self) -> List[List[str]]:
        """
        Extract continuous deleted lines from each hunk.
        
        Returns:
            List of deleted line lists for each hunk
        """
        result = []
        patches = self.project.unidiff_patch
        if not patches:
            return []
        
        for patched_file in patches:
            for hunk in patched_file:
                deleted_lines = []
                for line in hunk:
                    if line.is_removed:
                        deleted_lines.append(line.value.strip())
                result.append(deleted_lines)
        
        return result

    def execute(self, **kwargs) -> Any:
        """
        Execute baseline localization based on method.
        
        Available methods:
        - Git History-based:
          * line: Git blame tracking
          * line_log: Git log -L tracking
          * history_similarity: Git history + similarity matching
        
        - Direct matching (no history):
          * direct_llm: Direct LLM matching on target version
          * direct_similarity: Direct similarity matching on target version
        
        - Special methods:
          * function: Function-level context
          * file: Entire file (baseline)
          * context: Context-based localization
        """
        method = kwargs.get("method", "line")
        model = kwargs.get("model", "deepseek-api")

        # Git History-based methods
        if method == "line":
            return self.localize_by_line(model)
        elif method == "line_log":
            return self.localize_by_line_log(model)
        elif method == "history_similarity":
            return self.localize_with_history_similarity(model)
        
        # Direct matching methods (no history)
        elif method == "direct_llm":
            return self.localize_direct_llm(model)
        elif method == "direct_similarity":
            return self.localize_direct_similarity(model)
        
        # Special methods
        elif method == "function":
            return self.localize_by_function(model)
        elif method == "file":
            return self.localize_by_file()
        elif method == "context":
            return self.localization_context()
        
        # Legacy aliases
        elif method == "similarity":
            return self.localize_direct_similarity(model)

        return None

    # =========================================================================
    # Git Blame-based Line Localization
    # =========================================================================

    def localize_by_line(self, model: str) -> List[LocalizationResult]:
        """
        Localize vulnerable lines using git blame-based history tracking.

        Args:
            model: Model identifier for output file naming

        Returns:
            List of LocalizationResult for each hunk
        """
        output_file = self._localization_path / f"{model}.csv"
        results = []

        # Get line numbers from patch
        hunk_lines_list = self._get_target_line_numbers()

        for index, hunk_info in enumerate(hunk_lines_list):
            if hunk_info.get("type") == "add":
                self._logger.info(
                    f"Skipping add-only hunk at {self.project.final_patch_path}"
                )
                continue

            line_range = hunk_info.get("lines", [])
            if not line_range:
                continue

            # Track lines through history
            tracked = self._track_lines_through_history(line_range, model)

            # Get challenge version lines
            challenge_commit = self.project.get_challenge_commit()
            if not challenge_commit:
                continue

            result = self._map_to_target_version(
                challenge_commit,
                tracked,
                index,
            )

            if result:
                results.append(result)

                # Save to file
                with open(output_file, "a") as f:
                    print(
                        f"{result.commit_id}##{result.line_numbers}##{result.hunk_index}",
                        file=f,
                    )

        return results

    # =========================================================================
    # Git Log-based Line Localization
    # =========================================================================

    def localize_by_line_log(self, model: str) -> List[LocalizationResult]:
        """
        Localize vulnerable lines using git log -L to track line history.
        
        This method uses `git log -L` to directly track each line's history,
        which is more efficient than git blame for tracking multiple lines.

        Args:
            model: Model identifier for output file naming

        Returns:
            List of LocalizationResult for each hunk
        """
        output_file = self._localization_path / f"git_log.csv"
        output_file.write_text("")  # Clear file
        results = []

        # Get hunk line ranges
        hunk_lines = self._get_updown_linenos_for_chunk()

        for index, lines in enumerate(hunk_lines):
            # Track commits that changed these lines
            changed_commits = self._get_changed_commit_lines_log(lines)

            # Map to challenge version
            challenge_commit = self.project.get_challenge_commit()
            if not challenge_commit:
                continue

            nearest_idx = get_nearest_ancestor_commit(
                challenge_commit,
                [c[0] for c in changed_commits],
                self.project.npm_project_path,
            )

            if nearest_idx is None:
                continue

            base_commit, base_lineno, base_file = changed_commits[nearest_idx]
            
            # Get diff and map lines
            diff_content = run_command(
                f'git diff {base_commit}:{self.project.get_responding_file_name(base_commit)} '
                f'{challenge_commit}:{self.project.get_responding_file_name(challenge_commit)}',
                path=self.project.npm_project_path
            ).stdout

            from core.utils.parsing import parse_line_number_mapping
            changed_lines = parse_line_number_mapping(diff_content, base_lineno)
            changed_lines = sorted(list(set(changed_lines)))
            
            # Expand to continuous range
            if changed_lines:
                changed_lines = list(range(changed_lines[0], changed_lines[-1] + 1))

            result = LocalizationResult(
                commit_id=challenge_commit,
                line_numbers=changed_lines,
                hunk_index=index,
            )
            results.append(result)

            # Save to file
            with open(output_file, 'a') as f:
                print(f'{challenge_commit}##{changed_lines}##{index}', file=f)

        return results

    def _get_updown_linenos_for_chunk(self) -> List[List[int]]:
        """
        Get line ranges for each hunk chunk.
        
        Returns:
            List of line number lists for each chunk
        """
        patches = self.project.unidiff_patch
        if not patches:
            return []

        results = []
        for patch in patches:
            for hunk in patch:
                lines = []
                for line in hunk:
                    if line.is_removed:
                        lines.append(line.source_line_no)
                if lines:
                    results.append(lines)

        return results

    def _get_changed_commit_lines_log(
        self,
        lines: List[int]
    ) -> List[Tuple[str, List[int], str]]:
        """
        Track commits that changed given lines using git log -L.
        
        Args:
            lines: Line numbers to track
            
        Returns:
            List of (commit, lines, file_path) tuples
        """
        changed_commit_ids = []
        
        # For each line, get its change history
        for line in lines:
            commits = self._get_changed_commits_for_line(line)
            changed_commit_ids.extend(commits)

        # Sort commits by history order
        from core.utils.git import sort_commits_topologically
        changed_commit_ids = sort_commits_topologically(
            list(set(changed_commit_ids)),
            self.project.npm_project_path
        )

        # Track line evolution through commits
        before_lines = lines
        before_commit = get_parent_commit(
            self._patch_commit,
            self.project.npm_project_path
        )
        changed_commits = []

        for changed_commit_id in changed_commit_ids:
            current_file = self.project.get_responding_file_name(changed_commit_id)
            before_file = self.project.get_responding_file_name(before_commit)

            # Get diff
            diff_content = run_command(
                f'git diff {before_commit}:{before_file} {changed_commit_id}:{current_file}',
                path=self.project.npm_project_path
            ).stdout

            from core.utils.parsing import parse_line_number_mapping
            after_lines = parse_line_number_mapping(diff_content, before_lines)

            # Map lines through commit
            before_commit = get_parent_commit(
                changed_commit_id,
                self.project.npm_project_path
            )
            before_lines = self._get_mapped_lines_log(
                changed_commit_id,
                after_lines,
                before_commit
            )

            changed_commits.append((
                changed_commit_id,
                after_lines,
                current_file
            ))

        return changed_commits

    def _get_changed_commits_for_line(self, line: int) -> List[str]:
        """
        Get commits that changed a specific line using git log -L.
        
        Args:
            line: Line number
            
        Returns:
            List of commit hashes
        """
        target_file = self.project.get_responding_file_name(self._pre_patch_commit)
        log_command = f'git log -L {line},{line}:{target_file} {self._pre_patch_commit}'
        
        history = run_command(
            log_command,
            path=self.project.npm_project_path
        ).stdout

        # Parse commit IDs from log output
        commit_ids = []
        for log_line in history.split('\n'):
            if log_line.startswith('commit '):
                commit_id = log_line.split()[1]
                commit_ids.append(commit_id)

        return commit_ids

    def _get_mapped_lines_log(
        self,
        commit_id: str,
        after_lines: List[int],
        before_commit: str
    ) -> List[int]:
        """
        Map lines from after-commit to before-commit state.
        
        Args:
            commit_id: Current commit
            after_lines: Line numbers after commit
            before_commit: Parent commit
            
        Returns:
            Mapped line numbers
        """
        current_file = self.project.get_responding_file_name(commit_id)
        before_file = self.project.get_responding_file_name(before_commit)

        unchanged_lines = []
        changed_lines = []

        commit_content = run_command(
            f'git diff {commit_id}:{current_file} {before_commit}:{before_file}',
            path=self.project.npm_project_path
        ).stdout

        for line in after_lines:
            # Check if line was changed in this commit
            history = run_command(
                f'git log -L {line},{line}:{current_file} -n 1 {commit_id}',
                path=self.project.npm_project_path
            ).stdout

            if commit_id not in history:
                unchanged_lines.append(line)
                continue

            # Extract changed line numbers from history
            try:
                patch = PatchSet(StringIO(history))
                for patched_file in patch:
                    for hunk in patched_file:
                        for hunk_line in hunk:
                            if hunk_line.is_removed:
                                changed_lines.append(hunk_line.source_line_no)
            except Exception:
                pass

        # Map unchanged lines through diff
        from core.utils.parsing import parse_line_number_mapping
        unchanged_lines = parse_line_number_mapping(commit_content, unchanged_lines)

        return list(set(unchanged_lines + changed_lines))

    # =========================================================================
    # Git History + Similarity Matching
    # =========================================================================

    def localize_with_history_similarity(self, model: str) -> List[LocalizationResult]:
        """
        Localize using Git history tracking + similarity matching.
        
        Similar to history_llm but uses algorithmic similarity (SequenceMatcher)
        instead of LLM for code matching at each history point.

        Args:
            model: Model identifier for output file naming

        Returns:
            List of LocalizationResult for each hunk
        """
        output_file = self._localization_path / f"{model}_history_sim.csv"
        results = []

        # Get line numbers from patch
        pre_patch_content = run_command(
            f'git show {self._pre_patch_commit}:{self.project.get_responding_file_name(self._pre_patch_commit)}',
            path=self.project.npm_project_path
        ).stdout
        
        hunk_lines_list = self._get_target_line_numbers_for_llm(pre_patch_content)

        for index, hunk_lines in enumerate(hunk_lines_list):
            if hunk_lines[-1] == 'unused':
                continue
            
            # Convert to range format
            hunk_lines = (list(range(hunk_lines[0], hunk_lines[1] + 1)), hunk_lines[-1])

            # Track through history using similarity
            changed_commits = self._get_changed_commit_lines_similarity(hunk_lines, model)

            # Map to challenge version
            changed_commits = [(i[0], i[1][0], i[2]) for i in changed_commits]
            challenge_commit = self.project.get_challenge_commit()
            
            if not challenge_commit:
                continue

            nearest_idx = get_nearest_ancestor_commit(
                challenge_commit,
                [i[0] for i in changed_commits],
                self.project.npm_project_path,
            )

            if nearest_idx is None:
                if changed_commits and changed_commits[-1][1][0] == -1:
                    changed_lines = [-1]
                else:
                    continue
            else:
                base_commit, base_lineno, base_file_name = changed_commits[nearest_idx]
                diff_content = run_command(
                    f'git diff {base_commit}:{self.project.get_responding_file_name(base_commit)} '
                    f'{challenge_commit}:{self.project.get_responding_file_name(challenge_commit)}',
                    path=self.project.npm_project_path
                ).stdout
                
                from core.utils.parsing import parse_line_number_mapping
                changed_lines = parse_line_number_mapping(diff_content, base_lineno)
                changed_lines = sorted(list(set(changed_lines)))

            result = LocalizationResult(
                commit_id=challenge_commit,
                line_numbers=changed_lines,
                hunk_index=index,
            )
            results.append(result)

            # Save to file
            with open(output_file, 'a') as f:
                print(f'{challenge_commit}##{changed_lines}##{index}', file=f)

        return results

    def _get_changed_commit_lines_similarity(
        self,
        hunk_lines: Tuple[List[int], str],
        model: str,
    ) -> List[Tuple[str, Tuple[List[int], str], str]]:
        """
        Track line changes through git history using similarity matching.
        """
        from core.utils.parsing import parse_line_number_mapping
        
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

        while True:
            if before_lines[0][0] == -1:
                history.append((before_commit, before_lines, before_file_path))
                break

            current_commit = self._get_blame_commit(
                before_commit,
                before_file_path,
                before_lines[0]
            )

            if current_commit is None or current_commit == before_commit:
                break

            current_file_path = self.project.get_responding_file_name(current_commit)
            diff_content = run_command(
                f'git diff {before_commit}:{before_file_path} {current_commit}:{current_file_path}',
                path=self.project.npm_project_path
            ).stdout
            
            after_lines = parse_line_number_mapping(diff_content, before_lines[0])
            after_lines = (after_lines, before_lines[-1])
            
            parent_commit = get_parent_commit(
                current_commit,
                self.project.npm_project_path
            )
            parent_file_path = self.project.get_responding_file_name(parent_commit)
            
            history.append((current_commit, after_lines, current_file_path))

            git_info = run_command(
                f'git show {current_commit} --name-status',
                path=self.project.npm_project_path
            ).stdout
            
            if f'A\t{current_file_path}' in git_info:
                break

            if not is_commit_earlier(
                self.project.get_challenge_commit(),
                current_commit,
                self.project.npm_project_path
            ):
                break

            if not parent_commit:
                break

            before_lines = self._get_line_map_similarity(
                current_commit,
                after_lines,
                parent_commit,
            )

            if before_lines is None or len(before_lines[0]) == 0:
                break

            before_commit = parent_commit
            before_file_path = parent_file_path

        return history

    def _get_line_map_similarity(
        self,
        current_commit: str,
        current_hunk_lines: Tuple[List[int], str],
        before_commit: str,
    ) -> Optional[Tuple[List[int], str]]:
        """
        Map lines between commits using similarity matching.
        """
        temp_type = current_hunk_lines[-1]
        current_file_path = self.project.get_responding_file_name(current_commit)
        before_file_path = self.project.get_responding_file_name(before_commit)

        if before_file_path is None:
            return None

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

        function_range = self._get_function_range(
            current_file_content,
            before_file_content,
            current_hunk_lines[0]
        )

        target_lines = self._line_filter(current_hunk_lines[0], commit_content)
        current_line_content = self.get_line_content(
            current_commit,
            current_file_path,
            target_lines
        )

        removed_lines = self._get_removed_lines(commit_content, function_range)
        
        if len(removed_lines) == 0:
            function_range = [-1, -1]
            removed_lines = self._get_removed_lines(commit_content, function_range)

        before_lines = []

        if removed_lines:
            before_lines = self._similarity_map_lines(
                removed_lines,
                current_line_content
            )

        if len(before_lines) == 0:
            renamed_lines = self._find_rename_line(current_commit, current_line_content)
            if renamed_lines:
                before_lines = renamed_lines
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
            before_lines = self._exactly_map(
                before_file_content,
                before_lines,
                function_range
            )
            before_lines.sort()

        rest_lines = [i for i in current_hunk_lines[0] if i not in target_lines]
        from core.utils.parsing import parse_line_number_mapping
        rest_lines = parse_line_number_mapping(rev_commit_content, rest_lines)
        before_lines.extend(rest_lines)

        return (before_lines, temp_type)

    def _similarity_map_lines(
        self,
        removed_lines: List[str],
        current_hunk_lines: List[str],
    ) -> List[str]:
        """
        Map lines using string similarity (SequenceMatcher).
        """
        matched_lines = []
        
        for target_line in current_hunk_lines:
            if len(target_line.strip()) < 3:
                continue
            
            max_similarity = 0
            most_similar_line = ''
            
            for removed_line in removed_lines:
                normalized_target = target_line.strip()
                normalized_removed = removed_line.strip()
                
                similarity = SequenceMatcher(
                    None,
                    normalized_removed,
                    normalized_target
                ).ratio()
                
                if similarity > max_similarity:
                    max_similarity = similarity
                    most_similar_line = removed_line
            
            if most_similar_line:
                matched_lines.append(most_similar_line)
        
        return matched_lines

    # =========================================================================
    # Direct Similarity Matching (No History)
    # =========================================================================

    def localize_direct_similarity(self, model: str) -> List[LocalizationResult]:
        """
        Localize using direct similarity matching without Git history.
        
        Extracts deleted code from patch and finds similar lines in target
        version directly, without tracking through Git history.

        Args:
            model: Model identifier for output file naming

        Returns:
            List of LocalizationResult for each hunk
        """
        output_file = self._localization_path / "similarity.csv"
        results = []

        # Get deleted lines from patch
        source_lines = self._get_continuous_hunk_content()

        challenge_commit = self.project.get_challenge_commit()
        if not challenge_commit:
            return []

        target_file_content = self.project.get_target_file_content(challenge_commit)
        if not target_file_content:
            return []

        # For each hunk, find similar lines in target
        for index, deleted_lines in enumerate(source_lines):
            if not deleted_lines:
                target_lines = [1, len(target_file_content.splitlines())]
            else:
                target_lines = self._find_similar_lines(
                    deleted_lines,
                    target_file_content
                )

            result = LocalizationResult(
                commit_id=challenge_commit,
                line_numbers=target_lines,
                hunk_index=index,
            )
            results.append(result)

            with open(output_file, 'a') as f:
                print(f'{challenge_commit}##{target_lines}##{index}', file=f)

        return results

    def _find_similar_lines(
        self,
        deleted_lines: List[str],
        target_content: str
    ) -> List[int]:
        """
        Find lines in target content similar to deleted lines.
        """
        target_lines = target_content.splitlines()
        matching_lines = []

        for target_idx, target_line in enumerate(target_lines, start=1):
            for deleted_line in deleted_lines:
                normalized_target = target_line.strip()
                normalized_deleted = deleted_line.strip()

                similarity = SequenceMatcher(
                    None,
                    normalized_deleted,
                    normalized_target
                ).ratio()

                if similarity > 0.95:
                    matching_lines.append(target_idx)
                    break

        return sorted(list(set(matching_lines))) if matching_lines else [1]

    # =========================================================================
    # Direct LLM Matching (No History)
    # =========================================================================

    def localize_direct_llm(self, model: str) -> List[LocalizationResult]:
        """
        Localize using direct LLM matching without Git history.
        
        Extracts deleted code from patch and uses LLM to find semantically
        similar code in target version directly.

        Args:
            model: Model identifier for LLM inference

        Returns:
            List of LocalizationResult for each hunk
        """
        output_file = self._localization_path / f"{model}_direct_llm.csv"
        results = []

        source_lines = self._get_continuous_hunk_content()

        challenge_commit = self.project.get_challenge_commit()
        if not challenge_commit:
            return []

        target_file_content = self.project.get_target_file_content(challenge_commit)
        if not target_file_content:
            return []

        target_file_lines = target_file_content.splitlines()

        for index, deleted_lines in enumerate(source_lines):
            if not deleted_lines:
                target_lines = list(range(1, len(target_file_lines) + 1))
            else:
                target_lines = self._llm_find_similar_context(
                    deleted_lines,
                    target_file_lines,
                    model
                )

            result = LocalizationResult(
                commit_id=challenge_commit,
                line_numbers=target_lines,
                hunk_index=index,
            )
            results.append(result)

            with open(output_file, 'a') as f:
                print(f'{challenge_commit}##{target_lines}##{index}', file=f)

        return results

    def _llm_find_similar_context(
        self,
        deleted_lines: List[str],
        target_lines: List[str],
        model: str,
    ) -> List[int]:
        """
        Use LLM to find semantically similar context in target.
        """
        from core.managers.llm import LLMHandler
        import ast
        
        deleted_code = '\n'.join(deleted_lines)
        target_code = '\n'.join(target_lines)
        
        prompt = f'''As a JavaScript code semantic analysis expert, identify the lines in the target file that are most semantically similar to the given vulnerable code snippet.

Given vulnerable code from patch:
```javascript
{deleted_code}
```

Target file content:
```javascript
{target_code}
```

Please identify which lines (line numbers) in the target file correspond to or are most similar to the vulnerable code. Output as a Python list of line numbers, e.g., [1, 2, 3, 10, 11].

Line numbers:'''

        llm_handler = LLMHandler(self.project)
        llm_output = llm_handler.infer(prompt, model)  # Fix parameter order: content first, model second

        try:
            list_match = re.search(r'\[[\d\s,]+\]', llm_output)
            if list_match:
                line_numbers = ast.literal_eval(list_match.group())
                return sorted(list(set(line_numbers)))
            
            numbers = re.findall(r'\b\d+\b', llm_output)
            if numbers:
                return sorted(list(set(int(n) for n in numbers if 1 <= int(n) <= len(target_lines))))
            
        except Exception as e:
            self._logger.warning(f"Failed to parse LLM output for line numbers: {e}")
        
        return [1]

    # =========================================================================
    # Function-based Localization
    # =========================================================================

    def localize_by_function(self, model: str) -> List[LocalizationResult]:
        """
        Localize by finding functions containing vulnerable code.

        Uses tree-sitter for AST analysis to identify function boundaries.

        Args:
            model: Model identifier

        Returns:
            List of LocalizationResult
        """
        results = []

        challenge_commit = self.project.get_challenge_commit()
        if not challenge_commit:
            return []

        file_content = self.project.get_target_file_content(challenge_commit)
        if not file_content:
            return []

        parser = Parser()
        language = Language(tree_sitter_javascript.language())
        parser.set_language(language)

        tree = parser.parse(bytes(file_content, "utf8"))

        # Use parent class's localize_with_history_llm for line results
        line_results = super().localize_with_history_llm(model)

        for result in line_results:
            if result.line_numbers and result.line_numbers[0] != -1:
                functions = self._find_containing_functions(
                    tree.root_node,
                    result.line_numbers,
                )

                if functions:
                    result.file_path = str(functions[0])
                    results.append(result)

        return results

    def _find_containing_functions(
        self,
        node: Any,
        line_numbers: List[int],
    ) -> List[str]:
        """
        Find functions containing given line numbers.
        """
        functions = []

        function_types = {
            "function_declaration",
            "function_expression",
            "arrow_function",
            "method_definition",
        }

        def traverse(n):
            if n.type in function_types:
                start_line = n.start_point[0] + 1
                end_line = n.end_point[0] + 1

                if any(start_line <= line <= end_line for line in line_numbers):
                    name = self._get_function_name(n)
                    functions.append(name or f"anonymous@{start_line}")

            for child in n.children:
                traverse(child)

        traverse(node)
        return functions

    def _get_function_name(self, node: Any) -> Optional[str]:
        """Extract function name from tree-sitter node."""
        for child in node.children:
            if child.type == "identifier":
                return child.text.decode("utf8")

        if node.parent and node.parent.type == "variable_declarator":
            for child in node.parent.children:
                if child.type == "identifier":
                    return child.text.decode("utf8")

        return None

    # =========================================================================
    # File-based Localization
    # =========================================================================

    def localize_by_file(self) -> List[LocalizationResult]:
        """
        Simple file-level localization.

        Returns the entire file as the localization target.

        Returns:
            List with single LocalizationResult for the file
        """
        challenge_commit = self.project.get_challenge_commit()
        if not challenge_commit:
            return []

        target_file = self.project.get_responding_file_name(challenge_commit)
        if not target_file:
            return []

        content = self.project.get_target_file_content(challenge_commit)
        if not content:
            return []

        line_count = len(content.splitlines())

        return [
            LocalizationResult(
                commit_id=challenge_commit,
                line_numbers=list(range(1, line_count + 1)),
                hunk_index=0,
                file_path=target_file,
            )
        ]
