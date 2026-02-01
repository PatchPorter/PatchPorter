"""
Patch parsing utilities.

Provides functions for parsing and manipulating unified diff patches.
"""

import logging
import re
from typing import List, Tuple, Optional, Dict, Any
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PatchHunk:
    """Represents a single hunk in a patch."""

    source_start: int
    source_length: int
    target_start: int
    target_length: int
    lines: List[Tuple[str, str]]  # (line_type, content)
    header: str = ""

    @property
    def added_lines(self) -> List[str]:
        """Get lines that were added."""
        return [line for type_, line in self.lines if type_ == "+"]

    @property
    def removed_lines(self) -> List[str]:
        """Get lines that were removed."""
        return [line for type_, line in self.lines if type_ == "-"]

    @property
    def context_lines(self) -> List[str]:
        """Get context lines (unchanged)."""
        return [line for type_, line in self.lines if type_ == " "]

    @property
    def added_count(self) -> int:
        """Count of added lines."""
        return len(self.added_lines)

    @property
    def removed_count(self) -> int:
        """Count of removed lines."""
        return len(self.removed_lines)


@dataclass
class PatchedFile:
    """Represents a single file in a patch."""

    source_path: str
    target_path: str
    hunks: List[PatchHunk]
    is_added: bool = False
    is_deleted: bool = False
    is_renamed: bool = False

    @property
    def filename(self) -> str:
        """Get the target filename."""
        return Path(self.target_path).name

    @property
    def total_added(self) -> int:
        """Total lines added across all hunks."""
        return sum(h.added_count for h in self.hunks)

    @property
    def total_removed(self) -> int:
        """Total lines removed across all hunks."""
        return sum(h.removed_count for h in self.hunks)


def parse_unidiff(patch_content: str) -> List[PatchedFile]:
    """
    Parse unified diff content into structured objects.

    For more complex parsing, consider using the unidiff library.
    This is a simplified parser for basic use cases.

    Args:
        patch_content: Raw patch content

    Returns:
        List of PatchedFile objects
    """
    try:
        import unidiff
        patch_set = unidiff.PatchSet.from_string(patch_content)

        files = []
        for pf in patch_set:
            hunks = []
            for hunk in pf:
                lines = []
                for line in hunk:
                    lines.append((line.line_type, line.value))
                hunks.append(PatchHunk(
                    source_start=hunk.source_start,
                    source_length=hunk.source_length,
                    target_start=hunk.target_start,
                    target_length=hunk.target_length,
                    lines=lines,
                ))

            files.append(PatchedFile(
                source_path=pf.source_file,
                target_path=pf.target_file,
                hunks=hunks,
                is_added=pf.is_added_file,
                is_deleted=pf.is_removed_file,
                is_renamed=pf.is_rename,
            ))

        return files
    except ImportError:
        logger.warning("unidiff not installed, using basic parser")
        return _parse_unidiff_basic(patch_content)


def _parse_unidiff_basic(patch_content: str) -> List[PatchedFile]:
    """Basic fallback parser without unidiff library."""
    files = []
    current_file = None
    current_hunk = None
    hunk_pattern = re.compile(r"^@@ -(\d+),?(\d*) \+(\d+),?(\d*) @@")

    for line in patch_content.splitlines():
        if line.startswith("--- "):
            if current_file:
                if current_hunk:
                    current_file.hunks.append(current_hunk)
                files.append(current_file)
            source_path = line[4:].split("\t")[0]
            current_file = PatchedFile(
                source_path=source_path,
                target_path="",
                hunks=[],
            )
            current_hunk = None

        elif line.startswith("+++ ") and current_file:
            current_file.target_path = line[4:].split("\t")[0]

        elif line.startswith("@@") and current_file:
            if current_hunk:
                current_file.hunks.append(current_hunk)

            match = hunk_pattern.match(line)
            if match:
                current_hunk = PatchHunk(
                    source_start=int(match.group(1)),
                    source_length=int(match.group(2)) if match.group(2) else 1,
                    target_start=int(match.group(3)),
                    target_length=int(match.group(4)) if match.group(4) else 1,
                    lines=[],
                    header=line,
                )

        elif current_hunk and line:
            if line[0] in ("+", "-", " "):
                current_hunk.lines.append((line[0], line[1:]))

    # Don't forget the last file/hunk
    if current_file:
        if current_hunk:
            current_file.hunks.append(current_hunk)
        files.append(current_file)

    return files


def get_changed_line_numbers(patch: PatchedFile) -> Tuple[List[int], List[int]]:
    """
    Extract line numbers of changed lines from a patch.

    Args:
        patch: PatchedFile object

    Returns:
        Tuple of (removed_line_numbers, added_line_numbers)
    """
    removed = []
    added = []

    for hunk in patch.hunks:
        source_line = hunk.source_start
        target_line = hunk.target_start

        for line_type, _ in hunk.lines:
            if line_type == "-":
                removed.append(source_line)
                source_line += 1
            elif line_type == "+":
                added.append(target_line)
                target_line += 1
            else:  # context
                source_line += 1
                target_line += 1

    return removed, added


def get_source_line_numbers(patch: PatchedFile) -> List[int]:
    """
    Get all source line numbers affected by the patch.

    Args:
        patch: PatchedFile object

    Returns:
        List of line numbers in the source file
    """
    lines = []

    for hunk in patch.hunks:
        current_line = hunk.source_start

        for line_type, _ in hunk.lines:
            if line_type in ("-", " "):
                lines.append(current_line)
                current_line += 1

    return lines


def get_target_line_numbers(patch: PatchedFile) -> List[int]:
    """
    Get all target line numbers affected by the patch.

    Args:
        patch: PatchedFile object

    Returns:
        List of line numbers in the target file
    """
    lines = []

    for hunk in patch.hunks:
        current_line = hunk.target_start

        for line_type, _ in hunk.lines:
            if line_type in ("+", " "):
                lines.append(current_line)
                current_line += 1

    return lines


def parse_line_number_mapping(diff_content: str, base_lines: List[int]) -> List[int]:
    """
    Map line numbers from one version to another using diff content.

    Given a diff and line numbers in the source version, calculate
    the corresponding line numbers in the target version.

    This handles three cases:
    1. Lines before any hunk: apply cumulative offset
    2. Lines within a hunk but not modified: return target line number
    3. Lines within a hunk that are deleted: try to find corresponding added line

    Args:
        diff_content: Unified diff content
        base_lines: Line numbers in the source version

    Returns:
        Corresponding line numbers in the target version
    """
    if not diff_content or not base_lines:
        return list(base_lines) if base_lines else []

    try:
        import unidiff
        from io import StringIO
        patch_set = unidiff.PatchSet(StringIO(diff_content))
    except Exception:
        return list(base_lines)

    if not patch_set:
        return list(base_lines)

    result = []
    
    for current_line in base_lines:
        result_line = current_line
        is_in_hunk = False
        
        for patched_file in patch_set:
            for hunk in patched_file:
                old_start = hunk.source_start
                old_end = old_start + hunk.source_length - 1
                
                # Line is before this hunk
                if current_line < old_start:
                    continue
                
                # Line is after this hunk - apply offset and continue to next hunk
                if current_line > old_end:
                    line_delta = hunk.target_length - hunk.source_length
                    result_line += line_delta
                    continue
                
                # Line is within this hunk
                for line in hunk:
                    if line.source_line_no == current_line:
                        if line.target_line_no is None:
                            # Line was deleted - try to find corresponding added line
                            target_lino = _find_added_line_for_deleted(
                                diff_content, 
                                line.value.strip()
                            )
                            if target_lino is not None:
                                result.append(target_lino)
                            is_in_hunk = True
                        elif not line.is_removed:
                            # Line exists in both versions
                            result.append(line.target_line_no)
                            is_in_hunk = True
                
                if is_in_hunk:
                    break
            
            if is_in_hunk:
                break
        
        if not is_in_hunk:
            result.append(result_line)
    
    return result


def _find_added_line_for_deleted(diff_content: str, line_content: str) -> Optional[int]:
    """
    Find the target line number for a deleted line that may have been moved.
    
    When a line is deleted in one location and added in another (refactoring),
    this finds the new location.
    
    Args:
        diff_content: Full diff content
        line_content: The content of the deleted line (stripped)
        
    Returns:
        Target line number if found, None otherwise
    """
    if not line_content.strip():
        return None
    
    try:
        import unidiff
        from io import StringIO
        patch_set = unidiff.PatchSet(StringIO(diff_content))
        
        for patched_file in patch_set:
            for hunk in patched_file:
                for line in hunk:
                    if line.is_added and line.value.strip() == line_content:
                        return line.target_line_no
    except Exception:
        pass
    
    return None


def split_hunk_into_continuous_changes(hunk: PatchHunk) -> List[List[Tuple[str, str]]]:
    """
    Split a hunk into continuous change blocks.

    A continuous change block is a sequence of added/removed lines
    surrounded by context lines.

    Args:
        hunk: PatchHunk to split

    Returns:
        List of change blocks, each containing lines with context
    """
    blocks = []
    current_block = []
    in_change = False

    for line_type, content in hunk.lines:
        if line_type in ("+", "-"):
            if not in_change:
                # Start of a new change block
                # Include previous context lines
                current_block = current_block[-3:] if current_block else []
                in_change = True
            current_block.append((line_type, content))
        else:
            if in_change:
                # Add some context after the change
                current_block.append((line_type, content))
                if len([l for l in current_block if l[0] == " "]) >= 3:
                    blocks.append(current_block)
                    current_block = [(line_type, content)]
                    in_change = False
            else:
                current_block.append((line_type, content))

    # Don't forget the last block
    if current_block and any(t in ("+", "-") for t, _ in current_block):
        blocks.append(current_block)

    return blocks


def extract_security_relevant_hunks(
    patches: List[PatchedFile],
    exclude_patterns: Optional[List[str]] = None,
) -> List[PatchedFile]:
    """
    Filter patches to include only security-relevant files and hunks.

    Args:
        patches: List of PatchedFile objects
        exclude_patterns: Patterns to exclude (e.g., test files)

    Returns:
        Filtered list of patches
    """
    if exclude_patterns is None:
        exclude_patterns = ["min.js", "test", ".json", "dist", ".spec"]

    result = []

    for patch in patches:
        # Check if file should be excluded
        path_lower = patch.target_path.lower()
        if any(pattern in path_lower for pattern in exclude_patterns):
            continue

        # Only include JS/TS files
        ext = Path(patch.target_path).suffix.lower()
        if ext not in {".js", ".ts", ".mjs", ".cjs"}:
            continue

        # Skip added files (no code to backport)
        if patch.is_added:
            continue

        result.append(patch)

    return result


def format_hunk_as_diff(hunk: PatchHunk) -> str:
    """
    Format a hunk back to unified diff format.

    Args:
        hunk: PatchHunk to format

    Returns:
        Formatted diff string
    """
    header = f"@@ -{hunk.source_start},{hunk.source_length} +{hunk.target_start},{hunk.target_length} @@"
    lines = [header]

    for line_type, content in hunk.lines:
        lines.append(f"{line_type}{content}")

    return "\n".join(lines)


def format_patch(patch: PatchedFile) -> str:
    """
    Format a patched file back to unified diff format.

    Args:
        patch: PatchedFile to format

    Returns:
        Formatted diff string
    """
    lines = [
        f"--- {patch.source_path}",
        f"+++ {patch.target_path}",
    ]

    for hunk in patch.hunks:
        lines.append(format_hunk_as_diff(hunk))

    return "\n".join(lines)


# =========================================================================
# Localization Info Parsing
# =========================================================================

def parse_localization_info(file_path: str) -> Dict[str, Dict[str, List[int]]]:
    """
    Parse localization information from CSV file.
    
    File format: commit_id##[line_numbers]##hunk_index
    
    Args:
        file_path: Path to localization CSV file
        
    Returns:
        Dictionary mapping commit_id to {hunk_index: line_numbers}
    """
    commit_lines: Dict[str, Dict[str, List[int]]] = {}
    
    try:
        with open(file_path, 'r') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        logger.warning(f"Could not read localization file {file_path}: {e}")
        return commit_lines
    
    for line in lines:
        parts = line.split('##')
        if len(parts) != 3:
            continue
        
        commit_id = parts[0]
        try:
            # Parse line numbers from string like "[1, 2, 3]"
            linos = eval(parts[1])
            if not isinstance(linos, list):
                linos = [linos]
        except Exception:
            linos = []
        
        index = parts[2]
        
        if commit_id not in commit_lines:
            commit_lines[commit_id] = {}
        commit_lines[commit_id][index] = linos
    
    return commit_lines


def parse_lineno_difference(diff_content: str, base_lines: List[int]) -> List[int]:
    """
    Map line numbers through a diff to get corresponding target lines.
    
    Args:
        diff_content: Unified diff content
        base_lines: Line numbers in source version
        
    Returns:
        Corresponding line numbers in target version
    """
    if not diff_content or not base_lines:
        return base_lines
    
    try:
        patches = parse_unidiff(diff_content)
        if not patches:
            return base_lines
        
        return parse_line_number_mapping(diff_content, base_lines)
    except Exception as e:
        logger.warning(f"Error mapping line numbers: {e}")
        return base_lines


def get_removed_lines_from_patch(patch_content: str) -> List[str]:
    """
    Extract all removed lines from a patch.
    
    Args:
        patch_content: Raw patch content
        
    Returns:
        List of removed line contents
    """
    removed = []
    
    for line in patch_content.split('\n'):
        if line.startswith('-') and not line.startswith('---'):
            removed.append(line[1:])
    
    return removed


def get_added_lines_from_patch(patch_content: str) -> List[str]:
    """
    Extract all added lines from a patch.
    
    Args:
        patch_content: Raw patch content
        
    Returns:
        List of added line contents
    """
    added = []
    
    for line in patch_content.split('\n'):
        if line.startswith('+') and not line.startswith('+++'):
            added.append(line[1:])
    
    return added


def extract_hunks_from_patch(patch_path: str) -> List[List[str]]:
    """
    Extract hunks with metadata from a patch file.
    
    Args:
        patch_path: Path to patch file
        
    Returns:
        List of hunks (each hunk is a list of lines)
    """
    hunks = []
    current_hunk = []
    metadata = []
    
    try:
        with open(patch_path, 'r') as f:
            content = f.read()
    except Exception:
        return hunks
    
    for line in content.split('\n'):
        line_with_newline = line + '\n'
        
        if any(line.startswith(prefix) for prefix in [
            'diff', 'index', '---', '+++', 'deleted file', 'new file'
        ]):
            if current_hunk:
                hunks.append(metadata + current_hunk)
                current_hunk = []
                metadata = []
            metadata.append(line_with_newline)
        elif line.startswith('@@'):
            if current_hunk:
                hunks.append(metadata + current_hunk)
                current_hunk = []
            current_hunk.append(line_with_newline)
        else:
            current_hunk.append(line_with_newline)
    
    if current_hunk:
        hunks.append(metadata + current_hunk)
    
    return hunks


def filter_js_hunks(patch_content: str) -> str:
    """
    Filter patch to include only JavaScript file changes.
    
    Args:
        patch_content: Raw patch content
        
    Returns:
        Filtered patch content
    """
    result_lines = []
    current_file = ""
    include_current = False
    
    for line in patch_content.split('\n'):
        if line.startswith('diff '):
            # Extract file path
            parts = line.split()
            if len(parts) >= 3:
                current_file = parts[-1].lower()
                include_current = (
                    current_file.endswith('.js') or
                    current_file.endswith('.ts') or
                    current_file.endswith('.mjs')
                ) and 'test' not in current_file
        
        if include_current:
            result_lines.append(line)
    
    return '\n'.join(result_lines)


# Alias for backward compatibility
parse_patch = parse_unidiff
