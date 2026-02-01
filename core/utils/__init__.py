"""
Utility modules for SCA-Repair.

This package contains various utility functions organized by domain:
    - command: Shell command execution
    - git: Git operations
    - file: File and path operations
    - similarity: Code similarity calculations
    - parsing: Patch and diff parsing utilities
"""

from core.utils.command import run_command, CommandResult
from core.utils.git import (
    checkout_commit,
    get_parent_commit,
    is_commit_earlier,
    sort_commits_topologically,
    run_git_blame,
    parse_git_blame_output,
    get_file_at_commit,
    list_files_at_commit,
    get_diff_between_commits,
    get_commit_history,
    get_nearest_ancestor_commit,
)
from core.utils.file import (
    read_file,
    read_lines,
    write_file,
    ensure_directory,
    count_lines,
    remove_duplicate_lines,
    find_line_numbers,
    get_lines_in_range,
    copy_file,
    safe_delete,
    file_exists,
    dir_exists,
    is_javascript_file,
    should_exclude_file,
)
from core.utils.similarity import (
    calculate_bleu,
    calculate_codebleu,
    calculate_levenshtein_ratio,
    find_most_similar,
    rank_by_similarity,
)
from core.utils.parsing import (
    parse_unidiff,
    get_changed_line_numbers,
    get_source_line_numbers,
    get_target_line_numbers,
    parse_line_number_mapping,
    format_hunk_as_diff,
    format_patch,
    filter_js_hunks,
    parse_localization_info,
    get_removed_lines_from_patch,
    get_added_lines_from_patch,
)

__all__ = [
    # Command utilities
    "run_command",
    "CommandResult",
    # Git utilities
    "checkout_commit",
    "get_parent_commit",
    "is_commit_earlier",
    "sort_commits_topologically",
    "run_git_blame",
    "parse_git_blame_output",
    "get_file_at_commit",
    "list_files_at_commit",
    "get_diff_between_commits",
    "get_commit_history",
    "get_nearest_ancestor_commit",
    # File utilities
    "read_file",
    "read_lines",
    "write_file",
    "ensure_directory",
    "count_lines",
    "remove_duplicate_lines",
    "find_line_numbers",
    "get_lines_in_range",
    "copy_file",
    "safe_delete",
    "file_exists",
    "dir_exists",
    "is_javascript_file",
    "should_exclude_file",
    # Similarity utilities
    "calculate_bleu",
    "calculate_codebleu",
    "calculate_levenshtein_ratio",
    "find_most_similar",
    "rank_by_similarity",
    # Parsing utilities
    "parse_unidiff",
    "get_changed_line_numbers",
    "get_source_line_numbers",
    "get_target_line_numbers",
    "parse_line_number_mapping",
    "format_hunk_as_diff",
    "format_patch",
    "filter_js_hunks",
    "parse_localization_info",
    "get_removed_lines_from_patch",
    "get_added_lines_from_patch",
]
