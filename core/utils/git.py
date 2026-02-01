"""
Git operation utilities.

Provides clean abstractions for common Git operations with proper
error handling and logging.
"""

import re
import logging
from typing import Optional, List, Tuple
from pathlib import Path

from core.utils.command import run_command, CommandResult
from core.exceptions import GitOperationError
from core.config import config

logger = logging.getLogger(__name__)


def checkout_commit(
    commit: str,
    repo_path: Path | str,
    force: bool = True,
    clean: bool = True,
) -> CommandResult:
    """
    Checkout a specific commit in a git repository.

    Args:
        commit: Commit hash or reference to checkout
        repo_path: Path to the git repository
        force: Whether to force checkout (discard local changes)
        clean: Whether to clean untracked files after checkout

    Returns:
        CommandResult from the checkout operation

    Raises:
        GitOperationError: If checkout fails after fetch attempt
    """
    repo_path = Path(repo_path)

    # Build checkout command
    force_flag = "-f" if force else ""
    cmd = f"git checkout {force_flag} {commit}"

    if clean:
        cmd += " && git clean -df"

    result = run_command(cmd, path=repo_path)

    # If checkout failed, try fetching the commit first
    if result.has_error and config.git.fetch_on_missing_commit:
        logger.info(f"Commit not found locally, fetching: {commit}")
        fetch_result = run_command(
            f"git fetch {config.git.default_remote} {commit}",
            path=repo_path,
        )

        if fetch_result.success:
            result = run_command(cmd, path=repo_path)

    if result.has_error:
        logger.error(f"Checkout failed for {commit}: {result.stderr}")

    return result


def get_parent_commit(
    commit: str,
    repo_path: Path | str,
) -> Optional[str]:
    """
    Get the parent commit of a given commit.

    Args:
        commit: The commit hash
        repo_path: Path to the git repository

    Returns:
        Parent commit hash or None if not found
    """
    result = run_command(
        f"git log -1 --pretty=%P {commit}",
        path=repo_path,
    )

    if result.success and result.stdout.strip():
        # Return first parent (in case of merge commits)
        return result.stdout.strip().split()[0]

    return None


def is_commit_earlier(
    commit1: str,
    commit2: str,
    repo_path: Path | str,
) -> bool:
    """
    Check if commit1 is an ancestor of commit2.

    Args:
        commit1: First commit hash
        commit2: Second commit hash
        repo_path: Path to the git repository

    Returns:
        True if commit1 is an ancestor of commit2
    """
    # Handle same commit
    if commit1 == commit2 or commit1 in commit2 or commit2 in commit1:
        return True

    # Use git rev-list to check ancestry
    result = run_command(
        f"git rev-list {commit1}..{commit2}",
        path=repo_path,
    )

    return bool(result.stdout.strip())


def sort_commits_topologically(
    head_commit: str,
    commits: List[str],
    repo_path: Path | str,
) -> List[str]:
    """
    Sort commits in topological order (most recent first).

    Args:
        head_commit: The head commit to start from
        commits: List of commits to sort
        repo_path: Path to the git repository

    Returns:
        Sorted list of commits
    """
    result = run_command(
        f"git rev-list {head_commit}",
        path=repo_path,
    )

    if not result.success:
        return commits

    topo_order = result.stdout.strip().split("\n")
    commit_order = {c: i for i, c in enumerate(topo_order)}

    return sorted(
        commits,
        key=lambda c: commit_order.get(c, float("inf")),
    )


def get_nearest_ancestor_commit(
    target_commit: str,
    candidate_commits: List[str],
    repo_path: Path | str,
) -> Optional[int]:
    """
    Find the nearest ancestor from a list of candidate commits.

    Args:
        target_commit: The commit to find ancestors for
        candidate_commits: List of potential ancestor commits
        repo_path: Path to the git repository

    Returns:
        Index of the nearest ancestor in candidate_commits, or None
    """
    for i, candidate in enumerate(candidate_commits):
        if is_commit_earlier(candidate, target_commit, repo_path):
            return i
    return None


def run_git_blame(
    commit: str,
    file_path: str,
    line_number: int,
    repo_path: Path | str,
) -> str:
    """
    Run git blame for a specific line in a file at a given commit.

    Args:
        commit: The commit to blame at
        file_path: Path to the file (relative to repo)
        line_number: Line number to blame
        repo_path: Path to the git repository

    Returns:
        Git blame output for the specified line
    """
    result = run_command(
        f"git blame -L {line_number},{line_number} {commit} -- {file_path}",
        path=repo_path,
    )
    return result.stdout


def parse_git_blame_output(blame_output: str) -> List[str]:
    """
    Parse git blame output to extract commit hashes.

    Args:
        blame_output: Raw output from git blame

    Returns:
        List of commit hashes found in the blame output
    
    Note:
        Git blame output format:
        <commit-hash> (<author> <date> <time> <timezone> <line-number>) <code>
        The commit hash can be short (8 chars) or full (40 chars).
    """
    commits = []
    # Match both short (7+) and full (40) commit hashes at line start
    # Git blame outputs 7-character short hashes by default
    commit_pattern = re.compile(r"(\^?)([a-f0-9]{7,40})")

    for line in blame_output.splitlines():
        if not line.strip():
            continue
        match = commit_pattern.match(line)
        if match:
            # Group 1 is the optional '^' for boundary commits (initial commit)
            # Group 2 is the commit hash (remove ^ prefix if present)
            commits.append(match.group(2))
        else:
            # Fallback: split and take first field
            # This handles edge cases like non-standard formats
            parts = line.split()
            if parts and re.match(r"^[a-f0-9]{7,40}$", parts[0].lstrip("^")):
                commits.append(parts[0].lstrip("^"))

    return commits


def get_file_at_commit(
    commit: str,
    file_path: str,
    repo_path: Path | str,
) -> Optional[str]:
    """
    Get the content of a file at a specific commit.

    Args:
        commit: The commit hash
        file_path: Path to the file (relative to repo)
        repo_path: Path to the git repository

    Returns:
        File content or None if not found
    """
    result = run_command(
        f"git show {commit}:{file_path}",
        path=repo_path,
    )

    if result.success:
        return result.stdout

    return None


def list_files_at_commit(
    commit: str,
    repo_path: Path | str,
    pattern: Optional[str] = None,
) -> List[str]:
    """
    List all files in the repository at a specific commit.

    Args:
        commit: The commit hash
        repo_path: Path to the git repository
        pattern: Optional glob pattern to filter files

    Returns:
        List of file paths
    """
    result = run_command(
        f"git ls-tree -r --name-only {commit}",
        path=repo_path,
    )

    if not result.success:
        return []

    files = result.stdout.strip().splitlines()

    if pattern:
        import fnmatch
        files = [f for f in files if fnmatch.fnmatch(f, pattern)]

    return files


def get_diff_between_commits(
    commit1: str,
    commit2: str,
    file1: str,
    file2: str,
    repo_path: Path | str,
) -> str:
    """
    Get the diff between two files at different commits.

    Args:
        commit1: First commit
        commit2: Second commit
        file1: File path at commit1
        file2: File path at commit2
        repo_path: Path to the git repository

    Returns:
        Diff output
    """
    result = run_command(
        f"git diff {commit1}:{file1} {commit2}:{file2}",
        path=repo_path,
    )
    return result.stdout


def get_commit_history(
    file_path: str,
    repo_path: Path | str,
    start_commit: Optional[str] = None,
    follow_renames: bool = True,
) -> List[Tuple[str, str]]:
    """
    Get the commit history for a file.

    Args:
        file_path: Path to the file
        repo_path: Path to the git repository
        start_commit: Starting commit (optional)
        follow_renames: Whether to follow file renames

    Returns:
        List of (commit_hash, file_path) tuples
    """
    follow_flag = "--follow" if follow_renames else ""
    start = start_commit or "HEAD"

    result = run_command(
        f"git log {start} {follow_flag} --name-status --pretty=format:%H -- {file_path}",
        path=repo_path,
    )

    if not result.success:
        return []

    history = []
    current_commit = None
    rename_pattern = re.compile(r"^[RC]\d*\t(.+)\t(.+)$")
    add_pattern = re.compile(r"^A\t(.+)$")

    for line in result.stdout.splitlines():
        if re.match(r"^[0-9a-f]{40}$", line):
            current_commit = line
        elif current_commit:
            rename_match = rename_pattern.match(line)
            add_match = add_pattern.match(line)

            if rename_match:
                history.append((current_commit, rename_match.group(2)))
                current_commit = None
            elif add_match:
                history.append((current_commit, add_match.group(1)))
                current_commit = None

    return history
