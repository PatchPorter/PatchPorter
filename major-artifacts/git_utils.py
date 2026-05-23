import subprocess
from pathlib import Path
from typing import Optional
from difflib import SequenceMatcher


class GitError(RuntimeError):
    pass


def run_git(repo_path: Path, args: list[str], check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(repo_path), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and result.returncode != 0:
        raise GitError(result.stderr.strip() or result.stdout.strip() or "git command failed")
    return result.stdout


def commit_exists(repo_path: Path, commit: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "cat-file", "-e", f"{commit}^{{commit}}"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def rev_parse(repo_path: Path, ref: str) -> str:
    return run_git(repo_path, ["rev-parse", ref]).strip()


def get_parent_commit(repo_path: Path, commit: str) -> Optional[str]:
    parents = run_git(repo_path, ["log", "-1", "--pretty=%P", commit]).strip()
    return parents.split()[0] if parents else None


def get_merge_base(repo_path: Path, left: str, right: str) -> Optional[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "merge-base", left, right],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def is_ancestor(repo_path: Path, ancestor: str, descendant: str) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "merge-base", "--is-ancestor", ancestor, descendant],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def get_file_at_commit(repo_path: Path, commit: str, file_path: str) -> Optional[str]:
    result = subprocess.run(
        ["git", "-C", str(repo_path), "show", f"{commit}:{file_path}"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return None
    return result.stdout


def list_files_at_commit(repo_path: Path, commit: str) -> list[str]:
    output = run_git(repo_path, ["ls-tree", "-r", "--name-only", commit])
    return [line for line in output.splitlines() if line]


def get_diff_between_files(
    repo_path: Path,
    left_commit: str,
    left_path: str,
    right_commit: str,
    right_path: str,
) -> str:
    return run_git(
        repo_path,
        ["diff", f"{left_commit}:{left_path}", f"{right_commit}:{right_path}"],
        check=False,
    )


def get_commit_patch(repo_path: Path, commit: str) -> str:
    return run_git(repo_path, ["show", "--format=", "--patch", commit], check=True)


def rev_list_path_between(repo_path: Path, base_commit: str, target_commit: str, file_path: str) -> list[str]:
    output = run_git(
        repo_path,
        ["rev-list", "--reverse", "--ancestry-path", f"{base_commit}..{target_commit}", "--", file_path],
        check=True,
    )
    return [line for line in output.splitlines() if line]


def blame_line(repo_path: Path, commit: str, file_path: str, line_number: int) -> Optional[str]:
    output = run_git(
        repo_path,
        ["blame", "--porcelain", "-L", f"{line_number},{line_number}", commit, "--", file_path],
        check=False,
    )
    first_line = output.splitlines()[0] if output.splitlines() else ""
    token = first_line.split(" ", 1)[0].lstrip("^")
    return token if token else None


def choose_most_recent_commit(repo_path: Path, head: str, commits: list[str]) -> Optional[str]:
    if not commits:
        return None
    rev_list = run_git(repo_path, ["rev-list", head]).splitlines()
    order = {commit: index for index, commit in enumerate(rev_list)}
    return min(commits, key=lambda commit: order.get(commit, 10**12))


def resolve_file_path(
    repo_path: Path,
    commit: str,
    preferred_path: str,
    reference_content: str = "",
) -> Optional[str]:
    if get_file_at_commit(repo_path, commit, preferred_path) is not None:
        return preferred_path

    files = list_files_at_commit(repo_path, commit)
    if not files or not reference_content:
        return None

    preferred_name = Path(preferred_path).name
    same_name = [item for item in files if Path(item).name == preferred_name]
    same_suffix = [item for item in files if item.endswith(Path(preferred_path).suffix)] if Path(preferred_path).suffix else []
    ranked_groups = [same_name, same_suffix, files]

    seen: set[str] = set()
    best_path = None
    best_score = 0.0
    for group in ranked_groups:
        for candidate in group:
            if candidate in seen:
                continue
            seen.add(candidate)
            content = get_file_at_commit(repo_path, commit, candidate)
            if not content:
                continue
            score = SequenceMatcher(None, reference_content[:20000], content[:20000]).ratio()
            if score > best_score:
                best_path = candidate
                best_score = score
        if best_score >= 0.25 and best_path is not None:
            return best_path

    return best_path if best_score >= 0.25 else None
