"""
File and path operation utilities.

Provides clean abstractions for common file operations with proper
error handling and logging.
"""

import logging
from pathlib import Path
from typing import List, Optional, Set, Union
import json
import shutil

logger = logging.getLogger(__name__)


def read_file(file_path: Union[str, Path]) -> str:
    """
    Read the entire content of a file.

    Args:
        file_path: Path to the file

    Returns:
        File content as string

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    path = Path(file_path)
    logger.debug(f"Reading file: {path}")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def read_lines(
    file_path: Union[str, Path],
    strip: bool = True,
    skip_empty: bool = False,
) -> List[str]:
    """
    Read a file and return lines as a list.

    Args:
        file_path: Path to the file
        strip: Whether to strip whitespace from each line
        skip_empty: Whether to skip empty lines

    Returns:
        List of lines
    """
    path = Path(file_path)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if strip:
        lines = [line.strip() for line in lines]

    if skip_empty:
        lines = [line for line in lines if line]

    return lines


def write_file(
    file_path: Union[str, Path],
    content: str,
    create_parents: bool = True,
) -> None:
    """
    Write content to a file.

    Args:
        file_path: Path to the file
        content: Content to write
        create_parents: Whether to create parent directories
    """
    path = Path(file_path)

    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)

    logger.debug(f"Writing file: {path}")

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def append_file(
    file_path: Union[str, Path],
    content: str,
    create_parents: bool = True,
) -> None:
    """
    Append content to a file.

    Args:
        file_path: Path to the file
        content: Content to append
        create_parents: Whether to create parent directories
    """
    path = Path(file_path)

    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "a", encoding="utf-8") as f:
        f.write(content)


def read_json(file_path: Union[str, Path]) -> dict:
    """
    Read and parse a JSON file.

    Args:
        file_path: Path to the JSON file

    Returns:
        Parsed JSON as dictionary
    """
    path = Path(file_path)

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(
    file_path: Union[str, Path],
    data: dict,
    indent: int = 4,
    create_parents: bool = True,
) -> None:
    """
    Write data to a JSON file.

    Args:
        file_path: Path to the JSON file
        data: Data to write
        indent: JSON indentation level
        create_parents: Whether to create parent directories
    """
    path = Path(file_path)

    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)


def ensure_directory(dir_path: Union[str, Path]) -> Path:
    """
    Ensure a directory exists, creating it if necessary.

    Args:
        dir_path: Path to the directory

    Returns:
        Path object to the directory
    """
    path = Path(dir_path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def count_lines(file_path: Union[str, Path]) -> int:
    """
    Count the number of lines in a file.

    Args:
        file_path: Path to the file

    Returns:
        Number of lines
    """
    path = Path(file_path)

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f)


def remove_duplicate_lines(file_path: Union[str, Path]) -> int:
    """
    Remove duplicate lines from a file (preserves order).

    Args:
        file_path: Path to the file

    Returns:
        Number of duplicates removed
    """
    path = Path(file_path)

    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    seen: Set[str] = set()
    unique_lines = []

    for line in lines:
        if line not in seen:
            seen.add(line)
            unique_lines.append(line)

    removed_count = len(lines) - len(unique_lines)

    with open(path, "w", encoding="utf-8") as f:
        f.writelines(unique_lines)

    logger.debug(f"Removed {removed_count} duplicate lines from {path}")
    return removed_count


def find_line_numbers(
    content: str,
    search_text: str,
) -> List[int]:
    """
    Find line numbers containing a specific text.

    Args:
        content: File content as string
        search_text: Text to search for

    Returns:
        List of line numbers (1-indexed)
    """
    line_numbers = []
    lines = content.splitlines()

    for i, line in enumerate(lines, 1):
        if search_text in line:
            line_numbers.append(i)

    return line_numbers


def get_lines_in_range(
    file_path: Union[str, Path],
    start_line: int,
    end_line: int,
) -> List[str]:
    """
    Get lines from a file within a specific range.

    Args:
        file_path: Path to the file
        start_line: Starting line number (1-indexed)
        end_line: Ending line number (1-indexed, inclusive)

    Returns:
        List of lines in the range
    """
    lines = read_lines(file_path, strip=False)
    return lines[start_line - 1 : end_line]


def copy_file(
    src: Union[str, Path],
    dst: Union[str, Path],
    create_parents: bool = True,
) -> Path:
    """
    Copy a file to a new location.

    Args:
        src: Source file path
        dst: Destination file path
        create_parents: Whether to create parent directories

    Returns:
        Path to the copied file
    """
    src_path = Path(src)
    dst_path = Path(dst)

    if create_parents:
        dst_path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy2(src_path, dst_path)
    return dst_path


def safe_delete(path: Union[str, Path]) -> bool:
    """
    Safely delete a file or directory.

    Args:
        path: Path to delete

    Returns:
        True if deletion was successful
    """
    path = Path(path)

    try:
        if path.is_file():
            path.unlink()
        elif path.is_dir():
            shutil.rmtree(path)
        return True
    except Exception as e:
        logger.warning(f"Failed to delete {path}: {e}")
        return False


def file_exists(file_path: Union[str, Path]) -> bool:
    """Check if a file exists."""
    return Path(file_path).is_file()


def dir_exists(dir_path: Union[str, Path]) -> bool:
    """Check if a directory exists."""
    return Path(dir_path).is_dir()


def get_file_extension(file_path: Union[str, Path]) -> str:
    """Get the file extension (without dot)."""
    return Path(file_path).suffix.lstrip(".")


def is_javascript_file(file_path: Union[str, Path]) -> bool:
    """Check if a file is a JavaScript/TypeScript file."""
    ext = get_file_extension(file_path).lower()
    return ext in {"js", "ts", "mjs", "cjs", "jsx", "tsx"}


def should_exclude_file(
    file_path: Union[str, Path],
    exclude_patterns: Optional[List[str]] = None,
) -> bool:
    """
    Check if a file should be excluded based on patterns.

    Args:
        file_path: Path to check
        exclude_patterns: List of patterns to exclude

    Returns:
        True if file should be excluded
    """
    if exclude_patterns is None:
        exclude_patterns = ["min.js", "test", ".json", "dist", ".history"]

    path_str = str(file_path).lower()
    return any(pattern in path_str for pattern in exclude_patterns)
