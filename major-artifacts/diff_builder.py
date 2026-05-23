import difflib

from .models import HunkEdit


def apply_hunk_edits(original_content: str, edits: list[HunkEdit]) -> str:
    lines = original_content.splitlines(keepends=True)
    for edit in sorted(edits, key=lambda item: item.start_line, reverse=True):
        replacement = edit.replacement
        if replacement and not replacement.endswith("\n"):
            replacement += "\n"
        replacement_lines = replacement.splitlines(keepends=True)
        if edit.start_line == -1:
            lines.extend(replacement_lines)
            continue
        start = max(0, edit.start_line - 1)
        end = max(start, edit.end_line)
        lines[start:end] = replacement_lines
    return "".join(lines)


def build_unified_diff(file_path: str, before: str, after: str) -> str:
    if before == after:
        return ""
    diff_lines = list(
        difflib.unified_diff(
            before.splitlines(),
            after.splitlines(),
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        )
    )
    return "\n".join(diff_lines) + "\n"
