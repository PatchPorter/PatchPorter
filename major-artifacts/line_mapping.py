from typing import Optional

from .patch_parser import parse_patch_content


def parse_line_number_mapping(diff_content: str, base_lines: list[int]) -> list[int]:
    if not diff_content or not base_lines:
        return list(base_lines) if base_lines else []

    try:
        patch_files = parse_patch_content(_ensure_diff_header(diff_content))
    except Exception:
        return list(base_lines)

    result: list[int] = []
    for current_line in base_lines:
        if current_line == -1:
            result.append(-1)
            continue

        result_line = current_line
        is_in_hunk = False
        for patched_file in patch_files:
            for hunk in patched_file.hunks:
                old_start = hunk.source_start
                old_end = old_start + hunk.source_length - 1
                if current_line < old_start:
                    continue
                if current_line > old_end:
                    result_line += hunk.target_length - hunk.source_length
                    continue

                for line in hunk.lines:
                    if line.source_line_no == current_line:
                        if line.target_line_no is None:
                            target_lino = _find_added_line_for_deleted(diff_content, line.content.strip())
                            if target_lino is not None:
                                result.append(target_lino)
                            is_in_hunk = True
                        elif line.kind != "-":
                            result.append(line.target_line_no)
                            is_in_hunk = True
                    if is_in_hunk:
                        break
                if is_in_hunk:
                    break
            if is_in_hunk:
                break

        if not is_in_hunk:
            result.append(result_line)
    return result


def _ensure_diff_header(diff_content: str) -> str:
    if "diff --git " in diff_content:
        return diff_content
    return "diff --git a/file b/file\n--- a/file\n+++ b/file\n" + diff_content


def _find_added_line_for_deleted(diff_content: str, line_content: str) -> Optional[int]:
    if not line_content.strip():
        return None
    try:
        patch_files = parse_patch_content(_ensure_diff_header(diff_content))
    except Exception:
        return None

    for patched_file in patch_files:
        for hunk in patched_file.hunks:
            for line in hunk.lines:
                if line.kind == "+" and line.content.strip() == line_content:
                    return line.target_line_no
    return None
