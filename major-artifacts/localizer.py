import ast
import re
from pathlib import Path

from .git_utils import (
    blame_line,
    choose_most_recent_commit,
    get_diff_between_files,
    get_file_at_commit,
    get_merge_base,
    get_parent_commit,
    is_ancestor,
    rev_list_path_between,
    resolve_file_path,
)
from .line_mapping import parse_line_number_mapping
from .llm import complete_prompt
from .models import FilePatch, HunkAnchor, LocalizationResult, TracePoint


class LocalizationError(RuntimeError):
    pass


def localize_file_patch(
    repo_path: Path,
    file_patch: FilePatch,
    anchors: list[HunkAnchor],
    fix_commit: str,
    pre_patch_commit: str,
    target_commit: str,
    model: str,
) -> list[LocalizationResult]:
    merge_base = get_merge_base(repo_path, pre_patch_commit, target_commit)
    if merge_base is None:
        raise LocalizationError("no common history between pre_patch_commit and target_commit")

    reference_content = get_file_at_commit(repo_path, fix_commit, file_patch.target_path)
    if reference_content is None:
        reference_content = get_file_at_commit(repo_path, pre_patch_commit, file_patch.source_path) or ""

    results: list[LocalizationResult] = []
    for anchor in anchors:
        try:
            if is_ancestor(repo_path, target_commit, pre_patch_commit):
                results.append(
                    localize_linear_backport(
                        repo_path,
                        anchor,
                        pre_patch_commit,
                        target_commit,
                        reference_content,
                        model,
                    )
                )
            else:
                results.append(
                    localize_two_branch_backport(
                        repo_path,
                        anchor,
                        pre_patch_commit,
                        target_commit,
                        merge_base,
                        reference_content,
                        model,
                    )
                )
        except LocalizationError as exc:
            if str(exc) != "no trace point is an ancestor of target_commit":
                raise
            results.append(
                localize_hunk_by_fuzzy_match(
                    repo_path,
                    file_patch,
                    anchor,
                    pre_patch_commit,
                    target_commit,
                    reference_content,
                )
            )
    return results


def localize_hunk_by_fuzzy_match(
    repo_path: Path,
    file_patch: FilePatch,
    anchor: HunkAnchor,
    pre_patch_commit: str,
    target_commit: str,
    reference_content: str,
) -> LocalizationResult:
    hunk = file_patch.hunks[anchor.hunk_index]
    source_path = file_patch.source_path if file_patch.source_path != "/dev/null" else file_patch.target_path
    target_path = resolve_file_path(repo_path, target_commit, source_path, reference_content)
    if target_path is None:
        target_path = resolve_file_path(repo_path, target_commit, file_patch.target_path, reference_content)
    if target_path is None:
        raise LocalizationError(f"fuzzy localization target file not found: {source_path}")

    target_content = get_file_at_commit(repo_path, target_commit, target_path)
    if target_content is None:
        raise LocalizationError(f"fuzzy localization target file not found: {target_path}")

    pre_patch_content = get_file_at_commit(repo_path, pre_patch_commit, source_path) or ""
    query_lines = build_fuzzy_query_lines(hunk, pre_patch_content)
    if not query_lines:
        raise LocalizationError(f"fuzzy localization has no usable query for hunk {anchor.hunk_index}")

    matched_lines = find_best_line_window(query_lines, target_content.splitlines())
    if not matched_lines:
        raise LocalizationError(f"fuzzy localization failed for hunk {anchor.hunk_index}: {target_path}")

    return LocalizationResult(anchor.hunk_index, target_path, matched_lines, anchor.hunk_type, target_commit, "fuzzy")


def build_fuzzy_query_lines(hunk, pre_patch_content: str) -> list[str]:
    removed = [line.content for line in hunk.lines if line.kind == "-"]
    if removed:
        return significant_lines(removed)

    pre_lines = pre_patch_content.splitlines()
    if hunk.source_start == -1:
        return []
    start = max(1, hunk.source_start - 3)
    end = min(len(pre_lines), hunk.source_start + 3)
    return significant_lines(pre_lines[start - 1:end])


def significant_lines(lines: list[str]) -> list[str]:
    result: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped in {"{", "}", "});", "};", ");"}:
            continue
        result.append(stripped)
    return result


def find_best_line_window(query_lines: list[str], target_lines: list[str]) -> list[int]:
    normalized_target = [line.strip() for line in target_lines]
    query = [line.strip() for line in query_lines if line.strip()]
    if not query or not normalized_target:
        return []

    best_score = 0.0
    best_start = -1
    best_length = len(query)
    candidate_lengths = sorted({max(1, len(query) - 1), len(query), len(query) + 1})
    for length in candidate_lengths:
        if length > len(normalized_target):
            continue
        for start in range(0, len(normalized_target) - length + 1):
            candidate = normalized_target[start:start + length]
            score = score_line_window(query, candidate)
            if score > best_score:
                best_score = score
                best_start = start
                best_length = length

    if best_start == -1 or best_score < 0.58:
        return []
    return list(range(best_start + 1, best_start + best_length + 1))


def score_line_window(query: list[str], candidate: list[str]) -> float:
    candidate_remaining = list(candidate)
    scores: list[float] = []
    exact_matches = 0
    for query_line in query:
        best_index = -1
        best_score = 0.0
        for index, candidate_line in enumerate(candidate_remaining):
            if not candidate_line:
                continue
            if query_line == candidate_line:
                score = 1.0
            elif query_line in candidate_line or candidate_line in query_line:
                score = 0.85
            else:
                score = similarity_ratio(query_line, candidate_line)
            if score > best_score:
                best_score = score
                best_index = index
        if best_index != -1:
            if best_score == 1.0:
                exact_matches += 1
            candidate_remaining.pop(best_index)
        scores.append(best_score)
    average = sum(scores) / len(scores)
    exact_bonus = 0.1 * (exact_matches / len(query))
    return min(1.0, average + exact_bonus)


def similarity_ratio(left: str, right: str) -> float:
    from difflib import SequenceMatcher

    return SequenceMatcher(None, left, right).ratio()


def localize_linear_backport(
    repo_path: Path,
    anchor: HunkAnchor,
    pre_patch_commit: str,
    target_commit: str,
    reference_content: str,
    model: str,
) -> LocalizationResult:
    trace = trace_hunk_history(
        repo_path,
        anchor,
        pre_patch_commit,
        target_commit,
        target_commit,
        reference_content,
        model,
    )
    return map_trace_to_target(repo_path, trace, target_commit, reference_content)


def localize_two_branch_backport(
    repo_path: Path,
    anchor: HunkAnchor,
    pre_patch_commit: str,
    target_commit: str,
    merge_base: str,
    reference_content: str,
    model: str,
) -> LocalizationResult:
    trace = trace_hunk_history(
        repo_path,
        anchor,
        pre_patch_commit,
        target_commit,
        merge_base,
        reference_content,
        model,
    )
    base_result = map_trace_to_target(repo_path, trace, merge_base, reference_content)
    return trace_target_side(
        repo_path,
        merge_base,
        target_commit,
        base_result.file_path,
        base_result.lines,
        base_result.hunk_type,
        reference_content,
    )


def trace_hunk_history(
    repo_path: Path,
    anchor: HunkAnchor,
    pre_patch_commit: str,
    target_commit: str,
    merge_base: str,
    reference_content: str,
    model: str,
) -> list[TracePoint]:
    history: list[TracePoint] = []
    before_commit = pre_patch_commit
    before_file_path = resolve_file_path(repo_path, before_commit, anchor.file_path, reference_content)
    if before_file_path is None:
        raise LocalizationError(f"source file not found at {before_commit}: {anchor.file_path}")

    before_lines = list(anchor.lines)
    hunk_type = anchor.hunk_type
    while True:
        if not before_lines or before_lines[0] == -1:
            history.append(TracePoint(before_commit, before_lines or [-1], before_file_path, hunk_type))
            break

        blame_commits = [
            commit
            for line in before_lines
            if (commit := blame_line(repo_path, before_commit, before_file_path, line))
        ]
        current_commit = choose_most_recent_commit(repo_path, before_commit, blame_commits)
        if current_commit is None or current_commit == before_commit:
            history.append(TracePoint(before_commit, before_lines, before_file_path, hunk_type))
            break

        if current_commit != merge_base and is_ancestor(repo_path, current_commit, merge_base):
            merge_file_path = resolve_file_path(repo_path, merge_base, before_file_path, reference_content)
            if merge_file_path is None:
                history.append(TracePoint(before_commit, before_lines, before_file_path, hunk_type))
                break
            diff_content = get_diff_between_files(
                repo_path,
                before_commit,
                before_file_path,
                merge_base,
                merge_file_path,
            )
            merge_lines = parse_line_number_mapping(diff_content, before_lines)
            history.append(TracePoint(merge_base, merge_lines, merge_file_path, hunk_type))
            break

        current_file_path = resolve_file_path(repo_path, current_commit, before_file_path, reference_content)
        if current_file_path is None:
            history.append(TracePoint(before_commit, before_lines, before_file_path, hunk_type))
            break

        diff_content = get_diff_between_files(
            repo_path,
            before_commit,
            before_file_path,
            current_commit,
            current_file_path,
        )
        after_lines = parse_line_number_mapping(diff_content, before_lines)
        history.append(TracePoint(current_commit, after_lines, current_file_path, hunk_type))

        if is_ancestor(repo_path, current_commit, target_commit):
            break

        parent_commit = get_parent_commit(repo_path, current_commit)
        if not parent_commit:
            break
        parent_file_path = resolve_file_path(repo_path, parent_commit, current_file_path, reference_content)
        if parent_file_path is None:
            break

        mapped = map_lines_to_parent_with_llm(
            repo_path,
            current_commit,
            current_file_path,
            after_lines,
            parent_commit,
            parent_file_path,
            hunk_type,
            model,
        )
        if not mapped:
            break
        before_commit = parent_commit
        before_file_path = parent_file_path
        before_lines, hunk_type = mapped

    if not history:
        raise LocalizationError(f"failed to trace hunk {anchor.hunk_index}")
    return history


def map_trace_to_target(
    repo_path: Path,
    trace: list[TracePoint],
    target_commit: str,
    reference_content: str,
) -> LocalizationResult:
    base = next((point for point in trace if is_ancestor(repo_path, point.commit, target_commit)), None)
    if base is None:
        raise LocalizationError("no trace point is an ancestor of target_commit")

    target_file_path = resolve_file_path(repo_path, target_commit, base.file_path, reference_content)
    if target_file_path is None:
        raise LocalizationError(f"target file not found at {target_commit}: {base.file_path}")

    if base.commit == target_commit:
        mapped_lines = base.lines
    elif base.lines and base.lines[0] == -1:
        mapped_lines = [-1]
    else:
        diff_content = get_diff_between_files(
            repo_path,
            base.commit,
            base.file_path,
            target_commit,
            target_file_path,
        )
        mapped_lines = sorted(set(parse_line_number_mapping(diff_content, base.lines)))

    if not mapped_lines:
        raise LocalizationError("line mapping to target_commit is empty")
    return LocalizationResult(-1, target_file_path, mapped_lines, base.hunk_type, base.commit)


def trace_target_side(
    repo_path: Path,
    merge_base: str,
    target_commit: str,
    file_path: str,
    lines: list[int],
    hunk_type: str,
    reference_content: str,
) -> LocalizationResult:
    if merge_base == target_commit:
        return LocalizationResult(-1, file_path, lines, hunk_type, merge_base)

    current_commit = merge_base
    current_file_path = resolve_file_path(repo_path, current_commit, file_path, reference_content)
    if current_file_path is None:
        raise LocalizationError(f"target-side base file not found at {merge_base}: {file_path}")
    current_lines = list(lines)

    target_file_path = resolve_file_path(repo_path, target_commit, current_file_path, reference_content)
    if target_file_path is None:
        raise LocalizationError(f"target file not found at {target_commit}: {current_file_path}")

    commits = rev_list_path_between(repo_path, merge_base, target_commit, current_file_path)
    for next_commit in commits:
        next_file_path = resolve_file_path(repo_path, next_commit, current_file_path, reference_content)
        if next_file_path is None:
            raise LocalizationError(f"target-side file not found at {next_commit}: {current_file_path}")

        if current_lines and current_lines[0] == -1:
            current_commit = next_commit
            current_file_path = next_file_path
            continue

        diff_content = get_diff_between_files(
            repo_path,
            current_commit,
            current_file_path,
            next_commit,
            next_file_path,
        )
        mapped_lines = sorted(set(parse_line_number_mapping(diff_content, current_lines)))
        if not mapped_lines:
            raise LocalizationError(
                f"target-side line mapping is empty at {next_commit[:12]} "
                f"from {current_commit[:12]} lines {current_lines}"
            )
        current_commit = next_commit
        current_file_path = next_file_path
        current_lines = mapped_lines

    if current_commit != target_commit:
        diff_content = get_diff_between_files(
            repo_path,
            current_commit,
            current_file_path,
            target_commit,
            target_file_path,
        )
        mapped_lines = sorted(set(parse_line_number_mapping(diff_content, current_lines)))
        if not mapped_lines:
            raise LocalizationError(
                f"target-side final line mapping is empty from {current_commit[:12]} "
                f"to {target_commit[:12]} lines {current_lines}"
            )
        current_lines = mapped_lines
        current_file_path = target_file_path

    return LocalizationResult(-1, current_file_path, current_lines, hunk_type, merge_base)


def map_lines_to_parent_with_llm(
    repo_path: Path,
    current_commit: str,
    current_file_path: str,
    current_lines: list[int],
    parent_commit: str,
    parent_file_path: str,
    hunk_type: str,
    model: str,
) -> tuple[list[int], str] | None:
    if not current_lines or current_lines[0] == -1:
        return (current_lines, hunk_type)

    diff_content = get_diff_between_files(
        repo_path,
        parent_commit,
        parent_file_path,
        current_commit,
        current_file_path,
    )
    removed_lines, line_map = extract_removed_lines(diff_content)
    if not removed_lines:
        reverse_diff = get_diff_between_files(
            repo_path,
            current_commit,
            current_file_path,
            parent_commit,
            parent_file_path,
        )
        mapped = parse_line_number_mapping(reverse_diff, current_lines)
        return (mapped, hunk_type) if mapped else None

    current_content = get_file_at_commit(repo_path, current_commit, current_file_path) or ""
    parent_content = get_file_at_commit(repo_path, parent_commit, parent_file_path) or ""
    function_range = get_function_range_for_parent(current_content, parent_content, current_lines)
    if function_range != (-1, -1):
        removed_lines, line_map = extract_removed_lines(diff_content, function_range)
    else:
        removed_lines, line_map = extract_removed_lines(diff_content)
    current_text = "\n".join(
        current_content.splitlines()[line - 1]
        for line in current_lines
        if 1 <= line <= len(current_content.splitlines())
    )
    if not removed_lines:
        removed_lines, line_map = extract_removed_lines(diff_content)
    if not removed_lines:
        return None

    prompt = build_line_mapping_prompt(removed_lines, current_text)
    output = complete_prompt(prompt, model)
    selected = parse_llm_line_list(output)
    mapped_lines: list[int] = []
    for item in selected:
        if item in line_map:
            mapped_lines.extend(line_map[item])
            continue
        for code, lines in line_map.items():
            if code.strip() == item.strip():
                mapped_lines.extend(lines)
                break
    mapped_lines = sorted(set(mapped_lines))
    return (mapped_lines, hunk_type) if mapped_lines else None


def extract_removed_lines(
    diff_content: str,
    function_range: tuple[int, int] | None = None,
) -> tuple[list[str], dict[str, list[int]]]:
    from .patch_parser import parse_patch_content

    try:
        patches = parse_patch_content(diff_content)
    except Exception:
        return [], {}

    removed: list[str] = []
    line_map: dict[str, list[int]] = {}
    start, end = function_range if function_range is not None else (-1, -1)
    for file_patch in patches:
        for hunk in file_patch.hunks:
            for line in hunk.lines:
                if line.kind != "-" or line.source_line_no is None:
                    continue
                if start != -1 and not (start <= line.source_line_no <= end):
                    continue
                code = line.content.strip()
                removed.append(code)
                line_map.setdefault(code, []).append(line.source_line_no)
    return removed, line_map


def get_function_range_for_parent(
    current_content: str,
    parent_content: str,
    current_lines: list[int],
) -> tuple[int, int]:
    current_functions = parse_c_like_functions(current_content)
    parent_functions = parse_c_like_functions(parent_content)
    function_name = find_enclosing_function_name(current_lines, current_functions)
    if not function_name:
        return (-1, -1)
    return parent_functions.get(function_name, (-1, -1))


def find_enclosing_function_name(
    lines: list[int],
    functions: dict[str, tuple[int, int]],
) -> str | None:
    matches: list[tuple[str, tuple[int, int]]] = []
    for name, (start, end) in functions.items():
        if all(start <= line <= end for line in lines if line != -1):
            matches.append((name, (start, end)))
    if not matches:
        return None
    matches.sort(key=lambda item: (item[1][1] - item[1][0], item[1][0]))
    return matches[0][0]


def parse_c_like_functions(content: str) -> dict[str, tuple[int, int]]:
    lines = content.splitlines()
    functions: dict[str, tuple[int, int]] = {}
    signature = ""
    signature_start = 0

    for index, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("#", "//", "/*", "*")):
            continue

        if not signature:
            signature = stripped
            signature_start = index
        else:
            signature += " " + stripped

        if "{" not in stripped:
            if stripped.endswith((";", "}", ":")):
                signature = ""
            continue

        candidate = signature.split("{", 1)[0].strip()
        match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*$", candidate)
        if not match:
            signature = ""
            continue

        name = match.group(1)
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            signature = ""
            continue

        brace_depth = stripped.count("{") - stripped.count("}")
        end_index = index
        while brace_depth > 0 and end_index < len(lines):
            end_index += 1
            brace_depth += lines[end_index - 1].count("{") - lines[end_index - 1].count("}")

        functions[name] = (signature_start, end_index)
        signature = ""

    return functions


def build_line_mapping_prompt(candidate_lines: list[str], current_text: str) -> str:
    return f"""As a JavaScript code semantics expert, identify the lines from the target codebase that are most semantically similar to the given code.

Output requirements:
1. Output a Python-style list of exact line strings from the target codebase.
2. Do not output explanation or markdown.
3. If no match is found, output [].

Target codebase:
{chr(10).join(candidate_lines)}

Given code:
{current_text}

The most semantically similar lines:
"""


def parse_llm_line_list(output: str) -> list[str]:
    try:
        start = output.find("[")
        end = output.rfind("]")
        if start < 0 or end <= start:
            return []
        value = ast.literal_eval(output[start:end + 1])
        return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []
    except Exception:
        return []
