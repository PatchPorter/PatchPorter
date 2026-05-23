from pathlib import Path

from .diff_builder import apply_hunk_edits, build_unified_diff
from .git_utils import (
    commit_exists,
    get_commit_patch,
    get_file_at_commit,
    get_parent_commit,
    rev_parse,
)
from .localizer import LocalizationError, localize_file_patch
from .llm import LLMError
from .models import HunkEdit, PortingRequest, PortingResult
from .patch_parser import (
    PatchParseError,
    extract_hunk_anchors,
    parse_patch_content,
    split_file_patch_into_change_chunks,
)
from .prompting import build_dynamic_context, generate_replacement
from .semantic import semantic_similarity_check


def port_patch(request: PortingRequest) -> PortingResult:
    repo_path = Path(request.repo_path).resolve()
    try:
        if not repo_path.exists():
            return _failed(request, "invalid_input", f"repo_path does not exist: {repo_path}")

        fix_commit = rev_parse(repo_path, request.fix_commit)
        target_commit = rev_parse(repo_path, request.target_commit)
        if not commit_exists(repo_path, fix_commit):
            return _failed(request, "invalid_input", f"fix_commit does not exist: {request.fix_commit}")
        if not commit_exists(repo_path, target_commit):
            return _failed(request, "invalid_input", f"target_commit does not exist: {request.target_commit}")

        pre_patch_commit = get_parent_commit(repo_path, fix_commit)
        if not pre_patch_commit:
            return _failed(request, "invalid_input", "fix_commit has no parent commit")

        patch_content = get_commit_patch(repo_path, fix_commit)
        if not patch_content.strip():
            return _failed(request, "invalid_input", "fix_commit patch is empty")

        try:
            file_patch = parse_patch_content(patch_content, filter_irrelevant_files=True)[0]
        except PatchParseError as exc:
            return _failed(request, "patch_parse_failed", str(exc))

        source_path = file_patch.source_path if file_patch.source_path != "/dev/null" else file_patch.target_path
        pre_patch_content = get_file_at_commit(repo_path, pre_patch_commit, source_path)
        if pre_patch_content is None:
            return _failed(request, "invalid_input", f"source file not found at fix parent: {source_path}")

        file_patch = split_file_patch_into_change_chunks(file_patch, pre_patch_content)
        anchors = extract_hunk_anchors(file_patch, pre_patch_content)
        try:
            localizations = localize_file_patch(
                repo_path,
                file_patch,
                anchors,
                fix_commit,
                pre_patch_commit,
                target_commit,
                request.model,
            )
        except LocalizationError as exc:
            return _failed(request, "localization_failed", str(exc))

        for index, localization in enumerate(localizations):
            localization.hunk_index = index

        target_file = localizations[0].file_path
        target_content = get_file_at_commit(repo_path, target_commit, target_file)
        if target_content is None:
            return _failed(request, "localization_failed", f"target file not found: {target_file}")

        edits: list[HunkEdit] = []
        target_lines = target_content.splitlines(keepends=True)
        for localization in localizations:
            hunk = file_patch.hunks[localization.hunk_index]
            lines = localization.lines
            if lines and lines[0] == -1:
                target_code = target_lines[-1] if target_lines else ""
                start_line = -1
                end_line = -1
            elif hunk.is_insert_only:
                start_line = min(lines)
                end_line = start_line - 1
                start = max(0, start_line - 1)
                end = min(len(target_lines), start_line)
                target_code = "".join(target_lines[start:end])
            else:
                start_line = min(lines)
                end_line = max(lines)
                start = max(0, start_line - 1)
                end = min(len(target_lines), end_line)
                target_code = "".join(target_lines[start:end])

            context = build_dynamic_context(target_content, lines)
            try:
                replacement = generate_replacement(hunk, target_code, context, request.model)
            except LLMError as exc:
                return _failed(request, "llm_generation_failed", str(exc))
            if not replacement.strip() and not hunk.is_delete_only:
                return _failed(request, "llm_generation_failed", f"empty replacement for hunk {localization.hunk_index}")
            edits.append(HunkEdit(localization.hunk_index, target_file, start_line, end_line, replacement))

        modified_content = apply_hunk_edits(target_content, edits)
        diff_text = build_unified_diff(target_file, target_content, modified_content)
        if not diff_text.strip():
            return _failed(request, "empty_diff", "generated diff is empty")

        try:
            reference_patch_for_semantic = patch_content
            if request.target_fix_commit:
                target_fix_commit = rev_parse(repo_path, request.target_fix_commit)
                if not commit_exists(repo_path, target_fix_commit):
                    return PortingResult(
                        cve_id=request.cve_id,
                        fix_commit=fix_commit,
                        target_commit=target_commit,
                        diff_text=diff_text,
                        semantic_similar=False,
                        status="semantic_check_failed",
                        message=f"target_fix_commit does not exist: {request.target_fix_commit}",
                    )
                reference_patch_for_semantic = get_commit_patch(repo_path, target_fix_commit)

            similar, reason = semantic_similarity_check(
                request.cve_id,
                reference_patch_for_semantic,
                diff_text,
                request.model,
            )
        except LLMError as exc:
            return PortingResult(
                cve_id=request.cve_id,
                fix_commit=fix_commit,
                target_commit=target_commit,
                diff_text=diff_text,
                semantic_similar=False,
                status="semantic_check_failed",
                message=str(exc),
            )
        return PortingResult(
            cve_id=request.cve_id,
            fix_commit=fix_commit,
            target_commit=target_commit,
            diff_text=diff_text,
            semantic_similar=similar,
            status="success",
            message=reason,
        )
    except Exception as exc:
        return _failed(request, "unexpected_error", str(exc))


def _failed(request: PortingRequest, status: str, message: str) -> PortingResult:
    return PortingResult(
        cve_id=request.cve_id,
        fix_commit=request.fix_commit,
        target_commit=request.target_commit,
        diff_text="",
        semantic_similar=False,
        status=status,
        message=message,
    )
