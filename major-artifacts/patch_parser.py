import re
from pathlib import PurePosixPath

from .models import FilePatch, Hunk, PatchLine, HunkAnchor


class PatchParseError(RuntimeError):
    pass


def _normalize_path(path: str) -> str:
    path = path.strip()
    if path == "/dev/null":
        return path
    if path.startswith("a/") or path.startswith("b/"):
        return path[2:]
    return path


CONFIG_FILENAMES = {
    ".babelrc",
    ".browserslistrc",
    ".editorconfig",
    ".eslintignore",
    ".eslintrc",
    ".eslintrc.cjs",
    ".eslintrc.js",
    ".eslintrc.json",
    ".gitignore",
    ".npmignore",
    ".npmrc",
    ".prettierrc",
    ".prettierrc.json",
    "babel.config.js",
    "cargo.lock",
    "composer.json",
    "composer.lock",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "jest.config.js",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "requirements.txt",
    "rollup.config.js",
    "setup.cfg",
    "setup.py",
    "tsconfig.json",
    "vite.config.js",
    "webpack.config.js",
    "yarn.lock",
}

CONFIG_SUFFIXES = {
    ".lock",
    ".toml",
    ".yaml",
    ".yml",
}

DOC_SUFFIXES = {
    ".adoc",
    ".md",
    ".markdown",
    ".rst",
    ".txt",
}

TEST_PATH_PARTS = {
    "__mocks__",
    "__snapshots__",
    "__test__",
    "__tests__",
    "spec",
    "specs",
    "test",
    "tests",
}

DOC_PATH_PARTS = {
    ".changeset",
    "changelog",
    "doc",
    "docs",
    "documentation",
    "examples",
}

GENERATED_PATH_PARTS = {
    "build",
    "coverage",
    "dist",
}


def is_irrelevant_patch_path(path: str) -> bool:
    normalized = _normalize_path(path)
    if normalized == "/dev/null":
        return False

    posix_path = PurePosixPath(normalized)
    parts = {part.lower() for part in posix_path.parts}
    name = posix_path.name.lower()
    suffix = posix_path.suffix.lower()

    if parts & TEST_PATH_PARTS:
        return True
    if parts & DOC_PATH_PARTS:
        return True
    if parts & GENERATED_PATH_PARTS:
        return True
    if name.startswith("readme") or name.startswith("changelog") or name.startswith("license"):
        return True
    if name in CONFIG_FILENAMES:
        return True
    if suffix in DOC_SUFFIXES:
        return True
    if suffix in CONFIG_SUFFIXES:
        return True
    return False


def _is_relevant_file_patch(file_patch: FilePatch) -> bool:
    paths = [
        path
        for path in (file_patch.source_path, file_patch.target_path)
        if path != "/dev/null"
    ]
    return any(not is_irrelevant_patch_path(path) for path in paths)


def parse_patch_content(patch_content: str, *, filter_irrelevant_files: bool = False) -> list[FilePatch]:
    files: list[FilePatch] = []
    file_by_path: dict[tuple[str, str], FilePatch] = {}
    current_file: FilePatch | None = None
    current_hunk: Hunk | None = None
    source_line = 0
    target_line = 0

    hunk_re = re.compile(
        r"^@@ -(?P<src>\d+)(?:,(?P<src_len>\d+))? "
        r"\+(?P<tgt>\d+)(?:,(?P<tgt_len>\d+))? @@"
    )

    for raw in patch_content.splitlines():
        if raw.startswith("diff --git "):
            parts = raw.split()
            if len(parts) < 4:
                raise PatchParseError(f"invalid diff header: {raw}")
            source_path = _normalize_path(parts[2])
            target_path = _normalize_path(parts[3])
            key = (source_path, target_path)
            current_file = file_by_path.get(key)
            if current_file is None:
                current_file = FilePatch(source_path, target_path)
                file_by_path[key] = current_file
                files.append(current_file)
            current_hunk = None
            continue

        if current_file is None:
            continue

        if raw.startswith("--- "):
            current_file.source_path = _normalize_path(raw[4:].split("\t", 1)[0])
            continue
        if raw.startswith("+++ "):
            current_file.target_path = _normalize_path(raw[4:].split("\t", 1)[0])
            continue

        match = hunk_re.match(raw)
        if match:
            src_start = int(match.group("src"))
            src_len = int(match.group("src_len") or "1")
            tgt_start = int(match.group("tgt"))
            tgt_len = int(match.group("tgt_len") or "1")
            current_hunk = Hunk(src_start, src_len, tgt_start, tgt_len)
            current_file.hunks.append(current_hunk)
            source_line = src_start
            target_line = tgt_start
            continue

        if current_hunk is None:
            continue
        if raw.startswith("\\ No newline at end of file"):
            continue
        if not raw:
            kind = " "
            content = ""
        else:
            kind = raw[0]
            content = raw[1:]
        if kind not in {" ", "+", "-"}:
            continue

        src_no = None
        tgt_no = None
        if kind == " ":
            src_no = source_line
            tgt_no = target_line
            source_line += 1
            target_line += 1
        elif kind == "-":
            src_no = source_line
            source_line += 1
        elif kind == "+":
            tgt_no = target_line
            target_line += 1
        current_hunk.lines.append(PatchLine(kind, content, src_no, tgt_no))

    if not files:
        raise PatchParseError("patch_content does not contain a diff --git header")
    if filter_irrelevant_files:
        files = [file_patch for file_patch in files if _is_relevant_file_patch(file_patch)]
        if not files:
            raise PatchParseError("patch_content does not contain relevant source-file changes")
    if len(files) != 1:
        raise PatchParseError("MVP only supports single-file patches")
    if not files[0].hunks:
        raise PatchParseError("patch_content does not contain any hunk")
    return files


def split_file_patch_into_change_chunks(file_patch: FilePatch, pre_patch_content: str) -> FilePatch:
    chunks = FilePatch(file_patch.source_path, file_patch.target_path)
    pre_lines = pre_patch_content.splitlines()
    pre_len = len(pre_lines)

    for hunk in file_patch.hunks:
        current_delete: list[PatchLine] = []
        current_add: list[PatchLine] = []

        for line in hunk.lines:
            if line.kind == "-":
                current_delete.append(line)
            elif line.kind == "+":
                current_add.append(line)
            else:
                _flush_change_chunk(
                    chunks,
                    current_delete,
                    current_add,
                    pre_lines,
                    pre_len,
                    anchor_line=line.source_line_no,
                    hunk_end_line=hunk.source_start + hunk.source_length,
                )
                current_delete = []
                current_add = []

        _flush_change_chunk(
            chunks,
            current_delete,
            current_add,
            pre_lines,
            pre_len,
            anchor_line=None,
            hunk_end_line=hunk.source_start + hunk.source_length,
        )

    return chunks if chunks.hunks else file_patch


def _flush_change_chunk(
    file_patch: FilePatch,
    removed: list[PatchLine],
    added: list[PatchLine],
    pre_lines: list[str],
    pre_len: int,
    anchor_line: int | None,
    hunk_end_line: int,
) -> None:
    if not removed and not added:
        return

    if removed and added:
        source_start = min(line.source_line_no for line in removed if line.source_line_no is not None)
        source_end = max(line.source_line_no for line in removed if line.source_line_no is not None)
        target_start = min(line.target_line_no for line in added if line.target_line_no is not None)
        target_end = max(line.target_line_no for line in added if line.target_line_no is not None)
        source_length = source_end - source_start + 1
        target_length = target_end - target_start + 1
        lines = list(removed) + list(added)
    elif removed:
        source_start = min(line.source_line_no for line in removed if line.source_line_no is not None)
        source_end = max(line.source_line_no for line in removed if line.source_line_no is not None)
        source_length = source_end - source_start + 1
        target_start = source_start
        target_length = 0
        lines = list(removed)
    else:
        source_start = anchor_line if anchor_line is not None else hunk_end_line
        source_start = _normalize_add_anchor(source_start, pre_lines, pre_len)
        target_start = min(line.target_line_no for line in added if line.target_line_no is not None)
        source_length = 1
        target_length = len(added)
        lines = list(added)

    file_patch.hunks.append(Hunk(source_start, source_length, target_start, target_length, lines))


def _normalize_add_anchor(anchor: int, pre_lines: list[str], pre_len: int) -> int:
    while 1 <= anchor <= pre_len and pre_lines[anchor - 1].strip() == "":
        anchor += 1
    if anchor > pre_len or (anchor == pre_len and pre_len > 0 and pre_lines[-1].strip() == ""):
        return -1
    return anchor


def extract_hunk_anchors(file_patch: FilePatch, pre_patch_content: str) -> list[HunkAnchor]:
    anchors: list[HunkAnchor] = []
    pre_lines = pre_patch_content.splitlines()
    pre_len = len(pre_lines)

    for index, hunk in enumerate(file_patch.hunks):
        removed_lines = [line.source_line_no for line in hunk.lines if line.kind == "-" and line.source_line_no]
        added_lines = [line.target_line_no for line in hunk.lines if line.kind == "+" and line.target_line_no]
        context_lines = [line.source_line_no for line in hunk.lines if line.kind == " " and line.source_line_no]

        if removed_lines and added_lines:
            hunk_type = "change"
            lines = list(range(min(removed_lines), max(removed_lines) + 1))
        elif removed_lines:
            hunk_type = "delete"
            lines = list(range(min(removed_lines), max(removed_lines) + 1))
        else:
            hunk_type = "add"
            anchor = _first_context_after_add(hunk)
            if anchor is None:
                anchor = context_lines[-1] if context_lines else hunk.source_start
            while 1 <= anchor <= pre_len and pre_lines[anchor - 1].strip() == "":
                anchor += 1
            lines = [-1] if anchor > pre_len else [anchor]

        anchors.append(HunkAnchor(index, file_patch.source_path, lines, hunk_type))
    return anchors


def _first_context_after_add(hunk: Hunk) -> int | None:
    seen_add = False
    for line in hunk.lines:
        if line.kind == "+":
            seen_add = True
            continue
        if seen_add and line.kind == " " and line.source_line_no is not None:
            return line.source_line_no
    return None
