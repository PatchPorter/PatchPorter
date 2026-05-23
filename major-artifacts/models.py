from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import json


@dataclass
class PortingRequest:
    cve_id: str
    fix_commit: str
    target_commit: str
    repo_path: Path
    model: str = "deepseek-api"
    target_fix_commit: Optional[str] = None

    @classmethod
    def from_json_file(cls, path: str | Path) -> "PortingRequest":
        input_path = Path(path)
        data = json.loads(input_path.read_text(encoding="utf-8"))
        return cls(
            cve_id=data["cve_id"],
            fix_commit=data["fix_commit"],
            target_commit=data["target_commit"],
            repo_path=Path(data["repo_path"]),
            model=data.get("model", "deepseek-api"),
            target_fix_commit=data.get("target_fix_commit"),
        )


@dataclass
class PortingResult:
    cve_id: str
    fix_commit: str
    target_commit: str
    diff_text: str
    semantic_similar: bool
    status: str
    message: str = ""


@dataclass
class PatchLine:
    kind: str
    content: str
    source_line_no: Optional[int] = None
    target_line_no: Optional[int] = None


@dataclass
class Hunk:
    source_start: int
    source_length: int
    target_start: int
    target_length: int
    lines: list[PatchLine] = field(default_factory=list)

    @property
    def is_insert_only(self) -> bool:
        has_add = any(line.kind == "+" for line in self.lines)
        has_del = any(line.kind == "-" for line in self.lines)
        return has_add and not has_del

    @property
    def is_delete_only(self) -> bool:
        has_add = any(line.kind == "+" for line in self.lines)
        has_del = any(line.kind == "-" for line in self.lines)
        return has_del and not has_add

    def as_patch_text(self) -> str:
        body = "\n".join(f"{line.kind}{line.content}" for line in self.lines)
        return (
            f"@@ -{self.source_start},{self.source_length} "
            f"+{self.target_start},{self.target_length} @@\n{body}"
        )


@dataclass
class FilePatch:
    source_path: str
    target_path: str
    hunks: list[Hunk] = field(default_factory=list)


@dataclass
class HunkAnchor:
    hunk_index: int
    file_path: str
    lines: list[int]
    hunk_type: str


@dataclass
class TracePoint:
    commit: str
    lines: list[int]
    file_path: str
    hunk_type: str


@dataclass
class LocalizationResult:
    hunk_index: int
    file_path: str
    lines: list[int]
    hunk_type: str
    base_commit: str
    status: str = "mapped"
    message: str = ""


@dataclass
class HunkEdit:
    hunk_index: int
    file_path: str
    start_line: int
    end_line: int
    replacement: str
