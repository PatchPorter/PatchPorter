#!/usr/bin/env python3
"""Basic repository smoke test that does not require external services."""

from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def compile_python_files() -> None:
    for path in sorted(ROOT.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        source = path.read_text(encoding="utf-8")
        compile(source, str(path), "exec")


def check_required_files() -> None:
    required = [
        ROOT / "README.md",
        ROOT / "LICENSE",
        ROOT / "src" / "config.py",
        ROOT / "src" / "patchbp.py",
        ROOT / "data" / "cve-c-patch.json",
        ROOT / "eval" / "results" / "baseline.json",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        raise FileNotFoundError(f"Missing required files: {missing}")


def check_json_files() -> None:
    for path in sorted((ROOT / "data").glob("*.json")):
        with path.open() as f:
            json.load(f)
    for path in sorted((ROOT / "eval" / "results").glob("*.json")):
        with path.open() as f:
            json.load(f)


def main() -> None:
    check_required_files()
    check_json_files()
    compile_python_files()
    print("Smoke test passed.")


if __name__ == "__main__":
    main()
