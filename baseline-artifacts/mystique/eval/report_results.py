#!/usr/bin/env python3
"""Print a compact report from released evaluation summary JSON files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


RESULT_DIR = Path(__file__).resolve().parent / "results"


def summarize_value(value: Any) -> str:
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            if isinstance(item, (int, float, str)):
                parts.append(f"{key}={item}")
        return ", ".join(parts) if parts else f"{len(value)} entries"
    if isinstance(value, list):
        return f"{len(value)} rows"
    return str(value)


def main() -> None:
    files = sorted(RESULT_DIR.glob("*.json"))
    if not files:
        raise FileNotFoundError(f"No JSON result files found in {RESULT_DIR}")

    for path in files:
        with path.open() as f:
            data = json.load(f)
        print(f"\n{path.name}")
        if isinstance(data, dict):
            for key, value in data.items():
                print(f"  {key}: {summarize_value(value)}")
        else:
            print(f"  {summarize_value(data)}")


if __name__ == "__main__":
    main()
