"""Step 2: Run the JS reduction module, then prepare sliced dataset.

1. Reduce functions: replace non-critical code with /* placeholder_N */
2. Swap sliced-function fields into main fields for downstream inference

Usage:
  python step_2_reduce.py --input dataset/baseline_ppathf.json --output output/baseline_ppathf_reduced.json
"""

import sys
import json
import argparse
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "reduction_js"))
from main import do_reducing_serial, do_reducing_merge


def prepare_sliced(reduced_file, sliced_file):
    with open(reduced_file, "r", encoding="utf-8") as f:
        datas = json.load(f)
    for item in datas:
        item["func_before_source"] = item["func_before_sliced_source"]
        item["func_after_source"] = item["func_after_sliced_source"]
        item["func_before_target"] = item["func_before_sliced_target"]
    os.makedirs(os.path.dirname(sliced_file), exist_ok=True)
    with open(sliced_file, "w", encoding="utf-8") as f:
        json.dump(datas, f, indent=4, ensure_ascii=False)
    print(f"Sliced {len(datas)} samples -> {sliced_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 2: Reduce JS functions")
    parser.add_argument("--input", required=True, help="Path to baseline_ppathf.json")
    parser.add_argument("--output", required=True, help="Path to save reduced output")
    args = parser.parse_args()

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

    # 1. Reduce
    do_reducing_serial(args.input, args.output, id=0, base=1)
    do_reducing_merge(args.output, counts=1)
    print(f"Reduced dataset saved to {args.output}")

    # 2. Prepare sliced version
    sliced_file = os.path.join("dataset", "sliced", os.path.basename(args.output))
    prepare_sliced(args.output, sliced_file)
