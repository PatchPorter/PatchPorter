"""Step 5: Recover placeholders in generated patches back to full code.

Replaces /* placeholder_N */ markers with the original code pieces
that were removed during reduction.
"""

import json
import os
import sys
import argparse
import difflib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "reduction_js"))
from reduction_js.fcu import FunctionCompareUtilities
from reduction_js.reducer import Reducer

DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset")


def diff_strings(a, b):
    diff = difflib.unified_diff(
        a.splitlines(), b.splitlines(),
        fromfile="a", tofile="b", lineterm=""
    )
    return "\n".join(diff)


def read_json(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        return json.load(f)


def postprocess(output_string, key_before_target="### Function After (target):"):
    if key_before_target in output_string:
        parts = output_string.split(key_before_target)
        patch = parts[-1].strip("#").strip("\n")
        return patch
    else:
        return None


def do_recover(generations, test_set, origin_set):
    fcu = FunctionCompareUtilities()
    slicer = Reducer(tolerant=True)

    for sample in test_set:
        sid = sample["id"]
        if sid not in generations:
            print(f"ID {sid} not in generations, skip")
            continue

        if isinstance(generations[sid], str):
            gen = generations[sid]
            gen_processed = postprocess(output_string=gen,
                                        key_before_target="### Function After (target):")
        else:
            parts = generations[sid]["output"].split("```javascript", 1)
            if len(parts) == 2:
                code_block = parts[1].split("```", 1)[0]
            else:
                code_block = generations[sid]["output"].split("Function After (target):")[-1]
            gen_processed = code_block.strip("\n")

        if len(sample.get("removed_pieces_sliced_target", [])) > 0:
            gen_processed = slicer.do_recovering(
                reduced_func=gen_processed,
                removed_pieces=sample["removed_pieces_sliced_target"]
            )

        origin_set[sid]["target_after"] = gen_processed

    return origin_set


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 5: Recover placeholders in generated patches")
    parser.add_argument("--generations", required=True,
                        help="Path to id2gen.json or id2patch.json")
    parser.add_argument("--test_set", default=os.path.join(DATA_DIR, "sliced", "baseline_ppathf_reduced.json"),
                        help="Path to sliced reduced dataset")
    parser.add_argument("--origin", default=os.path.join(DATA_DIR, "baseline.json"),
                        help="Path to baseline.json")
    parser.add_argument("--output", required=True,
                        help="Path to save recovered dataset")
    args = parser.parse_args()

    generations = read_json(args.generations)
    test_set = read_json(args.test_set)
    origin_set = read_json(args.origin)

    recovered = do_recover(generations, test_set, origin_set)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(recovered, f, indent=4)
    print(f"Recovered data saved to {args.output}")
