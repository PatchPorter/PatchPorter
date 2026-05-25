"""Step 1: Convert baseline.json to PPatHF list format.

Input:  dataset/baseline.json   (dict keyed by id)
Output: dataset/baseline_ppathf.json  (list of samples)
"""

import json
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset")

if __name__ == "__main__":
    with open(os.path.join(DATA_DIR, "baseline.json"), "r", encoding="utf-8") as f:
        data = json.load(f)

    processed = []
    for key, value in data.items():
        if value.get("target_before") is None:
            continue
        processed.append({
            "id": key,
            "method_name": value["method_name"],
            "func_before_source": value["origin_before"],
            "func_after_source": value["origin_after"],
            "func_before_target": value["target_before"],
        })

    os.makedirs(DATA_DIR, exist_ok=True)
    output_path = os.path.join(DATA_DIR, "baseline_ppathf.json")
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(processed, f, indent=4, ensure_ascii=False)
    print(f"Converted {len(processed)} samples -> {output_path}")
