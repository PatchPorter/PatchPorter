"""Step 4: Post-process LLM output to extract the actual patch from raw generations.

Handles both StarCoder (plain text) and DeepSeek (markdown-wrapped code blocks).
Merges extracted patches back into the origin dataset.
"""

import json
import argparse
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), "dataset")


def read_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)


def get_patch(output_string, key_before_target="### Function After (target):"):
    if key_before_target in output_string:
        parts = output_string.split(key_before_target)
        patch = parts[-1].strip("#").strip("\n")
        return patch
    else:
        return None


def post_process(input_data, gen_patchs):
    for key, gen_patch in gen_patchs.items():
        if "tokens" in gen_patch:
            patch = get_patch(gen_patch["output"], "```javascript")
            if patch is not None:
                input_data[key]["target_after"] = patch
            else:
                patch = get_patch(gen_patch["output"], "### Function After (target):")
                if patch is not None:
                    input_data[key]["target_after"] = patch
                else:
                    input_data[key]["target_after"] = gen_patch["output"]
        else:
            patch = get_patch(gen_patch, "### Function After (target):")
            print(patch)
            input_data[key]["target_after"] = patch
    return input_data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 4: Extract patches from LLM output")
    parser.add_argument("--baseline", default=os.path.join(DATA_DIR, "baseline.json"),
                        help="Path to baseline.json (default: dataset/baseline.json)")
    parser.add_argument("--gen_data", required=True,
                        help="Path to generation output (id2gen.json or id2patch.json)")
    parser.add_argument("--output", required=True,
                        help="Path to save merged result")
    args = parser.parse_args()

    input_data = read_json(args.baseline)
    gen_data = read_json(args.gen_data)

    saved_data = post_process(input_data, gen_data)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(saved_data, f, indent=2)

    print(f"Post-processed data saved to {args.output}")
