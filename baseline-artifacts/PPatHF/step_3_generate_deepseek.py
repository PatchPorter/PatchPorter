"""Step 3: Generate patches via DeepSeek API."""

import json
import os
import argparse
from openai import OpenAI
from tqdm import tqdm

PROMPT_TEMPLATE = {
    "instruction": (
        "Below is a patch (including function before and function after) from origin code, "
        "paired with a corresponding function before from target code. "
        "Adapt the patch from origin to target by generating the function after "
        "based on the given function before.\n\n"
    ),
    "context": (
        "### Function Before (origin):\n{func_before_source}\n\n"
        "### Function After (origin):\n{func_after_source}\n\n"
        "### Function Before (target):\n{func_before_target}\n\n"
        "### Function After (target):\n"
    ),
    "output": "{func_after_target}"
}


def build_prompt(sample):
    instruction = PROMPT_TEMPLATE["instruction"]
    context = PROMPT_TEMPLATE["context"].format(
        func_before_source=sample["func_before_source"],
        func_after_source=sample["func_after_source"],
        func_before_target=sample["func_before_target"],
    )
    return instruction + context


def generate_patch(samples, api_key, model="deepseek-chat", max_tokens=8192):
    client = OpenAI(api_key=api_key, base_url="https://api.deepseek.com")
    id2patch = {}

    for sample in tqdm(samples):
        prompt = build_prompt(sample)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": ""},
                {"role": "user", "content": prompt},
            ],
            max_tokens=max_tokens,
            temperature=0,
        )
        usage = response.usage
        generated_code = response.choices[0].message.content.strip()
        id2patch[sample["id"]] = {
            "prompt": prompt,
            "output": generated_code,
            "tokens": {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
            },
        }

    return id2patch


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 3: DeepSeek API inference")
    parser.add_argument("--input", required=True, help="Path to sliced dataset (e.g. dataset/sliced/baseline_ppathf_reduced.json)")
    parser.add_argument("--output", required=True, help="Path to save id2patch output")
    parser.add_argument("--model", default="deepseek-chat")
    parser.add_argument("--max_tokens", type=int, default=8192)
    args = parser.parse_args()

    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise ValueError("DEEPSEEK_API_KEY environment variable not set")

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    patches = generate_patch(data, api_key=api_key, model=args.model, max_tokens=args.max_tokens)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(patches, f, indent=2, ensure_ascii=False)

    print(f"Patches saved to {args.output}")
