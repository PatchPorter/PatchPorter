import json

from .llm import complete_prompt


def semantic_similarity_check(
    cve_id: str,
    reference_patch: str,
    generated_diff: str,
    model: str,
) -> tuple[bool, str]:
    if not generated_diff.strip():
        return False, "generated diff is empty"

    prompt = f"""You are a security patch review expert.

Determine whether the generated porting diff implements the same security fix intent as the reference fix patch.
Do not require identical code text. Focus on security semantics and whether the vulnerable behavior is fixed in the same way.

CVE:
{cve_id}

Reference fix patch:
```diff
{reference_patch}
```

Generated porting diff:
```diff
{generated_diff}
```

Return strict JSON only:
{{"similar": true/false, "reason": "..."}}
"""
    output = complete_prompt(prompt, model)
    try:
        start = output.find("{")
        end = output.rfind("}")
        data = json.loads(output[start:end + 1])
        return bool(data.get("similar")), str(data.get("reason", ""))
    except Exception:
        lowered = output.lower()
        if "true" in lowered and "false" not in lowered:
            return True, output.strip()
        return False, output.strip()
