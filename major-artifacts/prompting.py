from .llm import complete_prompt, extract_tagged_block
from .models import Hunk


PATCHED_BEGIN = "[[PATCHED_CODE_BEGIN]]"
PATCHED_END = "[[PATCHED_CODE_END]]"


BACKPORT_WITH_LOCALIZATION = """You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: Your task is to analyze a known vulnerability patch and accurately apply its core fix logic to the target vulnerable code. To help you better understand the code structure, I will provide the code context of the target code.
Input:
- Vulnerability Patch: Source code differences (diff) containing the vulnerability fix logic.
- Target Vulnerable Code: The target vulnerable code snippet that needs to be fixed.
- Code Context: The code surrounding the target vulnerable code in the source file, provided for reference only to help you understand how to customize the patch application.
Output:
- Fixed Target Code: ONLY the repaired target vulnerable code after applying the patch logic. DO NOT output the surrounding context code.
Requirements:
1. Your modifications must strictly follow the fix logic in the vulnerability patch. Do not introduce any new features, code refactoring, or formatting adjustments that are unrelated to the code change of the patch.
2. CRITICAL: Your output should contain ONLY the modified target vulnerable code itself. The code context is for reference only to help you understand the structure and customize the patch. DO NOT include any context code in your output. Only output the minimal code segment that needs to be modified.
3. The final output must be pure code. Do not include any explanations or any descriptive text.
4. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output. Output valid, executable code only.

Vulnerability Patch:
```
{patch}
```

Target Vulnerable Code:
```
{target_code}
```

Code Context:
```
{context}
```

Output:
"""


BACKPORT_DELETION = """You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: The vulnerability patch contains DELETION operations. Your task is to analyze which code should be REMOVED to fix the vulnerability.
Input:
- Vulnerability Patch: Source code differences showing lines to be DELETED (marked with -).
- Target Vulnerable Code: The current vulnerable code that needs to have lines removed.
Output:
- Fixed Target Code: The code AFTER removing the vulnerable lines. If all lines should be deleted, output: [EMPTY]
Requirements:
1. CRITICAL: Lines marked with "-" in the patch should be REMOVED from your output.
2. If the patch shows only deletions with no additions, DO NOT include those deleted lines in your output.
3. Your output must be executable code after deletion. Do not include explanations.
4. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output.
5. If the entire target code is deleted, output exactly: [EMPTY]

Vulnerability Patch (lines to DELETE):
```
{patch}
```

Target Vulnerable Code:
```
{target_code}
```

Output the code after deletion:
"""


BACKPORT_WITH_LOCALIZATION_INSERT = """You are a security vulnerability expert specializing in vulnerability analysis and repair. You excel at precisely porting security patches from one code version to another.
Core Task: The vulnerability patch contains only INSERTION operations (no deletions or modifications). Your task is to analyze the patch and insert the security fix at the appropriate location in the target code.
Input:
- Vulnerability Patch: Source code differences (diff) containing the security fix logic to be inserted.
- Target Code Anchor: The code snippet that serves as a reference point (anchor) for where to insert the fix. This is NOT the code to be modified, but rather a location marker.
- Code Context: The code surrounding the target anchor in the source file, provided for reference only to help you understand how to customize the patch application.
Output:
- Fixed Code: ONLY the modified target code anchor with the security fix inserted. DO NOT output the surrounding context code.
Requirements:
1. This is an INSERTION operation. The target code anchor should remain unchanged, and you need to insert the patch logic near it at the appropriate position.
2. CRITICAL: Do NOT output the "<add here>" marker. It is only an internal anchor hint. Remove it from the final output.
3. Your modifications must strictly follow the fix logic in the vulnerability patch. Do not introduce any new features, code refactoring, or formatting adjustments that are unrelated to the code change of the patch.
4. CRITICAL: The code context is for reference only to help you understand the structure and customize the patch. DO NOT include any context code in your output. Only output the minimal code segment that contains the anchor and the inserted fix.
5. The final output must be pure code. Do not include any explanations or any descriptive text.
6. CRITICAL: Do NOT include any diff syntax symbols (such as +, -, @@) in your output. Output valid, executable code only.

Output Format Requirements (STRICT):
1. Output MUST contain two sections in this exact order:
    INSERT_BEFORE:
    (only the lines to insert)
    ANCHOR:
    (the original anchor code, unchanged)
2. Do NOT include any other text.

Vulnerability Patch:
```
{patch}
```

Target Code Anchor:
```
{target_code}
```

Code Context:
```
{context}
```

Output:
"""


def build_dynamic_context(file_content: str, lines: list[int]) -> str:
    file_lines = file_content.splitlines()
    if not file_lines:
        return ""
    if lines and lines[0] == -1:
        start = max(0, len(file_lines) - 40)
        return "\n".join(file_lines[start:])

    start_line = min(lines)
    end_line = max(lines)
    function_context = _find_enclosing_brace_block(file_lines, start_line, end_line)
    if function_context:
        return function_context

    start = max(0, start_line - 21)
    end = min(len(file_lines), end_line + 20)
    return "\n".join(file_lines[start:end])


def _find_enclosing_brace_block(lines: list[str], start_line: int, end_line: int) -> str:
    start_idx = max(0, start_line - 1)
    open_idx = None
    for index in range(start_idx, -1, -1):
        line = lines[index]
        if "{" in line and ("function" in line or "=>" in line or ")" in line):
            open_idx = index
            break
    if open_idx is None:
        return ""

    depth = 0
    close_idx = None
    for index in range(open_idx, len(lines)):
        for char in lines[index]:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
        if depth <= 0 and index >= end_line - 1:
            close_idx = index
            break
    if close_idx is None:
        return ""
    return "\n".join(lines[open_idx:close_idx + 1])


def build_hunk_prompt(hunk: Hunk, target_code: str, context: str) -> str:
    patch_text = hunk.as_patch_text()
    if hunk.is_delete_only:
        return BACKPORT_DELETION.format(patch=patch_text, target_code=target_code)
    elif hunk.is_insert_only:
        return BACKPORT_WITH_LOCALIZATION_INSERT.format(
            patch=patch_text,
            target_code=target_code,
            context=context,
        )
    return BACKPORT_WITH_LOCALIZATION.format(
        patch=patch_text,
        target_code=target_code,
        context=context,
    )


def generate_replacement(hunk: Hunk, target_code: str, context: str, model: str) -> str:
    prompt = build_hunk_prompt(hunk, target_code, context)
    output = complete_prompt(prompt, model)
    if hunk.is_insert_only:
        return extract_insert_before(output)
    replacement = extract_tagged_block(output, PATCHED_BEGIN, PATCHED_END)
    if replacement == output.strip():
        replacement = replacement.replace("[EMPTY]", "").strip()
    return replacement


def extract_insert_before(output: str) -> str:
    text = output.strip()
    if "INSERT_BEFORE:" not in text:
        return text.replace("<add here>", "").strip()
    after = text.split("INSERT_BEFORE:", 1)[1]
    insert = after.split("ANCHOR:", 1)[0] if "ANCHOR:" in after else after
    return insert.replace("<add here>", "").strip()
