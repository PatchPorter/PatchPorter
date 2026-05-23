import json
import os
from pathlib import Path
import urllib.error
import urllib.request


class LLMError(RuntimeError):
    pass


def complete_prompt(prompt: str, model: str = "deepseek-api") -> str:
    if model != "deepseek-api":
        raise LLMError(f"standalone porter currently supports deepseek-api only, got {model}")

    load_env_file(Path(__file__).resolve().parent / ".env")
    api_key = os.getenv("DEEPSEEK_API_KEY")
    if not api_key:
        raise LLMError("DEEPSEEK_API_KEY is not set")

    base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com").rstrip("/")
    model_name = os.getenv("DEEPSEEK_MODEL") or os.getenv("DEEPSEEK_MODEL_NAME") or "deepseek-chat"
    payload = {
        "model": model_name,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0,
    }
    request = urllib.request.Request(
        f"{base_url}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise LLMError(f"DeepSeek HTTP error {exc.code}: {body}") from exc
    except Exception as exc:
        raise LLMError(f"DeepSeek request failed: {exc}") from exc

    try:
        return data["choices"][0]["message"]["content"]
    except Exception as exc:
        raise LLMError(f"invalid DeepSeek response: {data}") from exc


def load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def extract_tagged_block(text: str, begin: str, end: str) -> str:
    start = text.find(begin)
    finish = text.find(end)
    if start >= 0 and finish > start:
        return text[start + len(begin):finish].strip()
    return strip_code_fence(text)


def strip_code_fence(text: str) -> str:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].startswith("```"):
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return stripped
