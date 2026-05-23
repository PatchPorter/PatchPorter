import argparse
import importlib.util
import json
import sys
from dataclasses import asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


DEFAULT_INPUT = "inputs/linux_pairs/cve-2012-2372_0a743164_to_b0809483.json"


def load_package(repo_root: Path):
    spec = importlib.util.spec_from_file_location(
        "standalone_porter",
        repo_root / "__init__.py",
        submodule_search_locations=[str(repo_root)],
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load package from {repo_root}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run standalone_porter Linux case(s)")
    parser.add_argument(
        "--input",
        default=DEFAULT_INPUT,
        help="Path to an input JSON file",
    )
    parser.add_argument(
        "--input-list",
        help="Path to a text file with one input JSON path per line",
    )
    parser.add_argument(
        "--output",
        help="Optional path to write the result JSON",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory to write batch result JSON files",
    )
    parser.add_argument(
        "--jobs",
        type=int,
        default=1,
        help="Number of concurrent workers for --input-list mode",
    )
    return parser


def resolve_path(repo_root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = repo_root / path
    return path


def run_one_case(package, repo_root: Path, input_path: Path) -> tuple[object, str]:
    request = package.PortingRequest.from_json_file(input_path)
    result = package.port_patch(request)
    result_json = json.dumps(asdict(result), ensure_ascii=False, indent=2)
    return result, result_json


def output_name_for_input(input_path: Path) -> str:
    return f"{input_path.stem}_result.json"


def process_batch_case(package, repo_root: Path, input_path: Path, output_dir: Path | None) -> dict[str, object]:
    result, result_json = run_one_case(package, repo_root, input_path)
    if output_dir:
        output_path = output_dir / output_name_for_input(input_path)
        output_path.write_text(result_json + "\n", encoding="utf-8")
    return {
        "input": str(input_path),
        "cve_id": result.cve_id,
        "status": result.status,
        "semantic_similar": result.semantic_similar,
        "message": result.message,
    }


def main() -> int:
    args = build_parser().parse_args()
    repo_root = Path(__file__).resolve().parent
    package = load_package(repo_root)

    if args.input_list:
        input_list_path = resolve_path(repo_root, args.input_list)
        input_paths = [
            resolve_path(repo_root, line.strip())
            for line in input_list_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        output_dir = resolve_path(repo_root, args.output_dir) if args.output_dir else None
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)

        summary: list[dict[str, object]] = []
        if args.jobs <= 1:
            for input_path in input_paths:
                summary.append(process_batch_case(package, repo_root, input_path, output_dir))
        else:
            with ThreadPoolExecutor(max_workers=args.jobs) as executor:
                futures = [
                    executor.submit(process_batch_case, package, repo_root, input_path, output_dir)
                    for input_path in input_paths
                ]
                for future in as_completed(futures):
                    summary.append(future.result())
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return 0

    input_path = resolve_path(repo_root, args.input)
    result, result_json = run_one_case(package, repo_root, input_path)

    if args.output:
        output_path = resolve_path(repo_root, args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(result_json + "\n", encoding="utf-8")

    print(result_json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
