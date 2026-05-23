# Major Artifacts

This directory contains the artifact cases and scripts used for the
multi-branch and data-leakage experiments.

## Artifact Files

- `300-multibranch-case.json`
  - 300 selected multi-branch patch-porting cases.
- `20-dataleakage-case.json`
  - 20 selected data-leakage/security-fix cases for qualitative inspection.
  - The file contains 17 semantically successful cases and 3 unsuccessful cases.

Each artifact entry has the following fields:

```json
{
  "cve_id": "CVE-...",
  "repository": "owner/repo",
  "fix_commit": "...",
  "target_commit": "...",
  "oracle_patch": "...",
  "generated_patch": "...",
  "semantic_similar": true
}
```

`oracle_patch` contains only source-code changes from the fix commit. Test,
documentation, package/configuration, lockfile, and generated build-output
changes are excluded.

## Quick Start

The artifact JSON files above are outputs for inspection. They are not used
directly as runner inputs.

To run the reproduction pipeline, prepare one input JSON file per case. Replace
all placeholder values with real commits and a local repository path:

```json
{
  "cve_id": "CVE-2026-XXXX",
  "fix_commit": "full_fix_commit_sha",
  "target_commit": "full_target_commit_sha",
  "repo_path": "/absolute/path/to/local/repo",
  "model": "deepseek-api"
}
```

`model` is optional and defaults to `deepseek-api`. `target_fix_commit` is also
optional. For the data-leakage artifacts it is omitted so semantic comparison
uses the source `fix_commit` patch directly.

Run one case:

```bash
python3 run_linux_case.py --input path/to/input.json --output result.json
```

Run a batch:

```bash
python3 run_linux_case.py \
  --input-list path/to/input-list.txt \
  --output-dir path/to/results
```

`input-list.txt` should contain one input JSON path per line.

Local clones of the referenced repositories are required. LLM-backed stages
require network/API access for the configured model. Relative input paths are
resolved relative to this `major-artifacts/` directory; absolute paths are
recommended.
