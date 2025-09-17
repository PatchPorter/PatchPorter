# PatchPorter

This paper introduces PatchPorter, an LLM-based method that automatically ports security patches for NPM packages. PatchPorter solves two main problems. First, its version tracing module leverages semantic understanding of LLM and code version history to identify the exact location of vulnerabilities. Second, it analyzes patch dependencies to provide the LLM with a minimal and sufficient context , which improves the patch quality and reduces errors. To comprehensively evaluate PatchPorter, we construct a dataset of 112 NPM vulnerabilities, each with a PoC for automatic testing. The results show that PatchPorter is much more effective than other methods and can also handle many different types of vulnerabilities. In addition, both of its core modules also perform better than other approaches.

This repository is the artifact of PatchPorter, and includes the following content:

## Project Structure

### 1. preliminary-study/ - Preliminary Study on porting data

Contains research and analysis tools for study of port data, primarily used for:

- **Metric Calculation** (`metric_c.py`, `metric_js.py`): 
    - Implements the SZZ algorithm for identifying target vulnerable versions. 
    - Computes code similarity between vulnerable pairs.
- **Data Files**:
  - `NPM-CVE.csv`: CVE information in NPM
  - `C-CVE.json`: CVE information in the C ecosystem

### 2. src/ - Porting Method Implementation

Core source code directory containing the complete patch porting implementation. See README.md in the src/ directory for more details.

### 3. dataset/ - Dataset

Contains datasets for evaluation, covering 112 NPM package security vulnerability cases:

#### Dataset Structure
Each subdirectory represents a specific vulnerability case, for example:
- `access-policy_3.1.0/`: CVE-2020-7674 vulnerability case
- `axios_0.21.0/`: axios library vulnerability case
- And 100+ other JavaScript package security vulnerability cases

#### Files in Each Case
- `package.json`: Vulnerability metadata (CVE ID, dependency information, fix commit, etc.)
- `vulnerable_versions.txt`: Vulnerable versions and corresponding commit hashes
- `patch.diff`: Original patch file
- `final-patch.diff`: Untangled patch file
- `*.test.js`: PoC
- `challenge-version.txt`: Target vulnerable version for backporting

