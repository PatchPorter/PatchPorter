# PatchPorter: LLM-Driven Security Patch Porting via Version Tracing and Context Selection for NPM

This repository contains the artifact for our paper **"PatchPorter: LLM-Driven Security Patch Porting via Version Tracing and Context Selection for NPM"**.

## Overview

PatchPorter is an automated tool for backporting security patches across different versions of JavaScript/NPM packages. It leverages Large Language Models (LLMs) with intelligent version tracing and context selection to generate accurate security patches for vulnerable package versions.


## Quick Start

### Prerequisites

- Python 3.8+
- Node.js 16+ and npm
- Git

### Installation

1. Clone the repository:
```bash
git clone https://github.com/PatchPorter/PatchPorter.git
cd PatchPorter
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Set up API keys (optional, for LLM inference):
```bash
export DEEPSEEK_API_KEY="your-deepseek-api-key"
export OPENAI_API_KEY="your-openai-api-key"  # For GPT-4 or other OpenAI models
```

### Running the Tool

```bash
# Run on all projects in the dataset
python core/run.py --all

# Run on a single project
python core/run.py --project dataset/redos/axios_0.21.0

# Run specific stages
python core/run.py --project dataset/redos/axios_0.21.0 --stages localize generate

# Use a specific model
python core/run.py --all --model gpt4o
```

For detailed usage instructions, see [core/README.md](core/README.md).

## Dataset

The evaluation dataset contains 112 vulnerable NPM packages across 5 vulnerability categories. Each project directory includes:
- Vulnerability metadata and CVE information
- Original security patches
- Multiple vulnerable versions for backporting evaluation

Dataset setup requires cloning from [SecBench.js](https://github.com/nicolo-ribaudo/nicolo-ribaudo.github.io). See [core/README.md](core/README.md) for setup instructions.

## Preliminary Study

The `motivation1-study/` directory contains data and analysis code for our preliminary study comparing code similarity patterns between NPM and C ecosystems. See [motivation1-study/README.md](motivation1-study/README.md) for details.


## Repository Structure

```
PatchPorter/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── core/                        # Main implementation
│   ├── run.py                   # CLI entry point
│   ├── pipeline.py              # Pipeline orchestration
│   ├── project.py               # Project abstraction
│   ├── config.py                # Configuration management
│   ├── managers/                # Core functionality modules
│   │   ├── localizer.py         # Version tracing & fault localization
│   │   ├── prompt.py            # Context selection & prompt generation
│   │   ├── llm.py               # LLM inference handler
│   │   ├── test.py              # Patch validation
│   │   └── ...                  # Other managers
│   ├── utils/                   # Utility functions
│   └── data/                    # Configuration files
├── dataset/                     # Evaluation dataset (113 vulnerable packages)
│   ├── code-injection/          # Code injection vulnerabilities
│   ├── command-injection/       # Command injection vulnerabilities
│   ├── path-traversal/          # Path traversal vulnerabilities
│   ├── prototype-pollution/     # Prototype pollution vulnerabilities
│   └── redos/                   # ReDoS vulnerabilities
└── motivation1-study/           # Preliminary study data & analysis
    ├── NPM-CVE.csv              # NPM vulnerability dataset
    ├── C-CVE.json               # C vulnerability dataset (for comparison)
    ├── plot_js_vs_c_cdf.py      # Similarity analysis visualization
    └── similarity_results/      # Pre-computed similarity metrics
```

