# PatchPorter Core Implementation

This directory contains the core implementation of PatchPorter, including the pipeline orchestration, version tracing, context selection, LLM integration, and patch validation.


## Pipeline Stages

PatchPorter executes the following stages:

1. **Localize** - Track vulnerable code across versions using git history and AST analysis
2. **Generate** - Create LLM prompts with selected context and patch information
3. **Infer** - Run LLM inference to generate backported patches
4. **Test** - Validate generated patches by applying and running tests

## Requirements

### Python Dependencies

Install via pip:

```bash
pip install -r ../requirements.txt
```

Key dependencies:
- `tree-sitter>=0.20.0` - AST parsing for JavaScript
- `tree-sitter-javascript>=0.20.0` - JavaScript grammar
- `unidiff>=0.7.0` - Unified diff parsing
- `nltk>=3.8.0` - Natural language processing
- `codebleu>=0.4.0` - Code similarity metrics
- `openai>=1.0.0` - LLM API client
- `numpy`, `matplotlib`, `scipy` - Data analysis and visualization

### Dataset Setup

The dataset projects need to be set up with their npm dependencies. Projects are based on [SecBench.js](https://github.com/cristianstaicu/SecBench.js):

```bash
# Clone SecBench.js for project structure reference
git clone https://github.com/cristianstaicu/SecBench.js.git

# For each project in dataset/, install npm dependencies
cd ../dataset/<project_name>
npm install
```

Each project directory should contain:
- `node_modules/<package_name>/` - The vulnerable package repository
- `patch.diff` - Original security patch
- `vulnerable_versions.txt` - List of vulnerable versions to backport
- `version-map.txt` - Mapping of versions to git commits

### API Configuration

Set environment variables for LLM API access:

```bash
# DeepSeek API (primary)
export DEEPSEEK_API_KEY="your-api-key"

# OpenAI API (for GPT-4, Gemini via proxy)
export OPENAI_API_KEY="your-api-key"
export OPENAI_BASE_URL="https://api.openai.com/v1"  # or your proxy URL
```

## Usage

### Command Line Interface

```bash
# Run all projects in batch
python run.py --all

# Run a single project
python run.py --project /path/to/project

# Run specific stages only
python run.py --project /path/to/project --stages localize generate

# Specify model for inference
python run.py --all --model gpt4o

# Use specific context granularity
python run.py --project /path/to/project --granularity function

# Enable debug logging
python run.py --project /path/to/project --debug
```

### Available Options

| Option | Description |
|--------|-------------|
| `--all` | Run on all projects from target-project.txt |
| `--project PATH` | Run on a single project |
| `--stages STAGES` | Space-separated list of stages: localize, generate, infer, test |
| `--model MODEL` | Model to use: deepseek-api, gpt4o, gemini, qwen3-14b, claude-sonnet-4-5-20250929 |
| `--method METHOD` | Localization method: history_llm (default), oracle |
| `--granularity LEVEL` | Context granularity: line, structure, function, file, dynamic |
| `--debug` | Enable debug logging |

### Programmatic Usage

```python
from core import Pipeline, Project
from core.config import config

# Initialize pipeline
pipeline = Pipeline()

# Run on a single project
result = pipeline.run_single(
    project_path=Path("../dataset/redos/axios_0.21.0"),
    model="deepseek-api",
    stages=["localize", "generate", "infer", "test"],
)

# Run on all projects
results = pipeline.run_all(model="deepseek-api")
```

## Output Structure

After running the pipeline, each project will contain:

```
project/
├── localization/
│   └── {model}.csv           # Localization results per version
├── prompt/
│   └── {version}-*.json      # Generated prompts with context
├── result/
│   └── {model}-result.txt    # Test results (True/False per version)
└── cost/
    └── {model}.txt           # Token usage and cost tracking
```

## Supported Models

| Model | Provider | Description |
|-------|----------|-------------|
| `deepseek-api` | DeepSeek | DeepSeek-Chat (default) |
| `gpt4o` | OpenAI | GPT-4o |
| `gpt-5` | OpenAI | GPT-5 |
| `gemini` | Google | Gemini Pro |
| `gemini-3-flash-preview` | Google | Gemini 3 Flash |
| `qwen3-14b` | Alibaba | Qwen3-14B |
| `claude-sonnet-4-5-20250929` | Anthropic | Claude Sonnet 4.5 |



## Directory Structure

```
core/
├── run.py                   # CLI entry point
├── pipeline.py              # Pipeline orchestration
├── project.py               # Project abstraction
├── config.py                # Configuration management
├── runner.py                # Batch execution utilities
├── exceptions.py            # Custom exception classes
├── managers/                # Core functionality modules
│   ├── base.py              # Base manager class
│   ├── meta.py              # Repository metadata management
│   ├── localizer.py         # Version tracing & fault localization
│   ├── baseline_localizer.py # Baseline localization methods
│   ├── prompt.py            # Context selection & prompt generation
│   ├── llm.py               # LLM inference handler
│   ├── test.py              # Patch validation via testing
│   ├── result.py            # Result analysis & metrics
│   └── untangler.py         # Patch simplification
├── utils/                   # Utility functions
│   ├── command.py           # Shell command execution
│   ├── file.py              # File I/O utilities
│   ├── git.py               # Git operations
│   ├── parsing.py           # Code parsing (tree-sitter)
│   └── similarity.py        # Code similarity metrics
└── data/
    └── target-project.txt   # List of projects to process
```
