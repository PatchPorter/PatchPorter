# PPatHF - JS Patch Porting

Zero-shot patch porting across JavaScript hard forks using LLMs.

## Setup

### 1. Set up Python environment

```bash
python -m venv .venv
source .venv/bin/activate

pip install torch transformers peft pydriller tree-sitter==0.21.3 unidiff pandas editdistance jellyfish fire tqdm openai setuptools wheel
```

To deactivate the environment when done, run:

```bash
deactivate
```

### 2. Download and build tree-sitter-javascript

Download `tree-sitter-javascript` v0.21.3 from GitHub, then build the shared library:

```bash
curl -L https://github.com/tree-sitter/tree-sitter-javascript/archive/refs/tags/v0.21.3.tar.gz -o tree-sitter-javascript-0.21.3.tar.gz
tar -xzf tree-sitter-javascript-0.21.3.tar.gz

cd tree-sitter-javascript-0.21.3
python build.py
```

The shared library is at `tree-sitter-javascript-0.21.3/build/tree-sitter-js-lib.so`.

### 3. Download StarCoder (for path A only)

Download [StarCoder](https://huggingface.co/bigcode/starcoder) to `model/starcoder/`.

### 4. Set DeepSeek API key (for path B only)

```bash
export DEEPSEEK_API_KEY=your_api_key_here
```

### 5. Prepare your baseline data

Create `dataset/baseline.json` with the following structure  or directly use the file we provide:

```json
{
    "sample_id": {
        "method_name": "...",
        "origin_before": "...",
        "origin_after": "...",
        "target_before": "...",
        "target_after": "..."    (ground truth, for reference)
    }
}
```

## Experiment Pipeline

### Step 1: Data Preparation

```bash
# Convert baseline.json to PPatHF format
python step_1_prepare_data.py
```

Produces `dataset/baseline_ppathf.json`.

### Step 2: Function Reduction

```bash
python step_2_reduce.py \
  --input dataset/baseline_ppathf.json \
  --output output/baseline_ppathf_reduced.json
```

Removes non-critical code blocks, replacing them with `/* placeholder_N */` markers. This reduces input length for the LLM.

Also automatically produces `dataset/sliced/baseline_ppathf_reduced.json` (sliced fields swapped into main fields for downstream inference).

### Step 3: LLM Inference

#### Path A: StarCoder (local)

```bash
# Zero-shot (no finetune)
python step_3_generate_starcoder.py \
  --base_model_name_or_path model/starcoder \
  --data_path dataset/sliced/baseline_ppathf_reduced.json \
  --output_path output/generations/starcoder.json \
  --model_max_length 8192 --max_length 8192 \
  --device cuda:0

#### Path B: DeepSeek API (online)

```bash
python step_3_generate_deepseek.py \
  --input dataset/sliced/baseline_ppathf_reduced.json \
  --output output/generations/deepseek.json
```

### Step 4: Post-Process

Extract the actual code patch from raw LLM output:

```bash
# StarCoder
python step_4_postprocess.py \
  --baseline dataset/baseline.json \
  --gen_data output/generations/starcoder.json \
  --output output/post/starcoder.json

# DeepSeek
python step_4_postprocess.py \
  --baseline dataset/baseline.json \
  --gen_data output/generations/deepseek.json \
  --output output/post/deepseek.json
```

### Step 5: Placeholder Recovery

Replace `/* placeholder_N */` markers with the original removed code:

```bash
# StarCoder
python step_5_recover.py \
  --generations output/generations/starcoder.json \
  --output output/recover/starcoder.json

# DeepSeek
python step_5_recover.py \
  --generations output/generations/deepseek.json \
  --output output/recover/deepseek.json
```

The recovered `target_after` field in the output now contains the full ported function.

## Output Files

| Step | Output File | Description |
|------|-------------|-------------|
| 1 | `dataset/baseline_ppathf.json` | Data in PPatHF format |
| 2 | `output/baseline_ppathf_reduced.json` | Reduced functions with placeholders |
| 2 | `dataset/sliced/baseline_ppathf_reduced.json` | Sliced version for inference |
| 3 | `output/generations/{starcoder,deepseek}.json` | LLM generations |
| 4 | `output/post/{starcoder,deepseek}.json` | Extracted patches |
| 5 | `output/recover/{starcoder,deepseek}.json` | Full recovered functions |

## File Overview

Original C reduction (from [PPatHF](https://github.com/xxx/PPatHF) baseline):
```
reduction/                     Original C reduction module
├── fcu.py                     C function utilities (tree-sitter)
├── reducer.py                 Core reduction logic
├── reducerConfig.py           Reduction settings
├── main.py                    Reduction entry point
└── run.sh                     Parallel reduction script
```

JS adaptations (our modifications):
```
├── step_1_prepare_data.py     Convert baseline.json -> PPatHF format
├── step_2_reduce.py           Thin wrapper: calls reduction_js/
├── step_3_generate_starcoder.py  StarCoder inference
├── step_3_generate_deepseek.py   DeepSeek API inference
├── step_4_postprocess.py      Extract patches from LLM output
├── step_5_recover.py          Replace /* placeholder */ markers
├── reduction_js/              JS reduction module (forked from reduction/)
│   ├── fcu.py                 JS function utilities (tree-sitter, 5 function types)
│   ├── reducer.py             Core reduction logic (JS AST node types)
│   ├── reducerConfig.py       Reduction settings (JS block types for_in, try, etc.)
│   ├── main.py                Reduction entry point
│   ├── run.sh                 Parallel reduction script
│   └── TestJavaScriptFunctions.py  Unit tests
├── config.py                  Shared configuration
└── README.md
```

Shared between C and JS:
```
├── porting/                   Prompt templates & finetuning
│   ├── data.py                Prompt templates / dataset classes
│   ├── train.py               LoRA finetuning script
│   └── run.sh                 Finetuning launcher
├── dataset/                   Input data (baseline.json, baseline_ppathf.json...)
│   └── sliced/                Sliced version for inference
├── output/                    Pipeline outputs
│   ├── generations/           Step 3: LLM generations
│   ├── post/                  Step 4: extracted patches
│   └── recover/               Step 5: recovered full functions
├── utils.py                   Token filtering utilities
├── metrics.py                 Metric computation
└── test.py                    Evaluation logic
```
