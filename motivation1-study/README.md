# Preliminary Study: Code Similarity Analysis

This directory contains the data and visualization code for the preliminary study in our paper **"PatchPorter: LLM-Driven Security Patch Porting via Version Tracing and Context Selection for NPM"**.

The study analyzes code similarity patterns between vulnerable and patched code across different programming language ecosystems, motivating our approach to NPM-specific patch backporting.

## Overview

We compare code similarity metrics between:
- **NPM ecosystem** (JavaScript packages)
- **C ecosystem** (C libraries and kernel code)

The analysis reveals that NPM packages exhibit higher code similarity between vulnerable and patched versions compared to C programs, suggesting that LLM-based patch backporting is particularly well-suited for the NPM ecosystem.



## Similarity Metrics

The analysis computes the following similarity metrics at function level:

1. **Token Jaccard Similarity** - Set-based token overlap measure
2. **Line Jaccard Similarity** - Line-level structural similarity
3. **BLEU Score** - Machine translation metric adapted for code
4. **Embedding Similarity** - Semantic similarity via code embeddings
5. **Top-1 Statement-Level EDS** - Edit distance similarity at statement granularity
6. **Top-1 Context-Level EDS** - Edit distance with surrounding context

## Usage

### Generate CDF Comparison Charts

```bash
python plot_js_vs_c_cdf.py
```

This generates a 2x3 grid of CDF plots comparing JavaScript and C similarity distributions, saved to `similarity_figures/cdf_function_level_js_vs_c.pdf`.

### Requirements

- Python 3.8+
- numpy
- matplotlib
- scipy

## Data Format

### Similarity Results (JSON)

Each item contains:
```json
{
    "item_id": "CVE-XXXX-XXXXX",
    "jaccard": 0.72,
    "line_diff": 0.68,
    "bleu": 0.45,
    "best_match_statement": 0.78,
    "best_match_line_context": 0.81
}
```

### Embedding Results (JSON)

Dictionary mapping item_id to embedding similarity:
```json
{
    "CVE-XXXX-XXXXX@0": {
        "embedding_similarity": 0.75,
    }
}
```

## Key Findings

The CDF plots reveal significant differences in code evolution patterns:
- **NPM packages** show higher similarity between vulnerable and patched versions
- **C ecosystem** exhibits more substantial changes during vulnerability fixes
- The difference is statistically significant (Mann-Whitney test p < 0.001)

These findings motivate the need for ecosystem-specific patch backporting approaches.


## Directory Structure

```
motivation1-study/
├── README.md                     # This file
├── plot_js_vs_c_cdf.py           # Main visualization script
├── NPM-CVE.csv                   # NPM vulnerability dataset
├── C-CVE.json                    # C vulnerability dataset
├── similarity_results/           # Pre-computed similarity metrics
│   ├── js-function_similarity.json
│   ├── c-function_similarity.json
│   ├── js-commit_function.json
│   └── function_embedding_results/
│       ├── js-function-embedding.json
│       ├── c-function-embedding.json
│       └── js-commit-function-embedding.json
└── similarity_figures/           # Generated figures
    └── cdf_function_level_js_vs_c.pdf
```
