# Evaluation

This cleaned release includes compact evaluation summaries under `eval/results/`.

Run a summary report without external raw artifacts:

```bash
cd opensource
python eval/report_results.py
```

The historical inspection scripts in this directory can generate detailed HTML diffs, but they require the full raw result artifacts and info files used during the paper evaluation. Those large artifacts are intentionally not included in this source release.
