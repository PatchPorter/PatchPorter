# Examples

Run a structural smoke test without installing external services:

```bash
cd opensource
python scripts/smoke_test.py
```

Run the full pipeline on one CVE after installing dependencies and configuring Joern plus an LLM backend:

```bash
cd opensource/src
python patchbp.py ../data/cve-c-patch.json --cveid CVE-2013-2020 --language c
```
