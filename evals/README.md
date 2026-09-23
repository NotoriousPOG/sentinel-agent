# Evaluations

This directory holds a synthetic dataset. The cases are not live alerts, not customer incidents, and not live threat intelligence. Expected labels are in `dataset.json`. The runner does not assign them.

`demo_mode` mocks used by the runner are already labeled `mock:`. Those rows are not live intelligence. Listed fixture indicators may carry canned verdicts; unknown IPs stay null. The conflicting-intelligence case is two `synthetic:` evidence rows, not a second vendor. The CVE case uses a public identifier and a `mock:osv` row. It does not download OSV.

```bash
python -m sentinel.evals run --output-dir evals/out
```

The command writes `report.json` and `report.md` in the directory the flag selects, and it prints the counts. This file does not copy those counts. What each count means, and what it is not, is in `docs/evaluations.md`.
