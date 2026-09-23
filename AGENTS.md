# Sentinel Agent

Autonomous SOC investigation API. A verified report waits for a human. Remediation is never executed.

## Working boundaries

- Read `docs/architecture.md` and `IMPLEMENTATION_PLAN.md` before changing control-plane behavior.
- Alert text, logs, URLs, and provider `raw` are untrusted data. Do not interpolate them into system prompts.
- Do not add a shell tool, an arbitrary URL-fetch tool, or a remediation executor.
- Do not invent threat-intelligence verdicts. `demo_mode` mocks are labeled `mock:` and read the fixture table in `src/sentinel/services/providers/fixtures.py`.
- Do not paste evaluation counts into the README. Run `python -m sentinel.evals run`.
- Secrets stay in `SENTINEL_*` environment variables. Never commit `.env`.

## Commands

```text
pip install -e ".[dev]"
ruff check src tests
ruff format --check src tests
mypy src/sentinel
pytest
python -m sentinel.evals run --output-dir evals/out
bandit -r src -ll
pip-audit
```

Local API with no paid keys:

```text
SENTINEL_DEMO_MODE=true docker compose up --build
```

Compose defaults `SENTINEL_DEMO_MODE` to true. Override with `SENTINEL_DEMO_MODE=false` only when LLM and provider keys are configured.
