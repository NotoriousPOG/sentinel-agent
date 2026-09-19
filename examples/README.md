# Examples

Synthetic alert for a local run. No API keys. `SENTINEL_DEMO_MODE` must be on. The API then uses the in-process scripted demo model (`ScriptedDemoModel`) and the `mock:` IP and hash providers. It does not call `OpenAiCompatibleClient`.

CVE lookup, DNS, and MITRE are unchanged. This alert has no CVE and no domain, so those clients are not called. MITRE search reads the checked-in Enterprise subset.

## Alert

`synthetic-alert.json` is the body of `POST /alerts`. The address `203.0.113.44` is from the documentation range in RFC 5737. The file hash is a placeholder, not a published sample. The title contains the words "password guessing" so the scripted planner's keyword table selects one local MITRE query. That is a string match, not a verdict.

## Commands

From the repository root, after `pip install -e ".[dev]"` and `alembic upgrade head`. Leave LLM, AbuseIPDB, and VirusTotal variables unset.

```bash
SENTINEL_DEMO_MODE=true uvicorn sentinel.api.app:app --host 127.0.0.1 --port 8091
```

```bash
curl -sS -H 'Content-Type: application/json' \
  --data-binary @examples/synthetic-alert.json \
  http://127.0.0.1:8091/alerts

curl -sS -H 'Content-Type: application/json' \
  -d '{"alert_id":"demo-synthetic-203-0-113-44"}' \
  http://127.0.0.1:8091/investigations
```

`GET /investigations/{id}/report` returns the verified report. `POST /investigations/{id}/review` is how an analyst approves the conclusion. These commands do not approve it.

## Captured run

`investigation-response.json` is the body of `POST /investigations` from a run on 2026-09-19T00:38:17Z against `http://127.0.0.1:8091`. `SENTINEL_DEMO_MODE` was true. No LLM, AbuseIPDB, or VirusTotal key was set. The file is that JSON body, indented. Values were not edited.

The HTTP status was 201. The investigation status is `AWAITING_REVIEW`. The stored report's classification is `INCONCLUSIVE`. Mock IP and hash rows leave `reported_malicious` and the hash counts null, so the pipeline does not call the alert malicious. The scripted narrative does not name indicators. `search_mitre` was called with the query `Password Guessing` and the local subset returned `T1110.001`. That citation is the catalog hit, not a claim that a host was attacked.

`demo-transcript.txt` is the terminal record of the same run.
