# Examples

Synthetic alerts for a local run. No API keys. `SENTINEL_DEMO_MODE` must be on (Compose defaults it to true). The API then uses the in-process scripted demo model (`ScriptedDemoModel`) and the `mock:` IP, hash, CVE, and DNS providers. It does not call `OpenAiCompatibleClient`.

MITRE search reads the checked-in Enterprise subset.

## Alerts

`synthetic-alert.json` is a generic JSON `POST /alerts` body. The address `203.0.113.44` is from the documentation range in RFC 5737. The file hash is a placeholder, not a published sample. Both are listed in `src/sentinel/services/providers/fixtures.py`. The title contains the words "password guessing" so the scripted planner's keyword table selects one local MITRE query. That is a string match, not a verdict.

`wazuh-synthetic-alert.json` is the same kind of demo in the documented Wazuh alert shape. The source IP is `192.0.2.50` (TEST-NET-1), not Wazuh's `18.18.18.18` logtest example. MITRE ids on the Wazuh rule stay on `raw_event`; the planner still uses the title keyword table.

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

The local Floci walkthrough is [floci/README.md](floci/README.md). It is a separate demo. It does not replace the commands above, and Floci does not execute the model.

## Captured run

`investigation-response.json` is the body of `POST /investigations` from a Compose run on 2026-09-22T08:53:34Z against `http://127.0.0.1:8091`. `SENTINEL_DEMO_MODE` was true (Compose default). No LLM, AbuseIPDB, or VirusTotal key was set. The file is that JSON body, indented. Values were not edited.

The HTTP status was 201. The investigation status is `AWAITING_REVIEW`. Classification is `SUSPICIOUS`. Fixture IP and hash rows are labeled `mock:` and `low` reliability, so the pipeline does not call the alert `MALICIOUS`. The scripted narrative does not name indicators. `search_mitre` was called with the query `Password Guessing` and the local subset returned `T1110.001`. That citation is the catalog hit, not a claim that a host was attacked.

`demo-transcript.txt` is the terminal record of the same Compose run, including the Wazuh example and an approved review.
