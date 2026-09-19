# Local Floci demo

A reviewer can walk a synthetic GuardDuty finding through [Floci](https://floci.io/aws/) and Sentinel without an AWS account. Floci is the object store. Sentinel's HTTP API is the investigation process.

This is not a GuardDuty integration. `GuardDutyAdapter` maps one documented finding object and fails closed when a required field is missing. It does not call GuardDuty, does not accept an EventBridge envelope, and does not map action shapes other than `portProbeAction`. CrowdStrike, Defender, Elastic, and Splunk still raise.

Bedrock AgentCore is not used. Floci's control-plane API stores runtime metadata and does not run the agent: https://floci.io/floci/services/bedrock-agentcore/

The scripted demo model and the existing mocks are unchanged. This demo does not force a `MALICIOUS` verdict. With `SENTINEL_DEMO_MODE=true`, a source IP is looked up through `mock:abuseipdb`, which leaves `reported_malicious` null. That null is not turned into `MALICIOUS`.

## What was verified, and what was not

Docker is not installed here (`docker` is not on `PATH`). Floci was not started. The runner was not executed, so no object was written to port 4566.

The image name below is the one published on 2026-09-19 at:

- https://floci.io/aws/ (`docker run` uses `floci/floci:latest`)
- https://github.com/floci-io/floci (`docker run` uses the same image; that README also adds `-u root` when the Docker socket is mounted)
- https://hub.docker.com/r/floci/floci (`docker pull floci/floci`, Compose example `floci/floci:latest`)

No numeric tag was published as the quickstart. This file does not invent one. `latest` is the tag those pages name.

On 2026-09-19 the finding was posted through FastAPI's `TestClient` with `SENTINEL_DEMO_MODE=true` and a temporary SQLite file. That process is not Floci, and it is not `examples/floci/runner.py`.

- `POST /alerts` with `source` `aws_guardduty` returned 201. `source_ip` was `203.0.113.50`.
- `POST /investigations` returned 201. Status `AWAITING_REVIEW`. The stored report's classification was `INCONCLUSIVE`. The scripted planner called `lookup_ip` twice. The only evidence source was `mock:abuseipdb`.
- `GET /investigations/{id}/report` returned 200.
- `POST /investigations/{id}/review` with `conclusion` `approve` and no remediation field returned 200 and status `COMPLETE`.

Pytest covers the mapper and the rule that approval does not call `isolate_instance`. Those tests do not open a socket.

EventBridge is listed on the Floci site. This demo does not call it. That API was not exercised here, so the runner uses S3 only.

## Floci

From the quickstart on https://floci.io/aws/. Not executed in this environment:

```bash
docker run -d --name floci \
  -p 4566:4566 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  floci/floci:latest
```

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID=test
export AWS_SECRET_ACCESS_KEY=test
export AWS_DEFAULT_REGION=us-east-1
```

The same page's upload example, also not executed here:

```bash
aws s3 mb s3://my-bucket
aws s3 cp hello-floci.txt s3://my-bucket/hello-floci.txt
```

The runner does not shell out to `aws`. When you start it, it constructs a boto3 S3 client the way the Floci README's boto3 snippet does: `endpoint_url`, region, and the test key pair. It calls `create_bucket` and `put_object` only. `boto3` is not a Sentinel dependency. Install it in the same environment before the runner commands:

```bash
pip install boto3
```

That install was not pinned here, and it was not run against Floci.

## Sentinel

From the repository root, after `pip install -e ".[dev]"` and `alembic upgrade head`. Leave LLM, AbuseIPDB, and VirusTotal variables unset.

```bash
SENTINEL_DEMO_MODE=true uvicorn sentinel.api.app:app --host 127.0.0.1 --port 8091
```

That process uses `ScriptedDemoModel`. It does not call `OpenAiCompatibleClient`. Floci is not in that process.

## Runner

Two steps. The first writes the synthetic finding to `s3://sentinel-floci-demo/findings/synthetic-guardduty-finding.json`, posts `{"source":"aws_guardduty","payload":...}` to `POST /alerts`, posts `POST /investigations`, and writes that response, including the report when one was stored, to `s3://sentinel-floci-demo/investigations/<id>.json`.

```bash
python -m examples.floci.runner ingest \
  --endpoint http://localhost:4566 \
  --sentinel http://127.0.0.1:8091
```

The second step calls `GET /investigations/<id>/report`. If that route returns the verified report, it calls `POST /investigations/<id>/review` with `conclusion: approve` and required notes. It does not send `remediation`. It then writes the decision to `s3://sentinel-floci-demo/reviews/<id>.json`. If the report route returns `404` `report_not_found`, the review route is not called and the S3 object says so.

```bash
python -m examples.floci.runner approve \
  --investigation-id <id-from-ingest> \
  --endpoint http://localhost:4566 \
  --sentinel http://127.0.0.1:8091
```

`isolate_instance` in `runner.py` raises `DemoActionRefused` if called. The approval function does not call it. Nothing in this demo isolates an instance, blocks an address, or calls an AWS mutate-defense API. There is no flag that turns the stub into an action.

These two commands were not run against a live Floci or a live API in this environment.

## Fixture

`synthetic_guardduty_finding.py` is the finding. It is labeled synthetic in the title and description. The citation is `FINDING_DOC_URL`:

https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Finding.html

Addresses `203.0.113.50` and `192.0.2.10` are RFC 5737 documentation ranges. Severity `2` is in GuardDuty's documented low band. The finding type `Recon:EC2/PortProbeUnprotectedPort` is named on https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html

The mapper copies the whole object onto `raw_event`. It promotes the port-probe remote IPv4 to `source_ip` and the matching local IPv4 to `destination_ip`. `instanceId` is not a hostname. `publicIp` is not the source address. An `awsApiCallAction` remote address stays on `raw_event`.
