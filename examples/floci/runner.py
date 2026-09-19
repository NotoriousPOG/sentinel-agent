"""Put a synthetic GuardDuty finding through Floci S3 and Sentinel.

Floci stores objects. Sentinel's HTTP API is the investigation process.
Bedrock AgentCore is not used: Floci's control-plane API stores runtime
metadata and does not run the agent
(https://floci.io/floci/services/bedrock-agentcore/).

This runner does not isolate an instance, block an address, or call any
AWS mutate-defense API. ``isolate_instance`` raises if something calls it.
EventBridge is not used. S3 create and put are the only AWS calls.

``boto3`` is imported only when the CLI builds an S3 client. Unit tests
inject a store and do not import it. Sentinel still has to be started with
``SENTINEL_DEMO_MODE=true``. This module does not start that process and
does not change mock verdicts.
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from collections.abc import Mapping
from typing import Any, Protocol
from urllib.parse import quote

from examples.floci.synthetic_guardduty_finding import synthetic_guardduty_finding

DEFAULT_BUCKET = "sentinel-floci-demo"
DEFAULT_SENTINEL = "http://127.0.0.1:8091"
DEFAULT_FLOCI = "http://localhost:4566"
FINDING_KEY = "findings/synthetic-guardduty-finding.json"
APPROVAL_NOTES = (
    "Synthetic demo. Approving the conclusion records the decision only. "
    "This step does not isolate an instance, block an address, or call a mutate API."
)


class DemoRunError(RuntimeError):
    """The demo stopped. The message does not include the finding body."""


class DemoActionRefused(RuntimeError):
    """A forbidden response action was invoked."""


class JsonResponse:
    """One HTTP result. ``body`` is parsed JSON, or None when the body is empty."""

    def __init__(self, status_code: int, body: object) -> None:
        self.status_code = status_code
        self.body = body


class JsonClient(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Mapping[str, Any] | None = None,
    ) -> JsonResponse:
        """Send one JSON request. Must not follow a caller-supplied host list."""


class ObjectStore(Protocol):
    def create_bucket(self, *, Bucket: str) -> Mapping[str, Any]:
        """Create the demo bucket. Not a defense API."""

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        ContentType: str,
    ) -> Mapping[str, Any]:
        """Write one object."""


def isolate_instance(*_args: object, **_kwargs: object) -> None:
    """Stub. Approval must never call this. A call is a defect, not a switch."""
    raise DemoActionRefused("isolate_instance is not part of this demo and must not run")


def _error_code(exc: BaseException) -> str:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return ""
    error = response.get("Error")
    if not isinstance(error, dict):
        return ""
    code = error.get("Code")
    return code if isinstance(code, str) else ""


def ensure_bucket(store: ObjectStore, bucket: str) -> None:
    """Create the demo bucket. An existing bucket is not an error."""
    try:
        store.create_bucket(Bucket=bucket)
    except Exception as exc:
        if _error_code(exc) in {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}:
            return
        raise


def put_json(store: ObjectStore, bucket: str, key: str, document: Mapping[str, Any]) -> None:
    store.put_object(
        Bucket=bucket,
        Key=key,
        Body=json.dumps(document, indent=2, sort_keys=True).encode("utf-8"),
        ContentType="application/json",
    )


class UrllibJsonClient:
    """Stdlib client for the local Sentinel process. Timeouts are fixed."""

    def __init__(self, timeout: float = 60.0) -> None:
        self._timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Mapping[str, Any] | None = None,
    ) -> JsonResponse:
        data = None if json_body is None else json.dumps(json_body).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            status = exc.code
        if not raw:
            return JsonResponse(status, None)
        return JsonResponse(status, json.loads(raw))


def _base(url: str) -> str:
    return url.rstrip("/")


def _object(response: JsonResponse, what: str) -> dict[str, Any]:
    if not isinstance(response.body, dict):
        raise DemoRunError(f"{what} returned {response.status_code} without a JSON object")
    return response.body


def publish_finding(
    *,
    store: ObjectStore,
    bucket: str,
    sentinel_base: str,
    http: JsonClient,
    finding: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Store the finding in S3, post it to Sentinel, and store the investigation.

    The investigation body is the ``POST /investigations`` response, which
    includes the report when verification accepted one. This does not approve
    the conclusion.
    """
    document = dict(synthetic_guardduty_finding() if finding is None else finding)
    ensure_bucket(store, bucket)
    put_json(store, bucket, FINDING_KEY, document)
    base = _base(sentinel_base)
    created = http.request(
        "POST",
        f"{base}/alerts",
        json_body={"source": "aws_guardduty", "payload": document},
    )
    if created.status_code not in {200, 201}:
        raise DemoRunError(f"POST /alerts returned {created.status_code}")
    alert = _object(created, "POST /alerts").get("alert")
    if not isinstance(alert, dict) or not isinstance(alert.get("alert_id"), str):
        raise DemoRunError("POST /alerts did not return an alert_id")
    alert_id = alert["alert_id"]
    started = http.request(
        "POST",
        f"{base}/investigations",
        json_body={"alert_id": alert_id},
    )
    if started.status_code != 201:
        raise DemoRunError(f"POST /investigations returned {started.status_code}")
    investigation = _object(started, "POST /investigations")
    investigation_id = investigation.get("investigation_id")
    if not isinstance(investigation_id, str) or not investigation_id:
        raise DemoRunError("POST /investigations did not return an investigation_id")
    key = f"investigations/{quote(investigation_id, safe='')}.json"
    put_json(store, bucket, key, investigation)
    return {
        "alert_id": alert_id,
        "investigation_id": investigation_id,
        "finding_key": FINDING_KEY,
        "investigation_key": key,
        "status": investigation.get("status"),
    }


def _missing_report(response: JsonResponse) -> bool:
    if response.status_code != 404 or not isinstance(response.body, dict):
        return False
    return response.body.get("code") == "report_not_found"


def record_analyst_approval(
    *,
    store: ObjectStore,
    bucket: str,
    sentinel_base: str,
    investigation_id: str,
    http: JsonClient,
    notes: str = APPROVAL_NOTES,
) -> dict[str, Any]:
    """Record an analyst decision in S3.

    When ``GET /investigations/{id}/report`` returns the verified report,
    this posts ``POST /investigations/{id}/review``. That route stores the
    decision. This function does not call a response action. A missing
    report is recorded and the review route is not called.
    """
    if not investigation_id:
        raise DemoRunError("investigation_id is empty")
    base = _base(sentinel_base)
    encoded = quote(investigation_id, safe="")
    report = http.request("GET", f"{base}/investigations/{encoded}/report")
    review_body: dict[str, Any] | None = None
    review_status: int | None = None
    if report.status_code == 200:
        if not isinstance(report.body, dict):
            raise DemoRunError("GET /report returned 200 without a JSON object")
        review_body = {
            "investigation_id": investigation_id,
            "conclusion": "approve",
            "notes": notes,
        }
        reviewed = http.request(
            "POST",
            f"{base}/investigations/{encoded}/review",
            json_body=review_body,
        )
        if reviewed.status_code != 200:
            raise DemoRunError(f"POST /review returned {reviewed.status_code}")
        review_status = reviewed.status_code
        stored_review = reviewed.body
    elif _missing_report(report):
        stored_review = None
    else:
        raise DemoRunError(f"GET /report returned {report.status_code}")

    document: dict[str, Any] = {
        "synthetic": True,
        "kind": "analyst_approval",
        "investigation_id": investigation_id,
        "verified_report_present": report.status_code == 200,
        "review_route_called": review_body is not None,
        "report_status": report.status_code,
        "review_request": review_body,
        "review_status": review_status,
        "review_response": stored_review,
        "not_called": ["isolate_instance"],
    }
    ensure_bucket(store, bucket)
    key = f"reviews/{quote(investigation_id, safe='')}.json"
    put_json(store, bucket, key, document)
    return document


def floci_s3_client(endpoint: str) -> Any:
    """S3 client aimed at Floci. Credentials default to the documented test pair.

    Only the S3 client is constructed. No other AWS service client is created.
    """
    import boto3

    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        region_name=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID", "test"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY", "test"),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Local Floci demo. Stores a synthetic finding and an analyst decision. "
            "Does not remediate. Does not use Bedrock AgentCore."
        )
    )
    parser.add_argument("--endpoint", default=os.environ.get("AWS_ENDPOINT_URL", DEFAULT_FLOCI))
    parser.add_argument("--sentinel", default=os.environ.get("SENTINEL_BASE_URL", DEFAULT_SENTINEL))
    parser.add_argument("--bucket", default=DEFAULT_BUCKET)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("ingest", help="Put the finding in S3 and post it to Sentinel.")
    approve = sub.add_parser("approve", help="Record an analyst decision. Does not isolate.")
    approve.add_argument("--investigation-id", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store = floci_s3_client(args.endpoint)
    http = UrllibJsonClient()
    if args.command == "ingest":
        result = publish_finding(
            store=store,
            bucket=args.bucket,
            sentinel_base=args.sentinel,
            http=http,
        )
    else:
        result = record_analyst_approval(
            store=store,
            bucket=args.bucket,
            sentinel_base=args.sentinel,
            investigation_id=args.investigation_id,
            http=http,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
