"""Approval records a decision and does not call the isolate stub. No network."""

import inspect
import json
from collections.abc import Mapping
from typing import Any

import pytest
from examples.floci import runner
from examples.floci.runner import (
    DemoActionRefused,
    JsonResponse,
    isolate_instance,
    publish_finding,
    record_analyst_approval,
)
from examples.floci.synthetic_guardduty_finding import synthetic_guardduty_finding


class RecordingStore:
    """S3 stand-in. Any method other than create and put fails the test."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.objects: dict[str, dict[str, Any]] = {}

    def create_bucket(self, *, Bucket: str) -> Mapping[str, Any]:
        self.calls.append("create_bucket")
        return {"Bucket": Bucket}

    def put_object(
        self,
        *,
        Bucket: str,
        Key: str,
        Body: bytes,
        ContentType: str,
    ) -> Mapping[str, Any]:
        self.calls.append("put_object")
        self.objects[Key] = json.loads(Body)
        assert ContentType == "application/json"
        assert Bucket == "sentinel-floci-demo"
        return {}

    def __getattr__(self, name: str) -> Any:
        def forbidden(*_args: object, **_kwargs: object) -> None:
            raise AssertionError(f"unexpected store call {name}")

        return forbidden


class ScriptedHttp:
    def __init__(self, report_status: int, report_body: object) -> None:
        self.report_status = report_status
        self.report_body = report_body
        self.calls: list[tuple[str, str, object]] = []

    def request(
        self,
        method: str,
        url: str,
        *,
        json_body: Mapping[str, Any] | None = None,
    ) -> JsonResponse:
        self.calls.append((method, url, json_body))
        if url.endswith("/report"):
            return JsonResponse(self.report_status, self.report_body)
        if url.endswith("/review"):
            return JsonResponse(200, {"status": "COMPLETE", "review": json_body})
        if url.endswith("/alerts"):
            return JsonResponse(
                201,
                {"alert": {"alert_id": "synthetic-guardduty-portprobe-203-0-113-50"}},
            )
        if url.endswith("/investigations"):
            return JsonResponse(
                201,
                {
                    "investigation_id": "inv-demo",
                    "status": "AWAITING_REVIEW",
                    "report": {"classification": "INCONCLUSIVE"},
                },
            )
        raise AssertionError(url)


def test_isolate_instance_raises_if_called() -> None:
    with pytest.raises(DemoActionRefused, match="must not run"):
        isolate_instance("i-synthetic00000000001")


def test_approval_does_not_call_isolate_stub(monkeypatch: pytest.MonkeyPatch) -> None:
    called: list[str] = []

    def spy(*args: object, **kwargs: object) -> None:
        called.append("isolate_instance")
        isolate_instance(*args, **kwargs)

    monkeypatch.setattr(runner, "isolate_instance", spy)
    http = ScriptedHttp(200, {"classification": "INCONCLUSIVE"})
    store = RecordingStore()
    document = record_analyst_approval(
        store=store,
        bucket="sentinel-floci-demo",
        sentinel_base="http://127.0.0.1:8091",
        investigation_id="inv-demo",
        http=http,
    )
    assert called == []
    assert store.calls == ["create_bucket", "put_object"]
    assert document["review_route_called"] is True
    assert document["verified_report_present"] is True
    methods = [call[0] for call in http.calls]
    assert methods == ["GET", "POST"]
    review = http.calls[1][2]
    assert isinstance(review, dict)
    assert review["conclusion"] == "approve"
    assert "remediation" not in review
    assert "execute" not in review
    stored = store.objects["reviews/inv-demo.json"]
    assert stored["not_called"] == ["isolate_instance"]
    assert stored["review_request"]["conclusion"] == "approve"
    assert "isolate_instance(" not in inspect.getsource(record_analyst_approval)


def test_missing_report_skips_review_and_does_not_isolate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[str] = []
    monkeypatch.setattr(
        runner,
        "isolate_instance",
        lambda *_args, **_kwargs: called.append("isolate_instance"),
    )
    http = ScriptedHttp(404, {"error": "report_not_found", "code": "report_not_found"})
    store = RecordingStore()
    document = record_analyst_approval(
        store=store,
        bucket="sentinel-floci-demo",
        sentinel_base="http://127.0.0.1:8091",
        investigation_id="inv-demo",
        http=http,
    )
    assert called == []
    assert [call[0] for call in http.calls] == ["GET"]
    assert document["review_route_called"] is False
    assert document["verified_report_present"] is False
    assert store.objects["reviews/inv-demo.json"]["review_request"] is None


def test_publish_finding_stores_the_investigation_response() -> None:
    http = ScriptedHttp(200, {})
    store = RecordingStore()
    result = publish_finding(
        store=store,
        bucket="sentinel-floci-demo",
        sentinel_base="http://127.0.0.1:8091",
        http=http,
        finding=synthetic_guardduty_finding(),
    )
    assert result["investigation_id"] == "inv-demo"
    assert store.calls == ["create_bucket", "put_object", "put_object"]
    stored = store.objects["investigations/inv-demo.json"]
    assert stored["report"]["classification"] == "INCONCLUSIVE"
    assert stored["status"] == "AWAITING_REVIEW"
    posted = http.calls[0][2]
    assert isinstance(posted, dict)
    assert posted["source"] == "aws_guardduty"
    assert "isolate_instance(" not in inspect.getsource(publish_finding)


def test_runner_constructs_only_an_s3_client() -> None:
    text = inspect.getsource(runner.floci_s3_client)
    assert text.count("boto3.client(") == 1
    assert '"s3"' in text
    assert "ec2" not in text.lower()
    assert "waf" not in text.lower()
    assert "guardduty" not in text.lower()
