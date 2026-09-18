"""In-process scripted model.

Tool choice reads indicator fields and a fixed keyword table on title,
description, process, and command line. It does not read ``raw_event``,
``metadata``, dataset labels, or text inside the untrusted-data markers.
Report narrative is a constant. This is not ``OpenAiCompatibleClient``.
"""

from collections.abc import Sequence
from typing import TypeVar, cast

from pydantic import BaseModel

from sentinel.agents.decision import ModelTurn, TurnAction
from sentinel.agents.reporting import ReportNarrative
from sentinel.errors import ModelOutputInvalid
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.schemas.tools import HashAlgorithm
from sentinel.services.llm import LlmMessage, LlmRole

ModelT = TypeVar("ModelT", bound=BaseModel)

# First match wins. The query is a string the local ATT&CK subset can find.
# It is not a classification and it is not a detector.
_MITRE_QUERIES: tuple[tuple[str, str], ...] = (
    ("exploit public-facing", "Exploit Public-Facing Application"),
    ("ingress tool transfer", "Ingress Tool Transfer"),
    ("password guessing", "Password Guessing"),
    ("valid accounts", "Valid Accounts"),
    ("powershell", "PowerShell"),
    ("windows command shell", "Windows Command Shell"),
    ("brute force", "Brute Force"),
)

_NARRATIVE = ReportNarrative(
    executive_summary="Collected results are attached. Classification uses stored fields only.",
    analyst_notes="",
)


def plan_tools(alert: NormalizedAlert) -> list[tuple[str, dict[str, object]]]:
    """Tool name and arguments, in call order. Does not read dataset labels."""
    steps: list[tuple[str, dict[str, object]]] = []
    if alert.source_ip is not None:
        steps.append(("lookup_ip", {"ip": str(alert.source_ip)}))
    if alert.destination_ip is not None and alert.destination_ip != alert.source_ip:
        steps.append(("lookup_ip", {"ip": str(alert.destination_ip)}))
    if alert.file_hash is not None:
        steps.append(
            (
                "lookup_hash",
                {
                    "file_hash": alert.file_hash,
                    "algorithm": _hash_algorithm(alert.file_hash),
                },
            )
        )
    if alert.cve is not None:
        steps.append(("lookup_cve", {"cve_id": alert.cve}))
    if alert.domain is not None:
        steps.append(("lookup_domain", {"domain": alert.domain}))
    query = mitre_query(alert)
    if query is not None:
        steps.append(("search_mitre", {"query": query}))
    return steps


def plan_tool_names(alert: NormalizedAlert) -> list[str]:
    return [name for name, _arguments in plan_tools(alert)]


def mitre_query(alert: NormalizedAlert) -> str | None:
    """Keyword on structured text fields. Logs and metadata are not scanned."""
    haystack = _scanned_text(alert)
    if not haystack:
        return None
    for needle, query in _MITRE_QUERIES:
        if needle in haystack:
            return query
    return None


class ScriptedEvalModel:
    """One alert, one plan. Later calls finish, then return the fixed narrative."""

    def __init__(self, alert: NormalizedAlert) -> None:
        self._steps = plan_tools(alert)
        self._index = 0
        self.selected_tools: list[str] = []
        self.system_messages: list[str] = []

    def complete_structured(
        self,
        messages: Sequence[LlmMessage],
        response_model: type[ModelT],
    ) -> ModelT:
        self._record_system(messages)
        if response_model is ReportNarrative:
            return cast(ModelT, _NARRATIVE)
        if self._index >= len(self._steps):
            turn = ModelTurn(action=TurnAction.FINISH, tool=None, arguments={})
        else:
            name, arguments = self._steps[self._index]
            self._index += 1
            self.selected_tools.append(name)
            turn = ModelTurn(action=TurnAction.CALL_TOOL, tool=name, arguments=arguments)
        try:
            parsed = response_model.model_validate(turn.model_dump())
        except ValueError as exc:
            raise ModelOutputInvalid(raw_text=turn.model_dump_json(), detail=str(exc)) from exc
        return parsed

    def _record_system(self, messages: Sequence[LlmMessage]) -> None:
        for message in messages:
            if message.role is LlmRole.SYSTEM:
                self.system_messages.append(message.content)


def _scanned_text(alert: NormalizedAlert) -> str:
    parts = (alert.title, alert.description, alert.process, alert.command_line)
    return "\n".join(part for part in parts if part).casefold()


def _hash_algorithm(digest: str) -> str:
    length = len(digest)
    if length == 32:
        return HashAlgorithm.MD5.value
    if length == 40:
        return HashAlgorithm.SHA1.value
    if length == 64:
        return HashAlgorithm.SHA256.value
    raise ValueError("hash length is not md5, sha1, or sha256")
