"""Local Enterprise ATT&CK search.

Source, version, and retrieval date: ``src/sentinel/data/attack/README.md``.
The bundle is the Enterprise ATT&CK v19.2 STIX collection
(https://github.com/mitre-attack/attack-stix-data/releases/tag/v19.2),
retrieved 2026-09-18. This module does not download it.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any

from sentinel.errors import ProviderError
from sentinel.schemas.patterns import normalize_technique_id
from sentinel.schemas.tools import MitreTechniqueResult, SearchMitreInput, SearchMitreOutput
from sentinel.services.clock import Clock

ATTACK_VERSION = "19.2"
SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack-19.2.json"
)
_BUNDLE = "data/attack/enterprise-techniques.json"


@dataclass(frozen=True, slots=True)
class _Technique:
    result: MitreTechniqueResult


class MitreAttackCatalog:
    name = "mitre-attack"

    def __init__(self, *, clock: Clock) -> None:
        self._clock = clock
        self._techniques = _load()

    def search_mitre(self, query: SearchMitreInput) -> SearchMitreOutput:
        needle = query.query.casefold()
        matches: list[MitreTechniqueResult] = []
        for technique in self._techniques:
            item = technique.result
            if query.technique_id is not None and item.technique_id != query.technique_id:
                continue
            haystack = " ".join(
                (item.technique_id, item.name, item.tactic, item.description)
            ).casefold()
            if needle not in haystack:
                continue
            matches.append(item)
            if len(matches) >= 50:
                break
        return SearchMitreOutput(
            query=query.query,
            provider=self.name,
            techniques=matches,
            retrieved_at=self._clock.now(),
        )


@lru_cache(maxsize=1)
def _load() -> tuple[_Technique, ...]:
    items = _payload().get("techniques")
    if not isinstance(items, list) or not items:
        raise ProviderError("mitre-attack", "invalid_catalog")
    return tuple(_Technique(result=_record(item)) for item in items)


def official_technique(technique_id: str) -> MitreTechniqueResult | None:
    """Return the subset record for ``technique_id``, or None when it is absent.

    This reads the checked-in bundle. It does not download ATT&CK.
    """
    try:
        normalized = normalize_technique_id(technique_id)
    except ValueError:
        return None
    for technique in _load():
        if technique.result.technique_id == normalized:
            return technique.result
    return None


def technique_ids_in_result(result: Mapping[str, Any]) -> frozenset[str]:
    """Technique ids on a ``search_mitre`` result. ``raw`` is not read."""
    techniques = result.get("techniques")
    if not isinstance(techniques, list):
        return frozenset()
    found: set[str] = set()
    for item in techniques:
        if not isinstance(item, dict):
            continue
        value = item.get("technique_id")
        if not isinstance(value, str):
            continue
        try:
            found.add(normalize_technique_id(value))
        except ValueError:
            continue
    return frozenset(found)


def _record(item: object) -> MitreTechniqueResult:
    if not isinstance(item, dict):
        raise ProviderError("mitre-attack", "invalid_catalog")
    tactics = item.get("tactics")
    if not isinstance(tactics, list) or not tactics:
        raise ProviderError("mitre-attack", "invalid_catalog")
    names = [name for name in tactics if isinstance(name, str) and name.strip()]
    if len(names) != len(tactics):
        raise ProviderError("mitre-attack", "invalid_catalog")
    technique_id = item.get("technique_id")
    name = item.get("name")
    description = item.get("description")
    if not isinstance(technique_id, str) or not isinstance(name, str):
        raise ProviderError("mitre-attack", "invalid_catalog")
    if not isinstance(description, str):
        raise ProviderError("mitre-attack", "invalid_catalog")
    return MitreTechniqueResult(
        technique_id=technique_id,
        name=name,
        tactic=", ".join(names),
        description=description,
    )


def bundle_document() -> dict[str, Any]:
    """Parsed subset metadata. Tests use this; it does not touch the network."""
    return _payload()


def _payload() -> dict[str, Any]:
    payload = json.loads(_bundle_text())
    if not isinstance(payload, dict):
        raise ProviderError("mitre-attack", "invalid_catalog")
    if payload.get("attack_version") != ATTACK_VERSION or payload.get("source_url") != SOURCE_URL:
        raise ProviderError("mitre-attack", "invalid_catalog")
    return payload


def _bundle_text() -> str:
    resource = files("sentinel").joinpath(_BUNDLE)
    if resource.is_file():
        return resource.read_text(encoding="utf-8")
    path = Path(__file__).resolve().parents[2] / _BUNDLE
    return path.read_text(encoding="utf-8")
