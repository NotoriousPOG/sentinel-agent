"""Scripted demo model for ``POST /investigations``.

Used only when ``demo_mode`` is on. Planning rules are ``plan_tools`` in
``sentinel.evals.model``. This class does not read dataset labels, does not
construct ``OpenAiCompatibleClient``, and does not call a hosted model.
"""

from sentinel.config.settings import Settings
from sentinel.evals.model import ScriptedEvalModel
from sentinel.schemas.alerts import NormalizedAlert
from sentinel.services.llm import LlmProvider
from sentinel.services.llm_http import build_llm_client


class ScriptedDemoModel(ScriptedEvalModel):
    """In-process planner. Same rules as the offline eval model. Not a live LLM."""


def build_investigation_model(settings: Settings, alert: NormalizedAlert) -> LlmProvider:
    """Choose the model for one investigation.

    ``demo_mode`` returns ``ScriptedDemoModel`` and ignores LLM settings.
    Otherwise a missing base URL, key, or model is ``ConfigurationError``
    from ``build_llm_client``. The caller must not store a state in that case.
    """
    if settings.demo_mode:
        return ScriptedDemoModel(alert)
    return build_llm_client(settings)
