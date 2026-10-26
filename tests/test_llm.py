import pytest

from patchprio.llm import (
    ApplicabilityAssessor,
    ExploitationSignalExtractor,
    LLMMessage,
    LLMNotConfiguredError,
    LLMProvider,
    PriorityExplainer,
    get_provider,
)
from patchprio.llm.fallback import (
    EmptySignalExtractor,
    NeutralApplicabilityAssessor,
    TemplateExplainer,
)


def test_null_provider_raises():
    provider = get_provider("none")
    assert isinstance(provider, LLMProvider)
    with pytest.raises(LLMNotConfiguredError):
        provider.complete([LLMMessage("user", "test")])


def test_planned_provider_not_implemented():
    with pytest.raises(NotImplementedError):
        get_provider("openai-compatible")


def test_unknown_provider():
    with pytest.raises(ValueError):
        get_provider("unknown")


def test_fallbacks_satisfy_interfaces():
    assert isinstance(NeutralApplicabilityAssessor(), ApplicabilityAssessor)
    assert isinstance(EmptySignalExtractor(), ExploitationSignalExtractor)
    assert isinstance(TemplateExplainer(), PriorityExplainer)


def test_fallbacks_are_neutral():
    verdict = NeutralApplicabilityAssessor().assess({"cve_id": "CVE-1"}, {"asset_id": "a"})
    assert verdict.applicable is None
    text = TemplateExplainer().explain({"cve_id": "CVE-1"}, {"cvss_score": 9.8, "epss": 0.5}, 1)
    assert "CVE-1" in text and "9.8" in text
