import math

import numpy as np
import pandas as pd
import pytest

from patchprio.evaluation.metrics import (
    budget_metrics,
    coverage_curve,
    effort_for_coverage,
    expected_hits_at_k,
    policy_metrics,
    tie_groups,
)


def test_strict_order_hits():
    scores = pd.Series([0.9, 0.8, 0.7, 0.6])
    labels = pd.Series([1, 0, 1, 0])
    g = tie_groups(scores, labels)
    assert expected_hits_at_k(g, 1) == 1
    assert expected_hits_at_k(g, 2) == 1
    assert expected_hits_at_k(g, 3) == 2
    assert expected_hits_at_k(g, 10) == 2


def test_ties_use_expectation():
    # Четыре уязвимости с одинаковым баллом, одна эксплуатируемая:
    # при бюджете 2 в среднем попадаем в половину случаев.
    scores = pd.Series([9.8, 9.8, 9.8, 9.8, 5.0])
    labels = pd.Series([1, 0, 0, 0, 1])
    g = tie_groups(scores, labels)
    assert expected_hits_at_k(g, 2) == pytest.approx(0.5)
    assert expected_hits_at_k(g, 4) == pytest.approx(1.0)
    assert expected_hits_at_k(g, 5) == pytest.approx(2.0)


def test_random_ranker_equals_prevalence():
    labels = pd.Series([1] * 10 + [0] * 90)
    g = tie_groups(pd.Series(0.0, index=labels.index), labels)
    m = budget_metrics(g, 20)
    assert m["coverage"] == pytest.approx(0.2)
    assert m["efficiency"] == pytest.approx(0.1)
    assert m["lift"] == pytest.approx(1.0)


def test_missing_scores_go_last():
    scores = pd.Series([np.nan, 1.0, np.nan])
    labels = pd.Series([1, 0, 0])
    g = tie_groups(scores, labels)
    assert expected_hits_at_k(g, 1) == 0
    assert expected_hits_at_k(g, 3) == 1


def test_effort_for_coverage_with_ties():
    scores = pd.Series([3, 2, 2, 2, 2, 1])
    labels = pd.Series([1, 1, 1, 0, 0, 1])
    g = tie_groups(scores, labels)
    # 4 эксплуатируемых; 50% = 2: первая плюс 1 из группы "2" (2 из 4 эксплуатируемы)
    # нужно в среднем 2 позиции группы -> k = 1 + 2 = 3
    assert effort_for_coverage(g, 0.5) == 3
    assert effort_for_coverage(g, 1.0) == 6


def test_effort_none_without_positives():
    g = tie_groups(pd.Series([1.0, 2.0]), pd.Series([0, 0]))
    assert effort_for_coverage(g, 0.5) is None


def test_coverage_curve_endpoints():
    g = tie_groups(pd.Series([3, 2, 1]), pd.Series([0, 1, 1]))
    x, y = coverage_curve(g)
    assert x[0] == 0 and y[0] == 0
    assert x[-1] == pytest.approx(1.0) and y[-1] == pytest.approx(1.0)
    assert np.all(np.diff(x) > 0)


def test_policy_metrics():
    cvss = pd.Series([9.8, 7.5, 5.0, np.nan])
    labels = pd.Series([1, 0, 1, 0])
    m = policy_metrics(cvss >= 7.0, labels)
    assert m["effort"] == 2
    assert m["coverage"] == pytest.approx(0.5)
    assert m["efficiency"] == pytest.approx(0.5)
    assert math.isclose(m["lift"], 1.0)
