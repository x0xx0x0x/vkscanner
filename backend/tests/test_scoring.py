"""Tests for scoring engine."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.models import Finding, FindingSeverity, RiskClassification
from app.utils.scoring import aggregate_scores, classify, generate_summary


def test_classify_low():
    assert classify(10) == RiskClassification.LOW
    assert classify(25) == RiskClassification.LOW


def test_classify_medium():
    assert classify(26) == RiskClassification.MEDIUM
    assert classify(50) == RiskClassification.MEDIUM


def test_classify_high():
    assert classify(51) == RiskClassification.HIGH
    assert classify(75) == RiskClassification.HIGH


def test_classify_critical():
    assert classify(76) == RiskClassification.CRITICAL
    assert classify(100) == RiskClassification.CRITICAL


def test_aggregate_empty():
    score, cls, conf, breakdowns = aggregate_scores({})
    assert score == 0.0
    assert cls == RiskClassification.LOW


def test_aggregate_with_findings():
    findings = {
        "url_analyzer": [
            Finding(
                category="url", title="Test",
                description="Test finding",
                severity=FindingSeverity.HIGH,
                score_impact=30.0,
            ),
        ],
    }
    score, cls, conf, breakdowns = aggregate_scores(findings)
    assert score > 0
    assert len(breakdowns) == 1


def test_score_capping():
    """Score should never exceed 100."""
    findings = {
        "url_analyzer": [
            Finding(category="url", title=f"Finding {i}",
                    description="Test", severity=FindingSeverity.CRITICAL,
                    score_impact=50.0)
            for i in range(10)
        ],
    }
    score, cls, conf, breakdowns = aggregate_scores(findings)
    assert score <= 100


def test_generate_summary():
    findings = [
        Finding(category="url", title="Test finding",
                description="A test", severity=FindingSeverity.HIGH,
                score_impact=20.0),
    ]
    summary = generate_summary(65, RiskClassification.HIGH, findings)
    assert "HIGH RISK" in summary
    assert "65" in summary
