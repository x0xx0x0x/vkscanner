"""
Scoring engine for VK Scanner.

Aggregates findings from all analyzers into a single risk score (0-100)
and assigns a classification (LOW / MEDIUM / HIGH / CRITICAL).
"""

from __future__ import annotations

from app.models import (
    AnalyzerBreakdown,
    Finding,
    FindingSeverity,
    RiskClassification,
)


# ── Severity → base score contribution ──────────────────────────
SEVERITY_SCORES: dict[FindingSeverity, float] = {
    FindingSeverity.INFO: 0.0,
    FindingSeverity.LOW: 2.0,
    FindingSeverity.MEDIUM: 15.0,
    FindingSeverity.HIGH: 35.0,
    FindingSeverity.CRITICAL: 50.0,
}

# ── Analyzer weights (must sum to 1.0) ──────────────────────────
ANALYZER_WEIGHTS: dict[str, float] = {
    "url_analyzer": 0.35,
    "header_analyzer": 0.15,
    "link_extractor": 0.15,
    "email_analyzer": 0.10,
    "document_analyzer": 0.25,
}

# ── Classification thresholds ───────────────────────────────────
THRESHOLDS = [
    (25, RiskClassification.LOW),
    (50, RiskClassification.MEDIUM),
    (75, RiskClassification.HIGH),
    (100, RiskClassification.CRITICAL),
]


def classify(score: float) -> RiskClassification:
    """Map a 0-100 score to a risk classification."""
    for threshold, classification in THRESHOLDS:
        if score <= threshold:
            return classification
    return RiskClassification.CRITICAL


def compute_analyzer_score(findings: list[Finding]) -> float:
    """
    Compute a raw score for a single analyzer from its findings.

    The score is the sum of each finding's score_impact (if set) or
    a fallback based on severity.  Capped at 100.
    """
    total = 0.0
    for f in findings:
        if f.score_impact > 0:
            total += f.score_impact
        else:
            total += SEVERITY_SCORES.get(f.severity, 5.0)
    return min(total, 100.0)


def aggregate_scores(
    findings_by_analyzer: dict[str, list[Finding]],
) -> tuple[float, RiskClassification, float, list[AnalyzerBreakdown]]:
    """
    Aggregate findings from all analyzers into a final risk assessment.

    Returns:
        (risk_score, classification, confidence, breakdowns)
    """
    breakdowns: list[AnalyzerBreakdown] = []
    weighted_total = 0.0
    total_weight = 0.0
    total_findings = 0

    for analyzer_name, findings in findings_by_analyzer.items():
        weight = ANALYZER_WEIGHTS.get(analyzer_name, 0.10)
        raw_score = compute_analyzer_score(findings)
        weighted = raw_score * weight

        breakdowns.append(
            AnalyzerBreakdown(
                analyzer=analyzer_name,
                score=round(raw_score, 2),
                weight=weight,
                weighted_score=round(weighted, 2),
                findings_count=len(findings),
            )
        )
        weighted_total += weighted
        total_weight += weight
        total_findings += len(findings)

    # Normalize if weights don't sum to 1
    if total_weight > 0 and abs(total_weight - 1.0) > 0.01:
        weighted_total = weighted_total / total_weight

    # Worst-Case Risk Escalation: If any individual analyzer is highly malicious/suspicious,
    # the final score should reflect at least that maximum severity score, instead of being averaged down.
    max_raw_score = max([b.score for b in breakdowns], default=0.0)
    
    # We take the maximum of the weighted average or the highest threat score
    final_score = max(weighted_total, max_raw_score)
    risk_score = round(min(max(final_score, 0.0), 100.0), 2)
    classification = classify(risk_score)

    # Confidence: higher when more analyzers contributed findings
    analyzers_with_findings = sum(1 for b in breakdowns if b.findings_count > 0)
    total_analyzers = max(len(breakdowns), 1)
    base_confidence = (analyzers_with_findings / total_analyzers) * 100
    # Boost confidence if many findings agree
    finding_boost = min(total_findings * 2, 30)
    confidence = round(min(base_confidence + finding_boost, 100.0), 2)

    return risk_score, classification, confidence, breakdowns


def generate_summary(
    risk_score: float,
    classification: RiskClassification,
    findings: list[Finding],
) -> str:
    """Generate a human-readable summary of the scan results."""
    critical_count = sum(1 for f in findings if f.severity == FindingSeverity.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == FindingSeverity.HIGH)
    medium_count = sum(1 for f in findings if f.severity == FindingSeverity.MEDIUM)

    parts: list[str] = []

    if classification == RiskClassification.CRITICAL:
        parts.append(
            f"⚠️ CRITICAL RISK (Score: {risk_score}/100). "
            "This content exhibits multiple strong indicators of phishing or malicious intent."
        )
    elif classification == RiskClassification.HIGH:
        parts.append(
            f"🔴 HIGH RISK (Score: {risk_score}/100). "
            "Several suspicious indicators were detected that suggest potential phishing."
        )
    elif classification == RiskClassification.MEDIUM:
        parts.append(
            f"🟡 MEDIUM RISK (Score: {risk_score}/100). "
            "Some suspicious indicators were found. Exercise caution."
        )
    else:
        parts.append(
            f"🟢 LOW RISK (Score: {risk_score}/100). "
            "No significant phishing indicators were detected."
        )

    if critical_count:
        parts.append(f"Found {critical_count} critical issue(s).")
    if high_count:
        parts.append(f"Found {high_count} high-severity issue(s).")
    if medium_count:
        parts.append(f"Found {medium_count} medium-severity issue(s).")

    # Add top findings summary
    top_findings = sorted(findings, key=lambda f: f.score_impact, reverse=True)[:3]
    if top_findings:
        parts.append("Top concerns: " + "; ".join(f.title for f in top_findings) + ".")

    return " ".join(parts)
