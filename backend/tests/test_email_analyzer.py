"""Tests for email analyzer."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analyzers.email_analyzer import analyze_email
from app.utils.debug_trace import DebugTracer


def test_sender_mismatch():
    tracer = DebugTracer()
    results = analyze_email(
        tracer,
        sender="support@paypal.com",
        reply_to="hacker@evil.xyz",
        subject="Verify your account",
        body_text="Please verify your account immediately.",
    )
    all_findings = []
    for f_list in results.values():
        all_findings.extend(f_list)
    titles = [f.title for f in all_findings]
    assert "Reply-To domain mismatch" in titles


def test_display_name_spoofing():
    tracer = DebugTracer()
    results = analyze_email(
        tracer,
        sender="security@paypal.com <attacker@phish.xyz>",
        subject="Security Alert",
        body_text="Your account has been compromised.",
    )
    all_findings = []
    for f_list in results.values():
        all_findings.extend(f_list)


def test_header_spf_fail():
    tracer = DebugTracer()
    headers = """Received-SPF: fail (domain of evil.com does not designate 1.2.3.4)
From: admin@example.com
DKIM-Signature: v=1; a=rsa-sha256; d=example.com"""
    results = analyze_email(
        tracer,
        raw_headers=headers,
        subject="Test",
        body_text="Test body",
    )
    header_findings = results.get("header_analyzer", [])
    titles = [f.title for f in header_findings]
    assert "SPF Authentication Failed" in titles


def test_no_content():
    tracer = DebugTracer()
    results = analyze_email(tracer)
    all_findings = []
    for f_list in results.values():
        all_findings.extend(f_list)
    # Should have no critical findings
    critical = [f for f in all_findings if f.severity.value == "critical"]
    assert len(critical) == 0
