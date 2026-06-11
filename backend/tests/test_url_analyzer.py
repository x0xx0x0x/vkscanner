"""Tests for URL analyzer."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.analyzers.url_analyzer import analyze_url
from app.utils.debug_trace import DebugTracer


def test_ip_based_url():
    tracer = DebugTracer()
    findings = analyze_url("http://192.168.1.1/login", tracer)
    titles = [f.title for f in findings]
    assert "IP-based URL" in titles


def test_suspicious_tld():
    tracer = DebugTracer()
    findings = analyze_url("http://free-prize.tk/winner", tracer)
    titles = [f.title for f in findings]
    assert "Suspicious TLD" in titles


def test_http_no_ssl():
    tracer = DebugTracer()
    findings = analyze_url("http://example.com", tracer)
    titles = [f.title for f in findings]
    assert "No HTTPS" in titles


def test_at_symbol():
    tracer = DebugTracer()
    findings = analyze_url("http://google.com@evil.com/phish", tracer)
    titles = [f.title for f in findings]
    assert "Credential in URL" in titles


def test_suspicious_keywords():
    tracer = DebugTracer()
    findings = analyze_url("http://secure-login-verify.example.com/account", tracer)
    titles = [f.title for f in findings]
    assert "Suspicious keywords in URL" in titles


def test_legitimate_url():
    tracer = DebugTracer()
    findings = analyze_url("https://www.google.com", tracer)
    # Legitimate URL should have minimal/no high findings
    high_findings = [f for f in findings if f.severity.value in ("high", "critical")]
    assert len(high_findings) == 0


def test_url_shortener():
    tracer = DebugTracer()
    findings = analyze_url("https://bit.ly/abc123", tracer)
    titles = [f.title for f in findings]
    assert "URL shortener detected" in titles


def test_excessive_subdomains():
    tracer = DebugTracer()
    findings = analyze_url("http://a.b.c.d.example.com/path", tracer)
    titles = [f.title for f in findings]
    assert "Excessive subdomains" in titles


def test_typosquatting():
    tracer = DebugTracer()
    findings = analyze_url("http://goggle.com", tracer)
    titles = [f.title for f in findings]
    assert "Possible typosquatting" in titles


def test_debug_trace_populated():
    tracer = DebugTracer()
    analyze_url("http://test.example.com", tracer)
    steps = tracer.get_steps()
    assert len(steps) > 0
    assert steps[0].analyzer == "url_analyzer"
